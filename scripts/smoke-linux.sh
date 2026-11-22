#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID != 0 || $# != 2 ]]; then
    echo 'Usage: sudo bash scripts/smoke-linux.sh /path/to/netguard-agent username' >&2
    exit 2
fi
agent=$(realpath -- "$1")
owner=$2
uid=$(id -u "$owner")
[[ $uid != 0 ]]

unshare --net --mount --propagation private bash -s -- "$agent" "$owner" "$uid" <<'TEST'
set -euo pipefail
agent=$1
owner=$2
uid=$3
mount -t tmpfs -o mode=0755 tmpfs /run
ip link set lo up
work=$(mktemp -d)
chmod 755 "$work"
service= server=
cleanup() {
    if [[ -n $service ]]; then kill "$service" 2>/dev/null || true; wait "$service" || true; fi
    if [[ -n $server ]]; then kill "$server" 2>/dev/null || true; wait "$server" || true; fi
    rm -rf -- "$work"
}
trap cleanup EXIT
client() { runuser -u "$owner" -- "$agent" "$@"; }
python3 - "$work/port" <<'PY' &
import socket, sys
with socket.create_server(("127.0.0.1", 0)) as listener:
    with open(sys.argv[1], "w") as port:
        print(listener.getsockname()[1], file=port)
    while True:
        conn, _ = listener.accept()
        conn.close()
PY
server=$!
"$agent" --database "$work/state.db" --owner "$uid" &
service=$!
for _ in {1..40}; do
    [[ -s $work/port ]] && client status >/dev/null 2>&1 && break
    sleep .1
done
port=$(cat "$work/port")
check_connection() {
    python3 - "$port" "$1" <<'PY'
import socket, sys
try:
    socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.6).close()
    observed = "allowed"
except (TimeoutError, ConnectionError):
    observed = "blocked"
assert observed == sys.argv[2], (observed, sys.argv[2])
PY
}
check_connection allowed
cat > "$work/rules.json" <<JSON
{"schema_version":1,"policy":{"exclusions":[],"rules":[{"id":"loopback-smoke","name":"Test listener only","target":{"kind":"ip","value":"127.0.0.1"},"action":"block","enabled":true,"program":null,"protocol":6,"port":$port,"expires_at":null,"source":null}]}}
JSON
chmod 644 "$work/rules.json"
client import "$work/rules.json" >/dev/null
client export | python3 -c 'import json,sys; assert json.load(sys.stdin)["policy"]["rules"][0]["id"] == "loopback-smoke"'
client enable | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["active"] and s["report"]["applied"] == 1'
check_connection blocked
client pause | python3 -c 'import json,sys; assert not json.load(sys.stdin)["active"]'
check_connection allowed
client enable >/dev/null
kill -TERM "$service"
wait "$service"
service=
check_connection allowed
echo 'Linux IPC, import/export, native blocking, pause and SIGTERM recovery passed.'
TEST
