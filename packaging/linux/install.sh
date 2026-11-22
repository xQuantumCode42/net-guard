#!/usr/bin/env bash
set -euo pipefail
if (( EUID != 0 )); then
    echo 'Run this installer as root.' >&2
    exit 1
fi
cd -- "$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")"
sha256sum --check SHA256SUMS
install -Dm755 netguard-agent /usr/lib/netguard/netguard-agent
ln -sfn /usr/lib/netguard/netguard-agent /usr/bin/netguard
install -Dm644 netguard@.service /usr/lib/systemd/system/netguard@.service
if [[ -f netguard-desktop ]]; then
    install -Dm755 netguard-desktop /usr/bin/netguard-desktop
    install -Dm644 netguard.desktop /usr/share/applications/netguard.desktop
    install -Dm644 icon.png /usr/share/icons/hicolor/128x128/apps/netguard.png
fi
systemctl daemon-reload
echo 'Installed NetGuard. Start it using the desktop launcher or sudo systemctl start "netguard@$(id -u).service" from your user shell.'
