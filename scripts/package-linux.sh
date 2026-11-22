#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
profile=${NETGUARD_BUILD_PROFILE:-release}
case "$profile" in dev) output=debug ;; release) output=release ;; *) exit 2 ;; esac
mode=${1:-gui}
case "$mode" in gui|cli) ;; *) echo 'Usage: bash scripts/package-linux.sh [gui|cli]' >&2; exit 2 ;; esac
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]]
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml)
# The host distribution sets the binary compatibility baseline.
. /etc/os-release
case "$ID" in ubuntu|arch) ;; *) echo 'Build on Ubuntu or Arch Linux.' >&2; exit 1 ;; esac
destination="$root/release/$version/linux-$ID-x64-$mode"
[[ ! -e "$destination" ]] || { echo "Artifact already exists: $destination" >&2; exit 1; }
target_dir=${CARGO_TARGET_DIR:-"$root/target"}
if [[ $mode == gui ]]; then
    node scripts/check-version.mjs
    (cd apps/desktop && npm ci --no-audit --no-fund && npm run build)
    cargo build --locked --profile "$profile" --target-dir "$target_dir" -p netguard-agent -p netguard-desktop --features tauri/custom-protocol
else
    cargo build --locked --profile "$profile" --target-dir "$target_dir" -p netguard-agent
fi
mkdir -p "$root/release/$version"
stage=$(mktemp -d "$root/release/$version/.linux-staging.XXXXXXXX")
trap 'if [[ -n ${stage:-} ]]; then rm -rf -- "$stage"; fi' EXIT
install -m755 "$target_dir/$output/netguard-agent" "$stage/netguard-agent"
install -m755 packaging/linux/install.sh "$stage/install.sh"
install -m644 packaging/linux/netguard@.service "$stage/netguard@.service"
if [[ $mode == gui ]]; then
    install -m755 "$target_dir/$output/netguard-desktop" "$stage/netguard-desktop"
    install -m644 packaging/linux/netguard.desktop "$stage/netguard.desktop"
    install -m644 apps/desktop/src-tauri/icons/128x128.png "$stage/icon.png"
fi
(cd "$stage" && sha256sum -- * > SHA256SUMS && sha256sum --check SHA256SUMS)
mv -T -- "$stage" "$destination"
stage=''
echo "$destination"
