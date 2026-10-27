#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'Run with sudo after reviewing docs/LINUX.md.' >&2; exit 1; fi
project_dir="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
bundle=/opt/samurai-vpn-helper
unit=/etc/systemd/system/samurai-vpnd.service
[[ -x "$bundle/bin/samurai-vpnd" && "$(stat -c %u "$bundle")" == 0 ]] || {
    echo 'Install the current helper bundle first: sudo ./native/linux/install-helper.sh' >&2; exit 1;
}
[[ -z "$(find "$bundle" -perm /022 -print -quit)" && -z "$(find "$bundle" ! -user 0 -print -quit)" ]] || {
    echo "$bundle must be root-owned and not group/world writable" >&2; exit 1;
}
[[ ! -e "$unit" && ! -L "$unit" ]] || { echo 'samurai-vpnd is already installed; nothing was changed.' >&2; exit 1; }
for program in /usr/bin/wg /usr/sbin/ip /usr/bin/systemctl; do
    [[ -x "$program" ]] || { echo "Missing dependency: $program" >&2; exit 1; }
done
install -o root -g root -m 0644 "$project_dir/native/linux/samurai-vpnd.service" "$unit"
systemctl daemon-reload
systemctl enable --now samurai-vpnd.service
echo 'samurai-vpnd started. It runs as a temporary user with CAP_NET_ADMIN only.'
echo 'Remove: sudo systemctl disable --now samurai-vpnd && sudo rm /etc/systemd/system/samurai-vpnd.service'
