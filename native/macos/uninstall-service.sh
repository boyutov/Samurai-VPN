#!/bin/bash
# Removes the Samurai VPN service and stops its tunnels: sudo ./native/macos/uninstall-service.sh
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
/bin/launchctl bootout system /Library/LaunchDaemons/dev.samurai.vpn.service.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/dev.samurai.vpn.service.plist
# Only tunnels Samurai recorded; removing a control socket makes its wireguard-go exit.
if [[ -d /var/run/samurai-vpn ]]; then
    for record in /var/run/samurai-vpn/sm*; do
        [[ -f "$record" ]] || continue
        device="$(tr -d '[:space:]' < "$record")"
        [[ "$device" =~ ^utun[0-9]{1,3}$ ]] && rm -f "/var/run/wireguard/$device.sock"
    done
    rm -rf /var/run/samurai-vpn
fi
rm -rf '/Library/Application Support/SamuraiVPN' /var/run/samurai-vpnd
echo 'Samurai VPN service and its tunnels were removed. Homebrew WireGuard tools are kept.'
