#!/bin/bash
# Removes everything the Samurai VPN package installed:
#   sudo "/Library/Application Support/SamuraiVPN Setup/uninstall.sh"
set -euo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
setup='/Library/Application Support/SamuraiVPN Setup'
"$setup/uninstall-service.sh"
rm -rf /Applications/SamuraiVPN.app "$setup"
/usr/sbin/pkgutil --forget dev.samurai.vpn >/dev/null 2>&1 || true
echo 'Samurai VPN was removed. Profiles in your home folder (~/.samurai-vpn) are kept.'
