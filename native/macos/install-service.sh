#!/bin/bash
# Installs the Samurai VPN tunnel service on macOS 12.3+ (readlink -f):
#   sudo ./native/macos/install-service.sh dist/SamuraiVPN.app [wireguard-go] [wg]
# Tool paths default to Homebrew (brew install wireguard-go wireguard-tools). They are copied
# into a root-owned directory: root must never execute files the user can modify.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'macOS only' >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
app="${1:?Usage: install-service.sh SamuraiVPN.app [wireguard-go] [wg]}"
brew_bin="$( [[ -d /opt/homebrew/bin ]] && echo /opt/homebrew/bin || echo /usr/local/bin )"
wireguard_go="${2:-$brew_bin/wireguard-go}" wg="${3:-$brew_bin/wg}"
runtime="$app/Contents/runtime/Contents/Home" jar="$app/Contents/app/samurai-desktop.jar"
[[ -x "$runtime/bin/java" && -f "$jar" ]] || { echo "Not an app image from package.sh: $app" >&2; exit 1; }

root='/Library/Application Support/SamuraiVPN'
label='dev.samurai.vpn.service' plist="/Library/LaunchDaemons/dev.samurai.vpn.service.plist"
for tool in "$wireguard_go" "$wg"; do
    real="$(readlink -f "$tool" || true)"
    [[ -n "$real" && -x "$real" ]] || { echo "Not found: $tool (brew install wireguard-go wireguard-tools)" >&2; exit 1; }
    /usr/bin/otool -L "$real" >/dev/null 2>&1 || { echo 'otool is required: xcode-select --install' >&2; exit 1; }
    # Only system libraries: a Homebrew dylib would again be user-writable code running as root.
    if /usr/bin/otool -L "$real" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)'; then
        echo "$real links libraries outside /usr/lib and /System; refusing to run it as root" >&2; exit 1
    fi
done

/bin/launchctl bootout system "$plist" 2>/dev/null || true
rm -rf "$root"
mkdir -p "$root/bin" "$root/app"
/usr/bin/ditto "$(readlink -f "$wireguard_go")" "$root/bin/wireguard-go"
/usr/bin/ditto "$(readlink -f "$wg")" "$root/bin/wg"
/usr/bin/ditto "$runtime" "$root/runtime"
/usr/bin/ditto "$jar" "$root/app/samurai-desktop.jar"
chown -R root:wheel "$root"
chmod -R go-w "$root"

cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key><array>
    <string>$root/runtime/bin/java</string>
    <string>--add-opens</string><string>java.base/sun.nio.fs=ALL-UNNAMED</string>
    <string>-cp</string><string>$root/app/samurai-desktop.jar</string>
    <string>dev.samurai.vpn.macos.MacServiceMain</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/samurai-vpn.log</string>
</dict></plist>
PLIST
chown root:wheel "$plist"; chmod 644 "$plist"
/bin/launchctl bootstrap system "$plist"

for _ in $(seq 20); do [[ -S /var/run/samurai-vpnd/daemon.sock ]] && break; sleep 0.5; done
[[ -S /var/run/samurai-vpnd/daemon.sock ]] || { echo 'The service did not start; see /var/log/samurai-vpn.log' >&2; exit 1; }
echo 'Samurai VPN service is running.'
