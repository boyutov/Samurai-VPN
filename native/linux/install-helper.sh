#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'Run this installer with sudo after reviewing docs/LINUX.md.' >&2; exit 1; fi
project_dir="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
source_dir="$project_dir/dist/helper"
destination=/opt/samurai-vpn-helper
[[ -f "$source_dir/samurai-helper.jar" && -x "$source_dir/runtime/bin/java" && -f "$source_dir/bin/samurai-vpn-helper" ]] || {
    echo 'Build first: ./build.sh and ./package-helper.sh' >&2; exit 1;
}
[[ ! -L /opt && "$(stat -c %u /opt)" == 0 && ! -e "$destination" && ! -L "$destination" ]] || {
    echo 'Unsafe /opt or helper already installed. Existing installation was not changed.' >&2; exit 1;
}
[[ -z "$(find /opt -maxdepth 0 -perm /022 -print)" ]] || { echo '/opt must not be group/world writable' >&2; exit 1; }
for program in /usr/bin/wg /usr/sbin/ip /usr/bin/pkexec; do
    [[ -x "$program" ]] || { echo "Missing dependency: $program" >&2; exit 1; }
done
# Reject escaping symlinks in the bundle before copying it into a privileged location.
while IFS= read -r -d '' link; do
    resolved="$(realpath -- "$link")"
    [[ "$resolved" == "$source_dir/"* ]] || { echo 'Bundle contains an external symlink' >&2; exit 1; }
done < <(find "$source_dir" -type l -print0)
staging="$(mktemp -d /opt/.samurai-vpn-helper.XXXXXX)"
trap 'if [[ -n "$staging" ]]; then rm -rf -- "$staging"; fi' EXIT
cp -a -- "$source_dir/." "$staging/"
chown -R root:root "$staging"
chmod -R go-w "$staging"
chmod 755 "$staging" "$staging/bin" "$staging/bin/samurai-vpn-helper"
mv -T -- "$staging" "$destination"
staging=''
echo 'Helper installed. The desktop remains unprivileged; pkexec requests administrator authorization for each operation.'
echo 'No interface, route, firewall rule, autostart service or passwordless policy was installed.'
