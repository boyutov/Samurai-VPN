#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
source "$project_dir/scripts/java-runtime.sh"
case "${1:-}" in
    client|server|desktop) component="$1"; shift ;;
    *) echo 'Usage: ./samurai.sh client|server|desktop [arguments]' >&2; exit 2 ;;
esac
exec "$samurai_java" -jar "$project_dir/vpn-$component/target/samurai-$component.jar" "$@"
