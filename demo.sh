#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
mkdir -p .local
demo_dir="$(mktemp -d .local/demo-XXXXXX)"
server_pid=''
cleanup() {
    if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
./samurai.sh client gen-admin --out "$demo_dir/admin.token"
./samurai.sh server --dev --admin-token-file "$demo_dir/admin.token" >"$demo_dir/server.log" 2>&1 &
server_pid=$!
for attempt in {1..40}; do
    if ! kill -0 "$server_pid" 2>/dev/null; then echo "Server failed; see $demo_dir/server.log" >&2; exit 1; fi
    if grep -q 'control server listening' "$demo_dir/server.log"; then break; fi
    sleep 0.1
done
./samurai.sh client create-network --dev --server http://127.0.0.1:8787 --token-file "$demo_dir/admin.token" --name Friends --out "$demo_dir/owner.json"
for person in alice bob; do
    ./samurai.sh client keygen --out "$demo_dir/$person-key.json"
    ./samurai.sh client invite --dev --owner "$demo_dir/owner.json" --out "$demo_dir/$person-invite.json"
    ./samurai.sh client join --dev --invite "$demo_dir/$person-invite.json" --identity "$demo_dir/$person-key.json" --name "$person" --out "$demo_dir/$person.json"
done
for person in alice bob; do
    ./samurai.sh client export --dev --session "$demo_dir/$person.json" --out "$demo_dir/$person.conf"
done
./samurai.sh client peers --dev --session "$demo_dir/alice.json"
echo "Demo complete. Private local files: $demo_dir. No tunnel was activated."
