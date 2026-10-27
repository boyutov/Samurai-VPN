#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/../.."
export SAMURAI_PARENT_MOUNTNS="$(readlink /proc/self/ns/mnt)"
exec unshare --user --map-root-user --mount --net /usr/bin/python3 native/linux/test_helper_isolated.py
