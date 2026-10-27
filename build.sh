#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
source ./scripts/java-runtime.sh
exec mvn -B -ntp verify "$@"
