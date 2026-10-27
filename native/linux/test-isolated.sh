#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/../.."
# All test interfaces are created in new user/network namespaces, never on the host.
export SAMURAI_PARENT_NETNS="$(readlink /proc/self/ns/net)"
# The kernel does not autoload modules for user namespaces; NatTraversalTest needs masquerade.
if [[ ! -d /sys/module/nft_masq ]]; then
    echo "Модуль ядра nft_masq не загружен. Загрузите: sudo modprobe nft_masq" >&2
    exit 1
fi
# Inside the namespace uid is 0, so Java would resolve user.home to /root.
export MAVEN_OPTS="${MAVEN_OPTS:-} -Duser.home=$HOME"
# Ubuntu 23.10+ blocks unprivileged user namespaces through AppArmor.
if [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" == 1 ]]; then
    echo "AppArmor запрещает user namespaces. Временно разрешите:" >&2
    echo "  sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" >&2
    echo "После теста верните: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1" >&2
    exit 1
fi
exec unshare --user --map-root-user --net /bin/bash -c '
    set -euo pipefail
    /usr/sbin/ip link set lo up
    exec ./build.sh -Dsamurai.native.test=true "$@"
' samurai-isolated "$@"
