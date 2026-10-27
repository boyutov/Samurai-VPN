#!/usr/bin/env bash
# Sourced by the launchers. Prefer a configured JDK, then the local JDK 21,
# then PATH; reject old runtimes before starting the application or Maven.
samurai_java=''
samurai_java_home=''
samurai_try_java() {
    local executable="$1" candidate_home="$2" version_output
    [[ -x "$executable" ]] || return 1
    version_output="$("$executable" -version 2>&1)" || return 1
    if [[ "$version_output" =~ version[[:space:]]+\"([0-9]+) ]] && (( BASH_REMATCH[1] >= 21 )); then
        samurai_java="$executable"
        samurai_java_home="$candidate_home"
        return 0
    fi
    return 1
}
if [[ -n "${JAVA_HOME:-}" ]] && samurai_try_java "$JAVA_HOME/bin/java" "$JAVA_HOME"; then
    :
elif samurai_try_java /usr/lib/jvm/java-21-openjdk-amd64/bin/java /usr/lib/jvm/java-21-openjdk-amd64; then
    :
elif samurai_try_java "$(command -v java || true)" ''; then
    :
else
    echo 'Java 21 or newer is required. Install a JDK and set JAVA_HOME to its directory.' >&2
    exit 1
fi
if [[ -n "$samurai_java_home" ]]; then
    export JAVA_HOME="$samurai_java_home"
else
    unset JAVA_HOME
fi
unset -f samurai_try_java
