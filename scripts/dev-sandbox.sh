#!/bin/sh
# Opens the desktop app against a sandboxed daemon (IBEXWALL_ROOT), so the
# development host is never modified: no polkit policy, units or nftables.
# The sandbox daemon authorizes only the current user (see sandbox_polkit).
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
root=${IBEXWALL_DEV_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/ibexwall-dev-root}
export IBEXWALL_ROOT="$root"

for bin in ibexwalld ibexwall-desktop; do
    [ -x "$repo/target/debug/$bin" ] || {
        echo "missing $repo/target/debug/$bin; build it first" >&2
        exit 1
    }
done

plugins="$root/usr/lib/ibexwall/plugins"
for id in system.posture system.ports; do
    mkdir -p "$plugins/$id"
    bin="ibexwall-plugin-${id#system.}"
    # Copy then rename: a running plugin binary cannot be overwritten in
    # place (ETXTBSY) but it can be replaced.
    for file in "$repo/target/debug/$bin" "$repo/plugins/$id/plugin.toml" \
        "$repo/plugins/$id/plugin.toml.sig"; do
        name=$(basename -- "$file")
        cp "$file" "$plugins/$id/.$name.new"
        mv -f "$plugins/$id/.$name.new" "$plugins/$id/$name"
    done
done
mkdir -p "$root/run/ibexwall" "$root/var/lib/ibexwall" "$root/etc/ibexwall"

if ! [ -S "$root/run/ibexwall/core.sock" ] ||
    ! pgrep -x ibexwalld >/dev/null 2>&1; then
    setsid "$repo/target/debug/ibexwalld" \
        "--dev-key=$repo/target/devkey/dev.pub" \
        >"$root/ibexwalld.log" 2>&1 </dev/null &
    sleep 2
    # First run: the check plugins start disabled; enable them so the
    # screens have data. Safe to repeat.
    if [ -x "$repo/target/debug/ibexctl" ]; then
        for id in system.posture system.ports; do
            "$repo/target/debug/ibexctl" plugins enable "$id" >/dev/null 2>&1 || true
        done
    fi
fi

exec "$repo/target/debug/ibexwall-desktop"
