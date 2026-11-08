#!/bin/sh
# Opens the desktop app against a sandboxed daemon (IBEXWALL_ROOT), so the
# development host is never modified: no polkit policy, units or nftables.
# The sandbox daemon authorizes only the current user (see sandbox_polkit).
# A daemon this script starts is stopped, with its plugins, when the window closes.
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
root=${IBEXWALL_DEV_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/ibexwall-dev-root}
export IBEXWALL_ROOT="$root"

# The desktop binary must carry the built frontend (a plain debug build
# looks for the Vite dev server instead and shows "connection refused"):
#   (cd ui && pnpm build) && cargo build -p ibexwall-core -p ibexwall-cli \
#     -p ibexwall-plugins
#   cargo build --manifest-path ui/src-tauri/Cargo.toml --features custom-protocol
for bin in ibexwalld ibexwall-desktop; do
    [ -x "$repo/target/debug/$bin" ] || {
        echo "missing $repo/target/debug/$bin; build it first (see the top of this script)" >&2
        exit 1
    }
done

plugins="$root/usr/lib/ibexwall/plugins"
for id in system.posture system.ports net.dns net.nts net.firewall system.assistant system.hardening system.modules endpoint.rootkit net.exposure system.openscap; do
    mkdir -p "$plugins/$id"
    bin="ibexwall-plugin-${id#*.}"
    # Copy then rename: a running plugin binary cannot be overwritten in
    # place (ETXTBSY) but it can be replaced.
    # The official plugins are one multicall binary reached through a link.
    mkdir -p "$root/usr/libexec/ibexwall"
    cp "$repo/target/debug/ibexwall-plugins" "$root/usr/libexec/ibexwall/.plugins.new"
    mv -f "$root/usr/libexec/ibexwall/.plugins.new" "$root/usr/libexec/ibexwall/ibexwall-plugins"
    ln -sf "$root/usr/libexec/ibexwall/ibexwall-plugins" "$plugins/$id/$bin"
    for file in "$repo/plugins/$id/plugin.toml" \
        "$repo/plugins/$id/plugin.toml.sig"; do
        name=$(basename -- "$file")
        cp "$file" "$plugins/$id/.$name.new"
        mv -f "$plugins/$id/.$name.new" "$plugins/$id/$name"
    done
done
mkdir -p "$root/run/ibexwall" "$root/var/lib/ibexwall" "$root/etc/ibexwall"

# Shipped compliance profiles so the screen has data.
mkdir -p "$root/usr/lib/ibexwall/profiles"
if [ -d "$repo/profiles/compliance" ]; then
    cp "$repo/profiles/compliance"/*.yaml "$root/usr/lib/ibexwall/profiles/"
fi

if ! [ -S "$root/run/ibexwall/core.sock" ] ||
    ! pgrep -x ibexwalld >/dev/null 2>&1; then
    setsid "$repo/target/debug/ibexwalld" \
        "--dev-key=$repo/target/devkey/dev.pub" \
        >"$root/ibexwalld.log" 2>&1 </dev/null &
    started=$!
    sleep 2
    # First run: the check plugins start disabled; enable them so the
    # screens have data. Safe to repeat.
    if [ -x "$repo/target/debug/ibexctl" ]; then
        for id in system.posture system.ports net.dns net.nts net.firewall system.hardening system.assistant system.modules; do
            "$repo/target/debug/ibexctl" plugins enable "$id" >/dev/null 2>&1 || true
        done
    fi
fi

# The daemon starts its plugins as children and they outlive it, so what this
# run started is stopped with the window: the daemon, then the plugins of this
# sandbox only (matched by their path under $root).
cleanup() {
    [ -z "${started:-}" ] || kill "$started" 2>/dev/null || true
    for pid in $(pgrep -f "^$root/usr/" 2>/dev/null); do
        kill "$pid" 2>/dev/null || true
    done
}
if [ -n "${started:-}" ]; then
    trap cleanup EXIT INT TERM
    "$repo/target/debug/ibexwall-desktop"
else
    exec "$repo/target/debug/ibexwall-desktop"
fi
