#!/bin/sh
# SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The install, upgrade and removal steps every package format runs, written
# once. Each format's own script (rpm scriptlets, debian maintainer scripts,
# pacman's .install) calls these functions. POSIX sh.
#
#   post_install    users, tmpfiles, and the sockets switched on and started
#   post_upgrade    the same, then the running parts restarted on the new files
#   pre_remove      on a removal (not an upgrade): undo what IbexWall changed
#                   on the machine, then stop and disable its units
#   post_remove     the unit files are gone: tell systemd
#
# Nothing here ever fails the package operation: a step that cannot run (no
# systemd in a chroot or a container build) is skipped.

sockets_list=/usr/lib/ibexwall/sockets.list
was_enabled=no

have_systemd() {
    [ -d /run/systemd/system ]
}

# True on the first install: the state directory does not exist yet. Must be
# asked before tmpfiles creates it.
fresh_install=no

post_install() {
    fresh_install=no
    [ -d /var/lib/ibexwall ] || fresh_install=yes
    systemd-sysusers /usr/lib/sysusers.d/ibexwall.conf /usr/lib/sysusers.d/ibexwall-dns.conf >/dev/null 2>&1 || true
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/ibexwall.conf >/dev/null 2>&1 || true
    if have_systemd; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        # shellcheck disable=SC2046
        {
            systemctl preset $(cat "$sockets_list") >/dev/null 2>&1 || true
            systemctl start $(cat "$sockets_list") >/dev/null 2>&1 || true
        }
        # The connection monitor runs by default on a fresh install. Later
        # it follows the person's choice. Versions before 0.2 recorded no
        # choice, so an upgrade that finds none keeps what systemd has: a
        # monitor that was turned off on purpose stays off.
        choice=$(cat /var/lib/ibexwall/monitor.choice 2>/dev/null || true)
        if [ "$choice" = on ] || { [ "$choice" != off ] && [ "$fresh_install" = yes ]; } ||
            { [ -z "$choice" ] && [ "$was_enabled" = yes ]; }; then
            systemctl enable --now ibexwall-monitor.service >/dev/null 2>&1 || true
        fi
    fi
}

post_upgrade() {
    # Read before post_install touches anything.
    was_enabled=no
    if have_systemd && systemctl is-enabled --quiet ibexwall-monitor.service >/dev/null 2>&1; then
        was_enabled=yes
    fi
    post_install
    if have_systemd; then
        # The sockets keep listening; the services start again on the new
        # binaries the next time something connects.
        systemctl try-restart ibexwalld.service ibexwall-mcp.service >/dev/null 2>&1 || true
        systemctl try-restart 'ibexwall-plugin-*.service' >/dev/null 2>&1 || true
    fi
}

pre_remove() {
    if have_systemd; then
        # The monitor first: it wants the daemon and restarts when the
        # daemon goes, which would start the daemon again mid-removal.
        systemctl disable --now ibexwall-monitor.service >/dev/null 2>&1 || true
        # Stop taking connections, then undo, then stop the rest.
        systemctl stop ibexwalld.socket ibexwalld.service >/dev/null 2>&1 || true
        if [ -x /usr/bin/ibexwalld ]; then
            if ! /usr/bin/ibexwalld --cleanup; then
                echo "ibexwall: some changes could not be undone; the message above says which" >&2
                # A purge must then keep the snapshots and the audit trail
                # that a later rollback needs.
                : >/var/lib/ibexwall/cleanup.failed 2>/dev/null || true
            fi
        fi
        # shellcheck disable=SC2046
        systemctl disable --now $(cat "$sockets_list") >/dev/null 2>&1 || true
        systemctl stop 'ibexwall-plugin-*.service' ibexwall-dns.service ibexwall-mcp.service ibexwall-mcp.path >/dev/null 2>&1 || true
    fi
}

post_remove() {
    if have_systemd; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
}

# What a purge removes: the user's data, kept until now (state, audit chain,
# settings). Only the formats that have a purge call it. The debian postrm
# gets a copy of this function at build time (packaging/deb/debian/rules),
# because this file is already gone when a purge runs.
# When the removal could not undo every change, the snapshots and the audit
# trail (state.db) stay: they are what a rollback needs.
purge_data() {
    rm -rf /var/lib/ibexwall-mcp /var/lib/ibexwall-dns /etc/ibexwall /run/ibexwall
    if [ -e /var/lib/ibexwall/cleanup.failed ]; then
        echo "ibexwall: cleanup had failed; keeping /var/lib/ibexwall/snapshots and state.db" >&2
        find /var/lib/ibexwall -mindepth 1 -maxdepth 1 \
            ! -name snapshots ! -name 'state.db*' -exec rm -rf {} + 2>/dev/null || true
    else
        rm -rf /var/lib/ibexwall
    fi
}

# AppArmor (Debian and Ubuntu, package ibexwall-apparmor). The profiles live
# under /usr/share/ibexwall/apparmor and are linked into /etc/apparmor.d, so a
# removal takes them away with nothing left behind.
apparmor_share=/usr/share/ibexwall/apparmor
apparmor_profiles="usr.bin.ibexwalld usr.bin.ibexwall-dns usr.bin.ibexwall-mcp usr.libexec.ibexwall.ibexwall-plugins"

apparmor_active() {
    [ -x /usr/sbin/apparmor_parser ] && [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]
}

apparmor_install() {
    [ -d /etc/apparmor.d ] || return 0
    ln -sfn "$apparmor_share/ibexwall" /etc/apparmor.d/ibexwall
    for profile in $apparmor_profiles; do
        ln -sf "$apparmor_share/$profile" "/etc/apparmor.d/$profile"
        if apparmor_active; then
            apparmor_parser -r -T -W "/etc/apparmor.d/$profile" || echo "ibexwall-apparmor: $profile did not load" >&2
        fi
    done
    # The services already running are put under their profiles.
    if have_systemd && apparmor_active; then
        systemctl try-restart ibexwalld.service ibexwall-dns.service ibexwall-mcp.service >/dev/null 2>&1 || true
        systemctl try-restart 'ibexwall-plugin-*.service' >/dev/null 2>&1 || true
    fi
}

apparmor_remove() {
    for profile in $apparmor_profiles; do
        if apparmor_active; then
            apparmor_parser -R "/etc/apparmor.d/$profile" 2>/dev/null || true
        fi
        rm -f "/etc/apparmor.d/$profile"
        # The compiled copy apparmor_parser keeps.
        rm -f /var/cache/apparmor/*/"$profile"
    done
    rm -f /etc/apparmor.d/ibexwall
}

# SELinux (Fedora and the like, package ibexwall-selinux). The policy module
# gives the resolver, the MCP server and the plugins domains of their own; the
# files are labelled by it, and the services already running are restarted so
# they start in their domains.
selinux_paths="/usr/bin/ibexwall-dns /usr/bin/ibexwall-mcp /usr/libexec/ibexwall /etc/ibexwall /var/lib/ibexwall /var/lib/ibexwall-mcp /run/ibexwall"

selinux_install() {
    # shellcheck disable=SC2086
    restorecon -R $selinux_paths >/dev/null 2>&1 || true
    if have_systemd; then
        systemctl try-restart ibexwalld.service ibexwall-dns.service ibexwall-mcp.service >/dev/null 2>&1 || true
        systemctl try-restart 'ibexwall-plugin-*.service' >/dev/null 2>&1 || true
    fi
}

# Run before the module is removed: the processes leave their domains.
selinux_remove() {
    if have_systemd; then
        systemctl stop ibexwall-dns.service ibexwall-mcp.service >/dev/null 2>&1 || true
        systemctl stop 'ibexwall-plugin-*.service' >/dev/null 2>&1 || true
    fi
}
