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

have_systemd() {
    [ -d /run/systemd/system ]
}

post_install() {
    systemd-sysusers /usr/lib/sysusers.d/ibexwall.conf /usr/lib/sysusers.d/ibexwall-dns.conf >/dev/null 2>&1 || true
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/ibexwall.conf >/dev/null 2>&1 || true
    if have_systemd; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        # shellcheck disable=SC2046
        {
            systemctl preset $(cat "$sockets_list") >/dev/null 2>&1 || true
            systemctl start $(cat "$sockets_list") >/dev/null 2>&1 || true
        }
    fi
}

post_upgrade() {
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
        # Stop taking connections, then undo, then stop the rest.
        systemctl stop ibexwalld.socket ibexwalld.service >/dev/null 2>&1 || true
        if [ -x /usr/bin/ibexwalld ]; then
            /usr/bin/ibexwalld --cleanup || echo "ibexwall: some changes could not be undone; the message above says which" >&2
        fi
        # shellcheck disable=SC2046
        systemctl disable --now $(cat "$sockets_list") >/dev/null 2>&1 || true
        systemctl stop 'ibexwall-plugin-*.service' ibexwall-dns.service ibexwall-monitor.service ibexwall-mcp.service ibexwall-mcp.path >/dev/null 2>&1 || true
    fi
}

post_remove() {
    if have_systemd; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
}

# What a purge removes: the user's data, kept until now (state, audit chain,
# settings). Only the formats that have a purge call it.
purge_data() {
    rm -rf /var/lib/ibexwall /var/lib/ibexwall-mcp /etc/ibexwall /run/ibexwall
}
