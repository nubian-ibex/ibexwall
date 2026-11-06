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
