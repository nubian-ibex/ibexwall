<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# systemd-analyze security, every IbexWall unit

Measured by the packaging phase of the VM matrix (`cargo xtask vm-test --phase f10`)
on Fedora with the installed packages, 2026-11-06. A lower number is a
tighter sandbox: below 4 is rated OK by systemd, 4 to 6 MEDIUM, 6 to 9
EXPOSED, above 9 UNSAFE. The score depends on the systemd version, so another
distribution can differ by a few tenths. It is documented, not a gate.

The daemon and the services it starts:

- `ibexwall-dns-failsafe.service`: 1.8 OK
- `ibexwall-dns.service`: 1.4 OK
- `ibexwall-mcp-reload.service`: 1.7 OK
- `ibexwall-mcp.service`: 1.7 OK
- `ibexwall-monitor.service`: 2.8 OK
- `ibexwalld.service`: 2.7 OK

The plugins, one unit each (a dynamic user, only the capabilities the manifest
declares, a read-only system, no network unless declared):

32 plugin units, from 1.6 to 2.2, all rated OK:

- `ibexwall-plugin-accounts.service`: 1.8 OK
- `ibexwall-plugin-assistant.service`: 1.8 OK
- `ibexwall-plugin-audit.service`: 1.8 OK
- `ibexwall-plugin-av.service`: 1.8 OK
- `ibexwall-plugin-camera-mic.service`: 2.1 OK
- `ibexwall-plugin-coredump.service`: 1.6 OK
- `ibexwall-plugin-cves.service`: 2.2 OK
- `ibexwall-plugin-dns.service`: 1.6 OK
- `ibexwall-plugin-exposure.service`: 1.6 OK
- `ibexwall-plugin-firewall.service`: 1.8 OK
- `ibexwall-plugin-firmware.service`: 1.6 OK
- `ibexwall-plugin-flatpak-network.service`: 1.6 OK
- `ibexwall-plugin-flatpak-perms.service`: 1.9 OK
- `ibexwall-plugin-hardening.service`: 1.6 OK
- `ibexwall-plugin-integrity.service`: 1.8 OK
- `ibexwall-plugin-isolate.service`: 1.6 OK
- `ibexwall-plugin-modules.service`: 1.6 OK
- `ibexwall-plugin-mounts.service`: 1.6 OK
- `ibexwall-plugin-nts.service`: 1.8 OK
- `ibexwall-plugin-openscap.service`: 1.8 OK
- `ibexwall-plugin-persistence.service`: 1.9 OK
- `ibexwall-plugin-ports.service`: 1.6 OK
- `ibexwall-plugin-posture.service`: 1.8 OK
- `ibexwall-plugin-rootkit.service`: 1.8 OK
- `ibexwall-plugin-session-lock.service`: 1.9 OK
- `ibexwall-plugin-ssh.service`: 1.8 OK
- `ibexwall-plugin-sysctl.service`: 1.6 OK
- `ibexwall-plugin-telemetry.service`: 1.6 OK
- `ibexwall-plugin-updates.service`: 1.6 OK
- `ibexwall-plugin-usb.service`: 1.8 OK
- `ibexwall-plugin-vpn.service`: 1.6 OK
- `ibexwall-plugin-wifi.service`: 1.8 OK

The outside scanners run as root over a read-only system because they must read
most of it: they are not in the packaged set until the person starts a scan,
and their transient or installed scan units (`ibexwall-rootkit-scan`,
`ibexwall-openscap-scan`, `ibexwall-exposure-scan`, `ibexwall-av-scan`) rate
poorly by design (rkhunter about 9.0, OpenSCAP about 8.2). The units keep the
system read-only and write only to their own state directory.
