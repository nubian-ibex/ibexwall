<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Capabilities matrix (v1, F1)

Component, capability and reason. Reviewed at every phase.

- ibexwalld: root, no extra capability set yet. Writes only paths declared
  by plugin manifests, via openat2 with RESOLVE_NO_SYMLINKS. Needs
  CAP_NET_ADMIN once nft executors run in a VM-tested phase (F3+).
  The hardened unit (Appendix G) is not yet installed by the VM suite,
  which runs the daemon directly; unit validation with
  `systemd-analyze security` lands with packaging (F10).
- ibexwall-exec: no capabilities; runs in a transient unit (Type=oneshot,
  NoNewPrivileges, ProtectSystem=strict, ProtectHome=yes, PrivateTmp,
  SystemCallFilter=@system-service, RestrictAddressFamilies=AF_UNIX
  AF_NETLINK) with ReadWritePaths limited to one transaction.
- ibexctl: unprivileged. Connects to the 0666 socket; every method is
  authorized by polkit.
- Plugins (dev.echo): no capabilities, `DynamicUser` unit text generated
  from the manifest and covered by tests. In F1 the VM runs the plugin as
  a direct child of the daemon; unit-based launch arrives with packaging.
- polkit subject: `unix-process` with pid and start-time (ADR-0025).
  pidfd subjects remain a tracked follow-up.
