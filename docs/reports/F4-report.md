<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F4 report: apps and traffic (monitor)

Date: 2026-11-03. Plan: `docs/archive/plans/F4-apps-traffic.md`. ADRs: 0031, 0032,
0033.

## What was done

- eBPF connect monitor on aya (cgroup/connect4 and connect6, ring buffer,
  a `sched_process_exec` tracepoint that records each process's exec path
  in the kernel). It only observes: both hooks return 1 on every path.
- `ibexwall-identity`: cgroup classification per spec 4.9 (Flatpak, Snap,
  desktop `app-*` units, system services, containers, CLI), SHA-256 of
  the executable and the owning package through rpm, dpkg or pacman
  (allowlisted argv, no shell).
- `ibexwall-apps`: a TTL-aware, bounded IP-to-domain correlator, SQLite
  rollups (counts, first and last seen only), and the first-connection
  and changed-binary alerts (a package transaction explains a new hash).
- The monitor is its own hardened unit, `ibexwall-monitor.service`
  (ADR-0032), feeding a root-only core socket; the resolver reports
  answers over a datagram socket in its own runtime directory.
- Contract: `ListApps` and `GetAppDestinations` (spec regenerated).
- `flatpak.override` executor and the `apps.flatpak-network` plugin
  (ADR-0033): the block writes the file Flatpak reads, merges into an
  administrator's entries and rolls back byte for byte.
- Clients: `ibexctl apps list|info`, the Apps and network screen (mockup
  02, en and pt-BR, axe clean) and a TUI Apps tab.

## How it was verified

- 288 workspace tests, clippy, fmt, deny and schemas clean; 53 UI tests and
  14 e2e (axe on both themes and locales).
- `cargo xtask vm-test --phase f4` passes on fedora, ubuntu-24.04,
  ubuntu-26.04, debian and arch. Through the real core and the real
  monitor unit it proves attribution of: curl (owned by its package),
  a systemd service, a Flatpak scope (by the scope naming convention),
  a real Podman container, a real snap (Ubuntu) and Firefox installed
  from the distro package (fedora, debian, arch); IP-to-domain
  correlation over the resolver socket; the hardened unit under its
  capability set; processes that connect and exit at once; and, with
  the real `flatpak` reading the file back, the Flatpak block applied
  and rolled back to the same bytes.
- Overhead against the spec criterion (hook plus loader CPU, per
  connection, non-loopback, best of five): 0.65% (ubuntu-26.04), 0.88%
  (arch), 0.92% (ubuntu-24.04), 1.04% (debian), 1.26% (fedora) of one CPU
  at 1000 connections per second; target below 2%.

## Defects found and fixed along the way

- The connect hooks returned 0, which fails `connect()` with EPERM: the
  "monitor" blocked every outbound connection while loaded. Found when DNS
  stopped working in the end-to-end VM run; the earlier spike tests
  ignored `OSError`. Fixed, with a scenario that requires real IPv4 and
  IPv6 connections to complete (ADR-0031 correction).
- The monitor could not live as a child of `ibexwalld`: it would inherit
  the daemon's capability bounding set. It became its own unit (ADR-0032).
- Debian's `perf_event_paranoid=3` denies the exec tracepoint without
  `CAP_SYS_ADMIN`; the loader degrades, says so, and still attributes.
- A process that exited before `/proc` was read lost its cgroup; the
  loader now maps the cgroup id back to a path.
- An override file parser bug (spaces around `=`) and a dpkg error line
  parsed as a package name, both caught by tests.
- The F3 DNS screen formatted times without the active language.

## Deviations and open points

- Snap blocking (`snap.interface`) is not implemented: the spec says only
  Monitor and Flatpak block are functional in F4, and that is what ships.
- Flatpak block reaches the system-wide installation only; per-user
  installs live in home directories the core does not read.
- Alerts are events, not yet findings with remediation.
- Attribution of Flatpak is proven by the scope naming convention
  (`app-flatpak-<id>-<n>.scope`), not by launching a real Flathub app,
  and a Flatpak app launched outside a user session may not get that
  scope. Firefox on Ubuntu is a snap and is covered by the snap proof.
- Spec inconsistency to resolve: `apps.flatpak_perms` (and
  `system.session_lock`, `privacy.camera_mic`) contain `_`, which the
  manifest rule `[a-z0-9-]` rejects. F4 uses `apps.flatpak-network`; the
  name `apps.flatpak_perms` stays reserved for the F7 audit plugin.
- Not measured: bytes per app or destination, countries, 24-hour usage
  (the mockup shows them); the screen shows only what the monitor knows.
- Manual runs on Omarchy and EndeavourOS remain deferred by the
  maintainer.
