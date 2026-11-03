<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0032: the connection monitor is its own hardened unit

Status: accepted (2026-11-03). Phase: F4. The first draft had the core
spawn the loader as a child; testing the unit's hardening showed why that
cannot work (see Context).

## Context

The monitor needs `CAP_BPF`, `CAP_PERFMON` and `CAP_NET_ADMIN`, and its
events must reach the rollups and the event bus. `ibexwalld.service` has
`CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN CAP_FOWNER
CAP_DAC_READ_SEARCH` and a syscall filter, and a child inherits both: it
could never hold the BPF capabilities. Giving the daemon those
capabilities would hand them to every plugin supervisor path as well.

## Decision

`ibexwall-monitor.service` runs `ibexwall-ebpf-loader --socket
/run/ibexwall/monitor.sock` with only the capabilities it needs
(`CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`),
`ProtectSystem=strict`, a syscall allowlist plus `bpf perf_event_open`,
`RestrictAddressFamilies=AF_UNIX` and the rest of the usual set. The core
owns the stream socket (mode 0600) and accepts only uid 0 (or its own
uid, for the sandbox and tests) through `SO_PEERCRED`; each line is one
JSON object, parsed as untrusted data. systemd restarts the unit; the
core only reports `monitor.running` and the reason in `ListApps`.

The resolver reports answers (queried name, address, TTL) on a datagram
socket in its own runtime directory (`/run/ibexwall/dns/answers.sock`,
0750 for `ibexwall-dns`); the core joins them with connections. Names
stay in the core's memory for the TTL plus two minutes, bounded to 16k
addresses, and are never written by that channel.

## Findings (all five distros, 2026-11-03, `--phase f4` e2)

- The hardened unit loads, attaches and feeds the socket on Fedora,
  Ubuntu 24.04, Ubuntu 26.04 and Arch with `CAP_PERFMON` alone.
- Debian 13 sets `kernel.perf_event_paranoid=3`, which only lets
  `CAP_SYS_ADMIN` call `perf_event_open`, so the exec tracepoint cannot
  attach there. `CAP_SYS_ADMIN` is too much to hold for this: the loader
  degrades instead. Connections are still seen and attributed; only
  processes that exit before `/proc` is read lose their exec path. The
  loader reports it (`{"meta":"degraded"}`) and `ListApps` shows it.
  An administrator may add `CAP_SYS_ADMIN` through a drop-in.
- Processes that connect and exit at once beat `/proc`; the cgroup id in
  the event (the directory inode in cgroupfs) is mapped back to a path by
  a rate-limited walk of `/sys/fs/cgroup`, so even then the identity is
  right (verified with 20 immediate-exit connects per distro).

## Consequences

- Alerts are events (`apps.first_connection`, `apps.binary_changed`).
  Turning the binary-changed alert into a finding with remediation
  comes with the Apps screen.
- Loopback and unspecified destinations are not recorded: they are local
  plumbing, not network traffic.
- The sandbox root still opens both sockets but no unit connects, so the
  Apps screen reports "waiting for ibexwall-monitor" there.
