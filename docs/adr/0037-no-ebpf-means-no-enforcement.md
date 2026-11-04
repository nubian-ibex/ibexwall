<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0037: Without eBPF there is no per-app enforcement, and the UI says so

Status: accepted (maintainer decision, 2026-11-03). Phase: F6.

## Context

The spec asks for a fallback on machines where the eBPF programs cannot
load: nftables `socket cgroupv2 level N "<path>"` rules for known scopes,
plus NFQUEUE and `/proc`, shown as a degraded mode.

## Findings

- Every distro in the matrix (Fedora 44, Ubuntu 24.04 and 26.04, Debian,
  Arch) loads and attaches the programs; the one limitation seen is
  Debian's `perf_event_paranoid=3`, which withholds the exec tracepoint
  from a unit without `CAP_SYS_ADMIN`. Then rules on a program's path are
  unavailable (reported by the monitor, shown by the UI), while rules on
  services, Flatpak apps, snaps and containers (matched by cgroup) keep
  working.
- `socket cgroupv2` matches one exact cgroup path at a fixed depth. A
  system service has a stable path; a Flatpak app's scope carries a number
  that changes at every launch and a container's carries its id. The
  fallback could therefore cover services only, which is the least
  interesting case for a desktop user, and a half fallback would suggest
  protection it does not give.

## Decision

Degraded mode is honest, not emulated:

- when the monitor cannot load, the Apps screen says the monitor is off
  and why, the mode controls are disabled with that reason, the network is
  open, and `ibexctl apps list` shows the same;
- when only the exec tracepoint is missing, modes for apps matched by
  cgroup stay available and the rest are disabled with the reason;
- nothing is blocked or held while degraded (fail open).

The nft `socket cgroupv2` fallback for system services stays a follow-up,
to be built when a supported distro needs it.

## Consequences

- No second enforcement path to keep correct and test.
- A user on a kernel without eBPF gets monitoring-free, enforcement-free
  behavior with a clear explanation, never a false sense of protection.
- If the user wants the services-only fallback anyway, it is an additive
  change: a core-derived chain next to `apps_ask`, with the same
  reconcile and persistence.
