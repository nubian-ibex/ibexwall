<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0025: Caller identity and polkit subject (spike S1-b)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0005, docs/threat-model.md

## Context

Every privileged varlink method must know *who* is calling, without a
PID-reuse race (TOCTOU). The spec named `SO_PEERCRED` +
`SO_PEERPIDFD` (kernel >= 6.5) and pidfd-based polkit subjects as the
goal, with `unix-process` + start time as fallback.

## Findings (2026-11-01)

- `SO_PEERPIDFD` exists since Linux 6.5; our targets (kernel 6.19 era)
  all support it.
- Modern polkit (>= 124) itself is pidfd-oriented; the `unix-process`
  subject with **pid + start time** remains the portable, supported
  subject form across our distro matrix, and polkit validates the start
  time against /proc before matching rules.
- The current safe-Rust syscall layer we use (rustix) does not expose
  `SO_PEERPIDFD`; using it today would require an FFI module. The
  workspace forbids `unsafe` outside designated crates (SEC-07).

## Decision

F1 ships: `SO_PEERCRED` for uid/pid on each connection, `/proc/<pid>/stat`
start time read by the daemon (root), and polkit `CheckAuthorization`
with subject `unix-process:{pid, starttime}`. Never authorize by bare
PID; a missing or mismatched start time denies the call.

Adopt `SO_PEERPIDFD` + pidfd subjects in a designated FFI crate as soon
as one is warranted by other needs (eBPF loader lands with F4 anyway);
tracked in the threat model update triggers.

## Consequences

- No unsafe code and no new dependency in F1; portability across the
  whole distro matrix (polkit versions vary).
- Window between connect and /proc read is closed by start-time
  matching: a recycled PID yields a different start time → deny.
- Denial is fail-closed: identity resolution failure = PermissionDenied,
  never a bypass.
