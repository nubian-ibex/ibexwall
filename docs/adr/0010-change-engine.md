<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0010: Change engine with snapshots and timed confirmation (D-010)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0007, ADR-0009, threat model

## Context

Non-technical users must be able to harden their machines without fear,
and administrators must trust that failed or abandoned changes cannot
leave systems half-configured, especially for network and DNS changes
that can lock a machine out.

## Options considered

- **Apply directly, log enough to undo manually**: simplest; fails the
  "non-technical user" bar and crash-safety.
- **Declarative-only reconciliation** (no imperative steps): cannot
  express restarts, downloads or provider-specific actions.
- **Transactional imperative engine** (chosen): plan (validated typed
  ops + diff + risk flags) → approve (polkit) → apply (snapshot first,
  atomic file writes, progress) → verify → confirm window for network
  risk → commit, with rollback on failure/timeout/crash.

## Decision

Every system mutation goes through the change engine as a transaction.
Snapshots capture prior content, mode, owner, unit state, sysctl values
and nft dumps with checksums. Plans expire (default 10 min) and go stale
when the state fingerprint changes. Network-risk transactions enter
`pending_confirm` with a deadline (default 60 s); missing confirmation
triggers automatic rollback. On daemon start, any transaction found in
`applying` or `pending_confirm` is rolled back and the user notified.
One transaction runs at a time; operations are idempotent.

## Consequences

- The engine is the most safety-critical code in the project: it needs
  the highest coverage targets and chaos tests (kill -9 mid-apply, VM
  reset, uninstall with active resources).
- Some operations are inherently irreversible (`package.install`,
  `kexec_load_disabled`); they carry risk flags and explicit extra
  consent, and are excluded from "everything is reversible" claims.
- Timed confirmation can annoy experts; timeout is configurable per
  apply (`--confirm-timeout`).
