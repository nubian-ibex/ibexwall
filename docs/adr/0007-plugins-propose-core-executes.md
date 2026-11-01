<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0007: Plugins propose, the core executes (D-007)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0006, ADR-0008, ADR-0010

## Context

Plugins will come from many authors with varying quality. If plugins
could change the system directly, every plugin would be a root-equivalent
component and sandboxing, audit and rollback would be best-effort.

## Options considered

- **Plugins apply changes themselves**: simplest plugin API; forfeits a
  single audited execution path, manifest permissions become advisory,
  snapshots/rollback become per-plugin conventions.
- **Plugins declare desired state; core reconciles (declarative-only)**:
  great for idempotent config; awkward for imperative steps (run
  `chronyc`, restart services in order) and for diff previews.
- **Hybrid: plugins return typed operation lists; core validates,
  snapshots, executes and can invert** (chosen).

## Decision

A plan is a list of typed operations (`file.write`, `systemd.unit`,
`sysctl.set`, `nft.fragment`, ...) defined in `ibexwall-proto`. The core
validates every operation against the plugin manifest `[privileges]`,
locked keys and conflicts, then snapshots, previews (diff), executes in
order, verifies, and rolls back from the snapshot on failure or missed
confirmation. Plugins never write to the system themselves.

Controlled exception: signed official `monitor` plugins may keep runtime
kernel state (eBPF maps) with declared capabilities, reconciling desired
state persisted by the core through the same plan flow.

## Consequences

- One audited execution path; permissions are enforced, not advisory.
- Generic snapshot/rollback works for all plugins; operation inverses
  live in one place.
- Adding a new system effect costs a new typed operation (validation +
  inverse + tests), which is the intended friction.
- Plugin API is less "magic": plan/verify must be explicit.
