<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0006: Plugins as separate sandboxed processes (D-006)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0007

## Context

Third-party plugin code must never run inside the root daemon.

## Decision

Each plugin runs in its own systemd unit generated from its manifest:
`DynamicUser=yes` where possible, `ProtectSystem=strict`,
`NoNewPrivileges=yes`, minimal `CapabilityBoundingSet`, declared
read/write paths and address families. Monitor plugins needing kernel
state get declared capabilities only (CAP_BPF etc.).

## Consequences

- Fault and privilege isolation per plugin; `systemd-analyze security`
  score <= 3.0 expected for capability-free plugins.
- Supervisor complexity (timeouts, restarts, degraded states) lives in
  the core and is tested from F1.
