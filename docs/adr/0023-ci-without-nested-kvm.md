<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0023: CI runs no VM jobs at F0 (deviation)

- Status: Accepted
- Date: 2026-11-01
- Related: docs/archive/plans/F0-foundation.md

## Context

The engineering spec lists a `vm-tests` CI workflow, but GitHub-hosted
runners expose no nested KVM (`/dev/kvm`), which the QEMU harness
needs for usable boot times.

## Options considered

- **QEMU with TCG (software emulation) on hosted runners**: boot and
  smoke would take tens of minutes and be flaky; poor signal for the
  cost.
- **Larger/self-hosted runners with KVM**: viable; requires ops decisions
  and spend.
- **VM tests local-only at F0, static + unit CI** (chosen, provisional).

## Decision

At F0 the CI pipeline runs fmt, clippy, nextest, cargo-deny, schema
drift and DCO checks. `cargo xtask vm-test` is the local (and primary
developer) verification path. CI VM jobs are revisited in F1 with a
self-hosted or larger runner (spike S0-b).

## Consequences

- VM-only regressions can land between developer runs; mitigated by
  making vm-test fast, cached and part of the phase checklist.
- The deviation is explicit and time-boxed to F1.
