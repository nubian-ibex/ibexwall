<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0013: Permissive proto/sdk; dual-licensed eBPF (D-013)

- Status: Accepted (legal review pending, P-10)
- Date: 2026-11-01
- Related: ADR-0012

## Context

Third parties (including the proprietary managed plugin) need to link
the contract types and the plugin SDK. Linking GPL code from a closed
plugin would create a derivative work and block that path. eBPF programs
loaded into the kernel interact with GPL-only kernel helpers, which
constrains licensing of that code specifically.

## Options considered

- **Everything GPL**: simplest tree; kills third-party plugin licensing
  freedom and the managed-plugin architecture.
- **Everything permissive**: loses copyleft on the client itself.
- **Split by boundary** (chosen): contracts and SDK permissive; client
  GPL; eBPF dual.

## Decision

- `ibexwall-proto` and `ibexwall-sdk`: Apache-2.0 OR MIT, and they must
  never depend on GPL-only crates (enforced in review and by
  `cargo-deny` configuration when they gain dependencies).
- `ibexwall-ebpf`: GPL-2.0-only OR MIT (dual), satisfying kernel helper
  licensing while keeping the option of permissive reuse of that code.

## Consequences

- Speaking varlink to the GPL daemon over IPC does not create derivative
  works; linking the crates would. The boundary is crate-level and
  documented in `LICENSE` and `REUSE.toml`.
- Requires contributors to keep the boundary clean; CI lint for
  dependency direction is a follow-up task.
- Flagged for legal validation together with ADR-0012 (P-10).
