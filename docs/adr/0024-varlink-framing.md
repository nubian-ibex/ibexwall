<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0024: In-repo varlink framing (spike S1-a)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0005

## Context

The core IPC is varlink over unix sockets (ADR-0005). The spec required
a spike to choose between the `zlink` crate, the official `varlink`
crate, and hand-rolled framing over tokio.

## Options considered (spike S1-a, 2026-11-01)

- **`zlink` 0.8.0** (updated 2026-10-29, active): async-first on tokio,
  with `zlink-codegen` generating client/server code from `.varlink`
  files. Healthy project (talk at All Systems Go 2025).
- **`varlink` 13.0.0** (updated 2025-10-20): the official Rust
  implementation, sans-io core; also built around IDL-first codegen.
- **In-repo framing crate over tokio**: NUL-delimited JSON messages,
  `more`/`continues` streaming, named errors, the
  `org.varlink.service.*` bootstrap methods.

## Decision

Implement an in-repo crate `ibexwall-varlink` (server + client framing)
with serde_json + tokio only.

Rationale:

1. Our contract pipeline is **proto-first**: Rust types generate the
   IDL (`cargo xtask schemas`). Both crates are designed
   IDL-first (codegen consumes `.varlink`); adopting them means a
   double-generation pipeline (Rust → IDL → codegen → Rust) with a new
   drift class and a codegen step in every build.
2. The wire protocol is small and fully specified; ~a few hundred lines
   in-tree keep the root daemon's only input surface directly
   auditable, versioned with the contracts, and dependency-free beyond
   what we already ship.
3. We need unusual control on the server side anyway: per-connection
   peer credentials (SO_PEERCRED, ADR-0025), per-method authorization
   hooks before dispatch, and streaming backpressure for events.

## Consequences

- We own protocol edge cases (partial reads, oversized messages,
  malformed JSON, `oneway`) with unit tests; a fuzz target for the
  framing lands with the fuzz suite (SEC-08).
- Switching to `zlink` later is possible via ADR revision if framing
  maintenance costs exceed the switch cost; the interfaces themselves
  are unchanged (the IDL in `spec/` is authoritative).
- The `org.varlink.service.GetInfo` / `GetInterfaceDescription` /
  `GetVendorInformation` bootstrap methods are served from the same
  generated IDL, so clients built with official tooling still work.
