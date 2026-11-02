<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0027: ibexwall-varlink is Apache-2.0 OR MIT

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0013, ADR-0024

## Context

`ibexwall-sdk` must stay permissive (ADR-0013) so third-party and
proprietary plugins can link it. The SDK needs the varlink wire code, which
was GPL-3.0-or-later and depended on the GPL `ibexwall-sys`. Linking it
would make every plugin a derivative of GPL code.

## Decision

Relicense `ibexwall-varlink` (our own code) to Apache-2.0 OR MIT and drop
its dependency on `ibexwall-sys` (peer credentials come from `rustix`,
which is permissively licensed). The SDK depends on it; `cargo deny` keeps
enforcing the license allowlist. `REUSE.toml` lists the crate with the
proto/sdk group.

## Consequences

- The GPL daemon keeps using the same crate; nothing changes for it.
- Future dependencies of `ibexwall-varlink` and `ibexwall-sdk` must be
  permissive; a review check, as for proto and sdk.
- Pending legal review (P-10) now covers one more crate.
