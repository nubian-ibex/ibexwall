<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0012: Client licensing: GPL-3.0-or-later, DCO, no CLA (D-012)

- Status: Accepted (legal review pending, P-10)
- Date: 2026-11-01
- Related: ADR-0013

## Context

The client must stay fully open and auditable, remain fundable long-term
(a managed/corporate tier exists outside this repository), keep
contribution friction low, and remain compatible with third-party plugin
ecosystems.

## Options considered

- **Permissive (MIT/Apache-2.0) client**: maximum adoption; nothing stops
  a closed fork of the entire security center, undermining the "open
  security" promise and the dual-license strategy.
- **AGPL-3.0**: strongest copyleft; hosting/SaaS teeth are irrelevant
  here (desktop software) and it complicates enterprise adoption.
- **GPL-3.0-or-later client + permissive contract crates** (chosen).

## Decision

The client monorepo is GPL-3.0-or-later. Contributions use DCO
(`git commit -s`), no CLA. `ibexwall-proto` and `ibexwall-sdk` are the
deliberate exceptions (see ADR-0013) so plugins of any license can link
the contracts.

## Consequences

- All dependencies must be permissively licensed (no GPL in deps), which
  `cargo-deny` enforces; GPL appears only in our own crates and dual
  eBPF code.
- No CLA keeps contribution friction low; DCO provides provenance.
- Corporate managed mode lives in a separate proprietary repository that
  talks only through public contracts; legal review of the whole
  licensing setup is tracked (P-10).
