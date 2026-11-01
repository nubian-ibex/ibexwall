<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0002: Canonical naming and spelling (D-002)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0021

## Context

Consistent binary, package and brand names avoid collisions
(`iwctl` already exists for iwd).

## Decision

Brand spelling `IbexWall`; technical/packaging lowercase `ibexwall`.
CLI is `ibexctl`; daemon is `ibexwalld`; other binaries carry the
`ibexwall-` prefix. All identifiers live in `ibexwall_proto::names`.

## Consequences

- Renames require an ADR; new artifacts must contain `ibexwall` in
  their names (tested).
