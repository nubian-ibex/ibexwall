<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0014: Managed mode via open contracts (D-014)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0013

## Context

A corporate tier must exist without weakening or closing the open
client, and users must be able to verify what leaves their machine.

## Decision

The core implements org precedence, locks, `com.ibexwall.Policy`,
JCS+ed25519 signed bundles with anti-rollback, the report generator and
break-glass verification. The proprietary plugin is rootless, uses only
public API/SDK, and lives in a private repository.

## Consequences

- "The closed plugin cannot alter open protections" stays verifiable:
  public spec, SBOM, periodic external audit.
- Report schema intentionally lacks browsing/DNS history, files,
  screen, password and keystroke fields.
