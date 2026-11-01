<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0016: Protections never disabled by billing state (D-016)

- Status: Accepted
- Date: 2026-11-01

## Context

Disabling security as a payment enforcement mechanism is unacceptable
and would poison trust in the open client.

## Decision

Non-payment may degrade the management console to read-only after a
grace period. Endpoints keep all protections and the last valid policy,
indefinitely.

## Consequences

- Revenue enforcement lives entirely in the proprietary tier.
- The open client contains no license-check hooks affecting
  protections.
