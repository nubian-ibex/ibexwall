<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0021: Reverse-DNS prefix com.ibexwall (D-021)

- Status: Accepted (provisional)
- Date: 2026-11-01
- Related: ADR-0002

## Context

polkit actions, varlink interfaces and the app id need a stable
reverse-DNS prefix, ideally matching an owned domain.

## Decision

Use `com.ibexwall` everywhere, centralized in `names`. Pending domain
acquisition (P-01): if ibexwall.com is not acquired, the constant is
the single change point.

## Consequences

- Renaming after wide deployment would be painful; resolve P-01 before
  v1.0.
