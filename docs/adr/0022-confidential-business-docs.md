<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0022: Confidential business material stays out (D-022)

- Status: Accepted
- Date: 2026-11-01

## Context

Business planning documents exist in the private workspace but must
never leak into public repositories, issues, commits or docs.

## Decision

Business docs (plans/pricing, checkout/tenants, brand/domains) remain
in the private workspace only. This repository carries no references
to their contents beyond this record.

## Consequences

- Agents and contributors copy nothing from those documents into
  public artifacts; prices appear as placeholders until decided.
