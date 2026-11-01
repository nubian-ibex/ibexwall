<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0011: Monorepo for the open source client (D-011)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0012

## Context

While the plugin API is unstable, split repositories would turn every
contract change into cross-repo PR cascades.

## Decision

One repository for core, plugins, CLI, TUI, UI, MCP, SDK and packaging.
Separate repositories only where license, visibility or release cadence
differ (profiles, plugin index, website, docs, and the proprietary
managed/server/cloud repos).

## Consequences

- Contract changes are atomic; CI is one pipeline.
- Official plugins can be extracted later because their contract is
  external by design.
