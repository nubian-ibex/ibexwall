<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0003: Desktop first; Fedora, Ubuntu, Debian, Arch (D-003)

- Status: Accepted
- Date: 2026-11-01

## Context

Server fleets are the commercial future, but the gap to close is the
Linux desktop; the daemon+API architecture keeps the server door open.

## Decision

Target desktop first: Fedora (last two), Ubuntu LTS + current interim,
Debian 13, Arch and derivatives (community). Servers and immutable
distros come after v1 (P-09).

## Consequences

- systemd, cgroup v2, NetworkManager paths are hard requirements.
- Exact tested versions are pinned per release in the compatibility
  notes, starting with the F1 VM matrix.
