<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0008: Own nftables table; inbound via adapters (D-008)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0007, ADR-0009

## Context

Inbound firewall must respect the distro's manager (firewalld, ufw) so
users keep their native tools and semantics. Outbound enforcement and DNS
guarding need nftables rules that survive other tools' reloads.

## Options considered

- **Write into firewalld's/ufw's tables**: overwritten on reload; breaks
  user expectations; explicitly forbidden by product rules.
- **Replace the manager** (own stack only): hostile to distro
  integration; loses zones/services semantics.
- **Own table + adapters** (chosen).

## Decision

The core is the single owner of `table inet ibexwall`. Plugins contribute
fragments (chains and sets prefixed by their id); the core composes the
table and applies it atomically through the nftables JSON API
(libnftables/`nft -j`), validating with `nft -c` first. Native tables of
other tools are never touched.

Inbound firewall goes through adapters: firewalld (D-Bus), ufw (CLI with
fixed argv, no shell) and a bare "basic inbound protection" chain in our
own table for distros without a manager.

## Consequences

- Coexistence with Docker/libvirt/VPNs must be tested continuously
  (matrix in CI from F5).
- Two sources of truth (adapter state + our view) require drift
  detection and "adopt or reapply" flows.
- The bare-nftables adapter gives a consistent fallback everywhere.
