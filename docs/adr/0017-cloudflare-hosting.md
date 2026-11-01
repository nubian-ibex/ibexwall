<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0017: Website and docs on Cloudflare (D-017)

- Status: Accepted
- Date: 2026-11-01

## Context

Static sites need preview deploys, edge TLS and DDoS resilience without
operating servers.

## Decision

`ibexwall-website` and `ibexwall-docs` (Astro) deploy to Cloudflare
(Pages or Workers static assets) with per-PR previews. No third-party
trackers.

## Consequences

- CI holds the deploy definitions; DNS depends on P-01 domains.
