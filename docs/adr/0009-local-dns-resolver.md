<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0009: Local DNS resolver behind native backends (D-009)

- Status: Accepted
- Date: 2026-11-01
- Related: ADR-0008, ADR-0010

## Context

Secure DNS needs DoH/DoT/DoQ upstreams, blocklists, caching and NXDOMAIN
synthesis. systemd-resolved offers none of the filtering features and its
DoT-only upstream story is a poor fit; hijacking the system resolver
blindly is how projects break users' networking.

## Options considered

- **resolved-only (no resolver of our own)**: least code; no blocklists,
  no DoH upstream presets; feature gap unacceptable for the product.
- **Bundle dnsmasq/blocky-style generic resolver**: licensing and control
  tradeoffs; we need tight integration with plugin config, events and
  the change engine.
- **Own resolver process (`ibexwall-dns`) + backend adapters** (chosen).

## Decision

Ship `ibexwall-dns` (hickory-dns based): a dedicated unprivileged process
(user `ibexwall-dns`, only `CAP_NET_BIND_SERVICE`) listening on
`127.0.0.153:53` (configurable), with fixed bootstrap IPs, presets,
blocklists and fail-open semantics. System integration happens through
detected backend adapters (resolved+NM drop-ins, resolved+networkd, NM
without resolved, resolvconf hooks), each change going through the change
engine as typed `dns.backend` operations with snapshots.

Enforcement (blocking plaintext 53/853 for everyone but the resolver) is
an nft fragment in our own table, on by default when the plugin is
active. Failure mode defaults to restore: `OnFailure` removes our
drop-ins and restarts resolved.

## Consequences

- hickory-dns capability (DoH3, DoQ, DNSSEC) must be verified in a spike
  during F3; anything missing lands as an ADR update.
- Each backend adapter carries per-distro tests; portal-captive flows
  need explicit care (travel profile).
- The resolver never logs queries unless explicitly enabled (24 h cap).
