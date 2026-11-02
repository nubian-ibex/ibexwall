<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# ADR-0028: ibexwall-dns is a forwarding stub on hickory 0.26

Status: accepted (spike S3-a, 2026-11-02). Phase: F3.

## Context

The spec asks for a local resolver on `127.0.0.153:53` that blocks by list,
intercepts the browser DoH canary, counts without logging, and forwards
everything else over an encrypted upstream (spec section 4.8; hickory
support for DoH, DoT, DoQ, DoH3 and DNSSEC to be verified).

## Options

1. Recursive resolver (hickory recursor): no third party sees the query,
   but the product promise is encrypted DNS to a chosen provider, latency
   and load are worse, and it needs root hints and DNSSEC to be safe.
2. Forwarding stub on `hickory-server` with a custom `RequestHandler` and
   `hickory-resolver` as the upstream client (chosen).
3. Embed dnsmasq or unbound: smaller code, but a second process to
   supervise, no encrypted upstream in dnsmasq, and C code in the path.

## Decision

Option 2. Findings from the spike (hickory 0.26.3, crates.io, 2026-09-10,
`ring` backend, MIT OR Apache-2.0):

- A custom `RequestHandler` gets the query, answers locally (NXDOMAIN, or
  `0.0.0.0` and `::`) or forwards, and relays upstream NXDOMAIN and NODATA
  faithfully. Covered by `crates/ibexwall-dns/tests/forward.rs`.
- Upstreams are addressed by IP plus the certificate name, so no DNS is
  needed to reach the upstream (fixed bootstrap).
- Real providers, from the development host: Cloudflare answered over DoT,
  DoH and DoH3 (warm 7 to 10 ms) and timed out over DoQ; Quad9 answered
  over all four (warm about 50 ms from this network). The DoQ failure is
  expected for a provider that does not offer DoQ; presets must list only
  transports the provider documents.
- A failed upstream takes about 15 s to give up on QUIC despite the 3 s
  option; the stub must cap its own wait and answer SERVFAIL (follow-up in
  M1 hardening).
- DNSSEC validation is a separate feature (`dnssec-ring`); it stays off in
  the MVP and is not compiled in until an ADR enables it.
- Trust anchors come from `webpki-roots` (CDLA-Permissive-2.0, added to
  `deny.toml`), so reaching the upstream does not depend on the host trust
  store.

## Consequences

- No query names are logged; only per-category counters exist.
- The handler is `Clone` (shared state in `Arc`) so the daemon can swap the
  policy and read counters while the server runs.
- Provider facts (logging, jurisdiction, transports) must be verified from
  the provider's own documentation before a preset ships.
