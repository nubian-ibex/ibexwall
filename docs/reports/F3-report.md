<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F3 report: secure DNS

Date: 2026-11-02. Plan: `docs/archive/plans/F3-secure-dns.md`. ADRs: 0028, 0029, 0030.

## What was done

- `ibexwall-dns`, a forwarding stub on hickory 0.26: encrypted upstreams
  (DoT, DoH, DoQ, DoH3), block policy with allowlist, the Firefox DoH
  canary, known DoH endpoints refused through the stub, 5 s upstream cap,
  per-category counters without query names, `--failsafe`, and a
  benchmark binary for the latency targets.
- Block lists: hosts, domain and adblock parsing with validation and
  proptest; https-only downloads with a 64 MiB cap, atomic replacement
  and jitter; a bad download never replaces a good list.
- `net.dns` plugin for the systemd-resolved stack: the settings file, the
  resolved drop-in (with `FallbackDNS=` cleared so a dead resolver cannot
  leak plain queries), the resolver unit, the nft guard that refuses 53
  and 853 for everyone but the resolver, browser policies with explicit
  consent, both failure modes, provider presets with vendor-verified
  facts (Quad9, Cloudflare, AdGuard, DNS4EU).
- Core: typed nft fragments with exact rollback (prior chain captured,
  `nft list ruleset` identical after rollback); the browser.policy
  executor with per-vendor files from their own documentation; the
  GetDnsStatus counter channel; units restarted by a transaction are
  restarted after rollback.
- UI: the Secure DNS screen (providers with logging and jurisdiction,
  transport, list, enforcement, browser consent, counters) in en and
  pt-BR; ChangeFlow shows why a plan was refused.
- Agent: captive portals are detected and announced with the relief
  steps; enforcement is never lifted automatically.

## How it was verified

- 227 workspace tests, clippy/fmt/deny clean, schemas without drift; 36
  UI tests and 12 e2e (axe on both themes and locales).
- `cargo xtask vm-test --phase f3`: 13 scenarios on fedora,
  ubuntu-24.04, ubuntu-26.04, debian and arch, including a packet capture
  with no clear DNS, refusal of 53/853 for a user and for root, the
  canary, DoH endpoints, warm p99 under 2 ms and uncached overhead under
  5 ms versus direct DoT from the exempt user, one kill recovering, the
  failsafe after repeated kills (including its start-limit fix), exact
  rollback three times, browser policies written and rolled back, and
  `on_failure=block` failing closed.
- `--phase f1` and `--phase f2` regressions pass on fedora after the
  shared changes.

## Defects found and fixed along the way

- `systemctl is-enabled` exits non-zero for states other than enabled;
  snapshots read "disabled" as "not found" and rollback never disabled
  such units (an F1 defect).
- The failsafe could fail exactly when needed: a burst of transaction
  restarts trips resolved's start rate limit. It now clears it first.
- The DoH endpoints list was never downloaded when no block lists were
  configured.
- The transient executor did not make browser policy directories
  writable, and a sandbox root produced a settings path the manifest
  check rejected.
- `ibexctl --set` sent booleans as strings.

## Deviations

- backends are adapters inside the plugin proposing
  `file.write`/`systemd.unit`; the `dns.backend` operation stays
  reserved. Only the systemd-resolved stack is supported; others are
  refused with a reason (B2 to B4 pending).
- captive portals are announced, not auto-relieved.
- DNSSEC validation stays off and is not compiled in until an ADR enables
  it; Mullvad was rejected as a preset (public encrypted DNS discontinued
  2026-11-02).

## Risks

- An application with its own DoH client and an unknown endpoint can
  still bypass DNS-level blocking; inherent and documented.
- A VPN client with its own routing domains can win for those domains
  (listed as a "may affect").
- Only IPv4 upstream addresses are preset until connectivity probing
  lands; a machine without IPv4 cannot use the presets.

## Pending

- Backends B2 to B4 (resolved + networkd `UseDNS=`, NetworkManager alone,
  resolv.conf hooks), IPv6 preset addresses, DNSSEC ADR, the dedicated
  TUI DNS view, sending the agent inventory to the core (F4).

## Next step

F4 (apps and traffic): identity, eBPF monitor mode, correlation, the Apps
and network screen.

## After acceptance: your own DNS servers (2026-11-04)

- The resolver accepts a `plain` upstream (UDP and TCP) only for addresses on
  the machine's own networks (private, loopback, link-local, unique local,
  CGNAT such as VPNs use); a public address is refused at plan time and at
  start, so clear DNS never crosses the Internet.
- The server list is ordered: the first answers, the next ones take over
  (a secondary). Routes send the names under given domains to their own
  servers (split DNS: the corporate zone to the corporate resolver);
  everything else keeps the encrypted default.
- The check tells the person, as information and never a failure, which DNS
  servers the network or a VPN offers and which of their own upstreams go
  unencrypted. The screen shows them, fills one in on a click, takes a first
  and a second server and internal domains, and holds back the review while
  something is wrong.
- Found and fixed on the way: the resolver's default log filter let the DNS
  libraries write every queried name to the journal, contradicting the "no
  query names are logged" promise. Their level is now warn; the VM scenario
  asserts the journal holds no queried name.
- Verified (VM scenario d11, five distros): a local resolver answers only
  corp.example, a public name never reaches it and stays encrypted, the plain
  upstream is announced, plain DNS to a public address is refused, and the
  journal has no query name.
