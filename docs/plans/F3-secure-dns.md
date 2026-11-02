<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# F3: secure DNS

Goal: `net.dns` (plugin) and `ibexwall-dns` (resolver) so DNS leaves the
machine encrypted, blocked domains answer as configured, and turning it off
restores the original configuration byte for byte. Spec: PROMPT.md section
4.8 and phase F3.

Status: draft (autonomous mode, 2026-11-02). Milestones M1 to M3 need no
decision; M4 onward start after the spikes.

## Facts checked

- `hickory-resolver` and `hickory-server` 0.26.3 (2026-09-10, crates.io):
  features for DoT (`tls-*`), DoH (`https-*`), DoH3 (`h3-*`), DoQ
  (`quic-*`), DNSSEC (`dnssec-*`), crypto backend `ring` or `aws-lc-rs`;
  the server has a `blocklist` feature; MSRV 1.88; MIT OR Apache-2.0.
  To confirm in M1: that the server side can act as a forwarding stub
  with a custom request handler (needed for blocking, counters, canary).
- Everything else the spec marks *(verificar)* is a spike below.

## Scope decisions

- **Resolver = forwarding stub, not recursive.** It listens on
  `127.0.0.153:53` (UDP and TCP), answers from the block list, canary and
  allowlist, and forwards the rest to the chosen encrypted upstream with
  bootstrap IPs fixed in the preset (no circular dependency). ECS off.
- **Counters only by default.** Per-category block counters; query log is
  opt-in and never exported. The IP to (domain, TTL) map is short-lived,
  in memory, and exposed to `net.apps` only in F4.
- **Core executes.** `net.dns` proposes typed ops (`file.write` drop-ins,
  `dns.backend`, `nft.fragment`, `browser.policy`, `systemd.unit`); the
  core snapshots, applies in the transient executor, and rolls back.
- **Enforcement on by default** when the plugin is on, switchable off.
- DNSSEC validation: configurable, off by default in the MVP (ADR).
- Browser policies need explicit consent in the plan (never implied).

## Milestones

M1 Resolver core (`ibexwall-dns`)
- Hickory-based stub: UDP/TCP listener, upstream pool with DoT and DoH
  first, DoQ and DoH3 behind a capability probe; health checks; timeouts.
- Presets (Quad9, Cloudflare, Mullvad, AdGuard, DNS4EU, NextDNS/Control D
  with ID) as data with bootstrap IPs, log policy and jurisdiction, each
  with a source URL and consultation date (verify per provider).
- Tests: unit (parse, preset validation), integration against a local
  fake DoT/DoH server with test certificates; fuzz target for the block
  list parsers.

M2 Block lists
- Formats: hosts, plain domain list, adblock `||domain^`; HTTPS download
  with size cap, parse validation, atomic swap; scheduled update with
  jitter; allowlist; NXDOMAIN (default) or `0.0.0.0`/`::`.
- Presets HaGeZi (Light/Normal/Pro/Ultimate), OISD (small/big),
  StevenBlack; licenses and URLs verified before shipping each.
- Tests: golden parse fixtures, proptest on malformed input, memory bound.

M3 Plugin `net.dns` and contracts
- Manifest, config schema, Plan/Apply/Verify, locales en and pt-BR; proto
  additions are additive; `cargo xtask schemas`.
- Counters and status over the plugin socket; failsafe unit
  `ibexwall-dns-failsafe.service` (`OnFailure=`) that removes the
  drop-ins, restarts the resolver service of the host and notifies.
- `on_failure = restore | block` (default `restore`).

M4 Backends (adapters, one test VM each)
- B1 systemd-resolved + NetworkManager: drop-in `50-ibexwall.conf`
  (`DNS=127.0.0.153`, `Domains=~.`) plus the NM drop-in.
- B2 resolved + systemd-networkd (`UseDNS=` interaction).
- B3 NetworkManager without resolved (dnsmasq or default).
- B4 plain `resolv.conf` with resolvconf/openresolv hooks, never a blind
  overwrite.
- Detection picks one backend and explains why; unsupported combinations
  are refused with a clear message, not guessed.

M5 Enforcement and DoH
- nft fragment in `table inet ibexwall`: drop outbound UDP/TCP 53 and
  TCP/UDP 853 for every uid except the resolver's; loopback allowed.
- Known DoH endpoint blocking through the resolver; Firefox canary
  `use-application-dns.net` answers NXDOMAIN.
- Browser policies (Firefox `policies.json`, Chromium family
  `DnsOverHttpsMode: "off"`) behind consent; per-distro paths verified.

M6 Captive portal and failure modes
- NetworkManager connectivity `PORTAL` temporarily allows DHCP DNS with a
  notice and a short deadline; restores automatically.
- Kill the resolver: `restore` removes drop-ins and notifies; `block`
  keeps enforcement and shows the state.

M7 UI, TUI and agent
- DNS screen (mockup flow): provider, lists, enforcement, consent,
  counters, health; Plugins/Overview cards use real DNS state.
- i18n en and pt-BR, a11y (axe, keyboard), light and dark, all states.
- Also close the open F2 mockup gaps if the maintainer decides so
  (recommendation and recent activity panels, plugin profile selector).

M8 VM phase `--phase f3` and acceptance
- Per distro: tcpdump shows no clear DNS out (except the encrypted
  upstream); blocked domain answers per config; killing the resolver
  triggers the right mode; disabling restores the original files byte for
  byte; Firefox canary is NXDOMAIN; latency targets met.
- Threat model and capabilities matrix updated; phase report.

## Spikes (time-boxed, results become ADRs)

- S3-a (M1, 1 day): hickory server as forwarding stub with a custom
  handler; DoT, DoH, DoQ, DoH3 against real providers; memory and latency.
- S3-b (M4, 2 days): NM `global-dns` x resolved x `DefaultRoute` on
  Fedora, Ubuntu, Debian and Arch; confirm that DHCP per-link DNS cannot
  bypass the stub.
- S3-c (M4, 1 day): networkd `UseDNS=` and resolvconf hooks.
- S3-d (M5, 1 day): browser policy paths per distro (Firefox and
  Chromium family, Flatpak and Snap variants).

## Risks

- Breaking connectivity on a bad plan: mitigated by confirm-with-deadline
  (network risk), failsafe unit, and rollback by the executor.
- Distro DNS stacks differ; an unverified combination is refused.
- Blocking port 853 and known DoH can break captive portals and corporate
  VPNs; mitigated by the portal flow and per-network profiles.
- List licenses and provider claims can change; every shipped fact carries
  a URL and consultation date.
- Privacy regression if logging leaks: logs off by default, a test
  asserts no query log or domain in reports.

## Test plan

- Unit and proptest in `ibexwall-dns` and the plugin; fakes for
  `Fs`, `Systemd`, `Sysctl` in `ibexwall-sys`; no host changes.
- VM per distro (fedora, ubuntu-24.04, ubuntu-26.04, debian, arch) for
  each backend that distro uses; chaos: kill the resolver, drop the
  upstream, corrupt a list download.
- Restore byte for byte compared with a pre-apply hash of every touched
  file.

## Definition of done

Section 17 of the spec, plus: acceptance list of F3 passes in every VM,
ADRs for S3-a to S3-d and for DNSSEC default, phase report, updated
`STATUS.md`.

## Open questions for the maintainer

- Which provider presets ship in the default UI order, and is NextDNS /
  Control D (account-ID based) in scope for the alpha?
- Do the missing F2 mockup panels block v0.1 or move into M7?
