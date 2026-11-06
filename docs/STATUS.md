<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# STATUS

Last updated: 2026-11-04 (F9 delivered, report ready for acceptance)

## Current phase

F0 to F5 and F9 are accepted. F6 to F8 are delivered and wait for the
maintainer's acceptance. After acceptance, on 2026-11-04: OpenVPN import
(subset), the HTTPS MCP transport with user-defined tokens, own DNS servers
with a secondary and split DNS, ADR-0042 (nothing in the clear) and its
guard, and signed commits from now on. Next: F10 (packaging, release, docs, site). Run the app with
`scripts/dev-sandbox.sh` (sandboxed daemon, host untouched). Manual runs on
Omarchy and EndeavourOS, and with real assistant clients, are deferred by the
maintainer.

Phases, newest first (report, plan, ADRs):

- **F9, VPN and endpoint, accepted 2026-11-04** (`docs/reports/F9-report.md`,
  `docs/archive/plans/F9-vpn-and-endpoint.md`, ADR-0040 proposed). `endpoint.isolate`,
  `net.vpn` (WireGuard through NetworkManager and a kill switch),
  `endpoint.persistence`, `endpoint.integrity`, `endpoint.av`; address and
  interface matches in nft rules, private-file previews, symmetric execs.
  `--phase f9` green on five distros, with a `tcpdump` proof that a dropped
  tunnel leaks nothing under the kill switch and the EICAR file flagged by
  ClamAV and YARA. OpenVPN import (a documented subset, ADR-0040 accepted, `docs/openvpn-subset.md`) was added after acceptance, verified on five distros. Open: scan-folder discovery and a file watcher (need plugin units, F10).
- **F8, AI assistant (MCP)** (`docs/reports/F8-report.md`,
  `docs/plans/F8-assistant-mcp.md`, ADR-0039 accepted). `ibexwall-mcp` over
  stdio with nine tools and no way to apply, approve or revert; the core's
  proposal queue (irreversible plans refused, approval re-plans and compares);
  `ListAudit`; `ibexctl proposals` and `ibexctl mcp config`; the Assistant
  screen; a hash-chained call log written before each call; the polkit rule
  and the `ibexwall-assistants` group (accepted and shipped). `--phase f8`
  green on five distros with a scripted client (no language model) and an
  injection corpus in the suite. Open: OAuth (not built; a user-defined token instead).
- **F7, hardening and system plugins** (`docs/reports/F7-report.md`,
  `docs/plans/F7-hardening-and-system.md`, ADR-0038). Sixteen plugins;
  `--phase f7` green on five distros (15 scenarios). Open: pending firmware
  and HSI, a plugin monitor interface, GNOME user lock settings, telemetry
  control, OSV lookup.
- **F6, per-app enforcement and Ask mode** (`docs/reports/F6-report.md`,
  `docs/plans/F6-app-enforcement.md`, ADRs 0035 to 0037). Block over TCP, UDP,
  QUIC and IPv6 for the target only, Ask held until answered, fail open;
  `--phase f6` green on five distros.
- **F5, inbound firewall, accepted 2026-11-04** (`docs/reports/F5-report.md`,
  `docs/archive/plans/F5-inbound-firewall.md`, ADRs 0031 to 0034). firewalld, ufw and
  pure nftables adapters, Docker coexistence, byte-exact rollback. Open:
  profiles per connection, rich-rule editing, ufw app profiles.
- **F4, apps and traffic** (accepted; `docs/reports/F4-report.md`).
- **F3, secure DNS** (`docs/reports/F3-report.md`). Own servers, a secondary and split DNS were added on 2026-11-04. Core accepted; DoH
  endpoints, browser policies, captive portal, counters and latency evidence
  delivered; leftovers: DNS backends B2 to B4, IPv6 presets, a DNSSEC ADR, the
  TUI DNS view.
- **F2, posture and UI** and **F1, core and CLI** (accepted).

Cross-phase open items: a unit of its own for each plugin (F10; lifts the
sandbox limits noted in the F9 report), the F10 polkit packaging beyond the
assistants rule, manual runs on real desktops.

## What exists

- Cargo workspace with all 13 crate skeletons (proto, sdk, core, sys,
  ebpf, ebpf-loader, agent, cli, tui, mcp, dns, web, exporters) plus
  xtask; workspace-wide `forbid(unsafe_code)`, edition 2024, MSRV 1.96,
  toolchain pinned to 1.98.1.
- `ibexwall-proto` with the full F0 contract surface: Core API types,
  typed `Op` set, plugin manifest (+ validation), policy bundle
  (+ validation), report, canonical `names` module, deterministic
  schema export.
- `spec/`: generated JSON Schemas (27) and varlink IDL (3 interfaces);
  `cargo xtask schemas --check` enforces zero drift.
- `cargo xtask vm-test --distro fedora`: QEMU/KVM smoke harness,
  cloud-init NoCloud seed, checksum-verified image cache; PASS with
  Fedora 44 (kernel 6.19.10), running `ibexctl` inside the VM.
- CI: fmt, clippy `-D warnings`, nextest, cargo-deny, schema drift,
  DCO + Conventional Commits; actions pinned by SHA, zero default
  permissions; no VM jobs (ADR-0023).
- Community files, repo AGENTS.md, 23 ADRs, threat model v1.
- `.github-org/` workspace repo ready to become the org `.github`
  (profile README, SECURITY, conduct, issue/PR templates).

## Deviations and notes

- **GPG commit signing disabled locally** (`git config commit.gpgsign
  false` in this clone only) because agent-side pinentry cannot prompt.
  DCO sign-off trailers are present on every commit; re-enable or
  re-sign before pushing (`git rebase --gpg-sign main~10..main` style
  rewrite, or configure gpg with loopback). Not pushed yet (push only on
  request).
- Fedora cloud image/checksum names are discovered from the directory
  listing (checksum file names now vary per respin, e.g.
  `Fedora-Cloud-44-1.7-x86_64-CHECKSUM`); mirrors:
  dl.fedoraproject.org then mirrors.kernel.org. First run downloads
  ~557 MB.
- Host tools installed for VM testing (user-approved): `qemu-img`,
  `genisoimage`. Nothing else touched on the dev host.
- Extra test resources available for later phases (user-provided):
  hosts running Omarchy and EndeavourOS, VirtualBox VMs, docker/podman.
  QEMU/KVM via xtask stays the canonical automated path.

## Pending / next

- F10 done so far: M1 to M7. M1 to M4 (maintainability, multicall plugin
  binary, a unit per plugin, RPM/DEB/Arch packages with `ibexwalld --cleanup`),
  M5 (AppArmor profiles enforcing on Ubuntu 24.04 and 26.04, an SELinux module
  enforcing on Fedora, ADR-0044; packages `ibexwall-apparmor` and
  `ibexwall-selinux`), M6 (`cargo xtask release`: signed artifacts, a CycloneDX
  SBOM, an in-toto provenance statement, `verify-release`, `repro` (192 files
  identical), docs/release.md, the release workflow), M7 (five languages in
  the app and the site, `ibexwall-website`, `ibexwall-docs`,
  `ibexwall-plugin-index` repos built and pushed private; the site Lighthouse
  100). F10b done before that. Remaining: M8 (extend the matrix to smoke every
  earlier phase against installed packages), M9 (the v1.0 checklist and
  report). Publishing (COPR, PPA, OBS, AUR), the official release key, making
  the three new repos public and the Cloudflare Pages deploy need the
  maintainer.
- Domain (P-01 resolved): `ibexwall.com`, bought on Cloudflare. The GitHub org
  `nubian-ibex` Website field points to it. Still to do: org domain
  verification (TXT `_github-challenge-nubian-ibex-org`, then "Verify" in the
  org Pages settings), DNS for site (`ibexwall.com`) and docs
  (`docs.ibexwall.com`), optional Email Routing (`security@ibexwall.com`).
  Decided: host on Cloudflare Pages. The GitHub free plan is enough. Set
  `DOCS_BASE` in `ui/src/lib/site.ts` only once the site is live.
- Translations: the app is complete in en, pt-BR, es, fr, de (see
  docs/translating.md). The website: interface, hardening pages and the four
  standing pages are complete in all five; articles are complete in en and es,
  and pt-BR, fr, de have part of the set (the site falls back to English and
  says so); the docs guides are English so far, with the plugin reference
  generated in all five.
- Cloudflare access: `cf` is installed; the token lives in `~/.zshenv`
  (restart the agent session so it is visible; check with `cf auth whoami`).
- CI VM jobs on a KVM-capable runner.
- `ibexwall-proto` and `ibexwall-sdk` publication to crates.io when contracts
  stabilize.

History of F0 to F3: `docs/archive/STATUS-history-F0-F3.md`.
