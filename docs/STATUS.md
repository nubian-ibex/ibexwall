<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# STATUS

Last updated: 2026-11-07 (F11b fully delivered; all five distros green)

## Current phase

**Now: v0.1.1, desktop fixes.** v0.1.0 is published; installing it on
Fedora 45 and Ubuntu 26.10 (KDE) showed the app cannot change anything
as a desktop user. Plan: `docs/plans/v0.1.1-desktop-fixes.md` (M1 to
M7). Decision: ADR-0045 (interactive polkit authorization, option 1:
an `allowInteractiveAuthentication` field per call). Both are proposed
and wait for the maintainer's approval. Next after it: the first-run
assistant (B-04/B-06).

F0 to F10 and F10b are delivered. The F10 acceptance items are verified:
package install, upgrade and remove with no residue across the five
distros, the smoke of the earlier phases against the installed packages,
the signed release pipeline with SBOM and provenance, five languages in
the app and the site, and the public site and docs on Cloudflare Pages.
GitHub CI is green on every job (fmt, lint, tests with cargo-deny,
docs, coverage, the UI checks, commit hygiene) plus Scorecard, and the
commit history is signed and verified.

The audit plan is fully closed:

- `docs/plans/F10c-audit-fixes.md`, from the 2026-11-06 validation pass.
  The review found five P0, fourteen P1 and twelve P2 issues. M1 (the five
  P0), M2 (the transaction engine), M3 (the P2 set) and M4 (the deep
  plugin, DNS and MCP audit) are done, and the three remaining items
  closed on 2026-11-07: two were already done in code (stale notes), and
  the third (bounded, regular-file-only reads; symlink-checked socket
  chmod; prune after rollback) landed with tests. Fuzz targets are
  deferred to after v1.0.

F11a (Compliance) was approved and is delivered; see
`docs/reports/F11a-report.md`.

F11b (Managed-mode) is complete: `docs/plans/F11b-managed-mode.md`.

Architecture decisions are recorded internally, outside this repository;
the public plans and reports are self-contained without them.

Phases, newest first (report, plan):

- **F11a, compliance** (2026-11-06, `docs/reports/F11a-report.md`). The
  Compliance section: six shipped profiles (Baseline, LGPD, CMN 4.893/5.274,
  NIST 800-53 r5, NIST 800-171 r3, ISO 27001:2022 theme 8), the evaluator
  with six control states and attestations/exceptions, the CLI, the UI
  screen and two read-only MCP tools, the device-signed JSON/CSV/OSCAL
  export, and the `--phase f11a` run green on all five distros. The run
  also fixed a sysctl-plan bug that would have made the recommended preset
  fail on any kernel with `bpf_jit_harden` locked down.- **F11a, compliance** (2026-11-06, `docs/reports/F11a-report.md`). The
  Compliance section: six shipped profiles (Baseline, LGPD, CMN 4.893/5.274,
  NIST 800-53 r5, NIST 800-171 r3, ISO 27001:2022 theme 8), the evaluator
  with six control states and attestations/exceptions, the CLI, the UI
  screen and two read-only MCP tools, the device-signed JSON/CSV/OSCAL
  export, and the `--phase f11a` run green on all five distros. The run
  also fixed a sysctl-plan bug that would have made the recommended preset
  fail on any kernel with `bpf_jit_harden` locked down.
- **F11b, managed-mode contracts** (2026-11-07, in flight,
  `docs/plans/F11b-managed-mode.md`). M1-M6 done; `--phase f11b`
  green on fedora, ubuntu-24.04, ubuntu-26.04, debian and arch.
  policy bundle verification (JCS + ed25519 against trust anchors,
  expiry and anti-rollback), the `com.ibexwall.Policy` varlink
  interface (ApplyBundle writes the org layer; GetEffective;
  BuildReport assembles the spec report; UseBreakGlass verifies a
  signed break-glass code), `ibexctl policy apply-bundle`, the
  Organisation screen (five languages, shows locks and transparency),
  and the `--phase f11b` xtask harness. A test VM run on all five
  distros is pending.
- **F10b, assistant connection, detection, hardening** (2026-11-05,
  `docs/plans/F10b-assistant-detection-hardening.md`). The Assistant
  connect flow, the `system.assistant` plugin owning `mcp.toml`, token
  management, OpenSCAP, rkhunter and chkrootkit, local exposure, and the
  Hardening catalog in the app.
- **F10, packaging, release, docs, site** (`docs/plans/F10-packaging-release.md`).
  M1 to M9: maintainability, the multicall plugin binary, a unit per
  plugin, RPM/DEB/Arch packages with `ibexwalld --cleanup`, AppArmor
  enforcing on Ubuntu and an SELinux module on Fedora, `cargo xtask
  release` with signing, SBOM and provenance plus `verify-release` and
  `repro` (192 files identical), five languages, the website, docs and
  plugin-index repositories, the five-distro smoke, and the release
  checklist (`docs/release-checklist.md`).
- **F9, VPN and endpoint, accepted 2026-11-04** (`docs/reports/F9-report.md`,
  `docs/archive/plans/F9-vpn-and-endpoint.md`). `endpoint.isolate`,
  `net.vpn` (WireGuard through NetworkManager and a kill switch),
  `endpoint.persistence`, `endpoint.integrity`, `endpoint.av`; OpenVPN
  import (a documented subset, `docs/openvpn-subset.md`). `--phase f9`
  green on five distros, kill-switch leak proof included. Open:
  scan-folder discovery and a file watcher.
- **F8, AI assistant (MCP)** (`docs/reports/F8-report.md`,
  `docs/plans/F8-assistant-mcp.md`). `ibexwall-mcp` over stdio with nine
  read-only tools, the proposal queue, `ListAudit`, `ibexctl proposals`
  and `ibexctl mcp config`, the hash-chained call log, the polkit rule
  and the `ibexwall-assistants` group. `--phase f8` green on five
  distros with an injection corpus. Open: OAuth (a user-defined token
  shipped instead).
- **F7, hardening and system plugins** (`docs/reports/F7-report.md`,
  `docs/plans/F7-hardening-and-system.md`). Sixteen plugins at the time;
  `--phase f7` green on five distros. Open: pending firmware and HSI, a
  plugin monitor interface, GNOME user lock settings, telemetry control,
  OSV lookup.
- **F6, per-app enforcement and Ask mode** (`docs/reports/F6-report.md`,
  `docs/plans/F6-app-enforcement.md`). Block over TCP, UDP, QUIC and
  IPv6 for the target only, Ask held until answered, fail open;
  `--phase f6` green on five distros.
- **F5, inbound firewall, accepted 2026-11-04** (`docs/reports/F5-report.md`,
  `docs/archive/plans/F5-inbound-firewall.md`). firewalld, ufw and pure
  nftables adapters, Docker coexistence, byte-exact rollback. Open:
  profiles per connection, rich-rule editing, ufw app profiles.
- **F4, apps and traffic** (accepted; `docs/reports/F4-report.md`).
- **F3, secure DNS** (`docs/reports/F3-report.md`). Own servers, a
  secondary and split DNS, DoH endpoints, browser policies, captive
  portal, counters and latency evidence. Leftovers: DNS backends B2 to
  B4, IPv6 presets, a DNSSEC decision, the TUI DNS view.
- **F2, posture and UI** and **F1, core and CLI** (accepted).

## What exists

- Cargo workspace with the 13 crates plus xtask and the plugin set
  (net, system, endpoint, apps, device, privacy and vuln categories);
  workspace-wide `forbid(unsafe_code)` outside the designated eBPF and
  nfqueue crates, edition 2024, MSRV 1.96, toolchain pinned to 1.98.1.
- `ibexwall-proto` with the full contract surface, typed `Op` set,
  plugin manifest and policy bundle validation, canonical names,
  deterministic schema export; `spec/` holds 49 generated files and
  `cargo xtask schemas --check` enforces zero drift.
- 705 Rust tests, 119 UI tests; clippy and fmt clean;
  cargo-deny clean (pinned to 0.20.2 in CI; newer versions reject the
  config's version fields).
- VM harness: `cargo xtask vm-test --distro fedora|ubuntu-24.04|
  ubuntu-26.04|debian|arch --phase f0..f11a`, cloud-init NoCloud seed,
  checksum-verified image cache.
- GitHub CI: fmt, clippy, nextest with cargo-deny, rustdoc, coverage,
  the UI checks, DCO plus Conventional Commits, Scorecard, the release
  workflow; actions pinned by SHA, zero default permissions. The GTK and
  WebKit system libraries are installed in every job that builds the
  workspace. No VM jobs (no nested KVM on hosted runners); the VM matrix
  stays the local verification path.
- Packaging: RPM, DEB and Arch packages, `ibexwall-apparmor` and
  `ibexwall-selinux`, tmpfiles and sysusers, polkit rules, the release
  checklist. `cargo xtask release`, `verify-release`, `repro` and
  `releasekey`.
- The app, agent, tray, catalog and manifests in en, pt-BR, es, fr and
  de (`docs/translating.md`, `scripts/check-locales.mjs`).
- The site (ibexwall.com), the docs (docs.ibexwall.com), the plugin
  index and the compliance profiles (github.com/nubian-ibex/
  ibexwall-profiles), public, deployed on Cloudflare Pages;
  `security@ibexwall.com` through Email Routing.

## Deviations and notes

- Fedora cloud image and checksum names are discovered from the
  directory listing (names vary per respin); mirrors:
  dl.fedoraproject.org then mirrors.kernel.org. First run downloads
  ~557 MB.
- Host tools installed for VM testing (user-approved): `qemu-img`,
  `genisoimage`. Nothing else touches the dev host.
- `deny.toml` ignores RUSTSEC-2024-0370 (unmaintained, inherited from
  the GTK stack) and cargo-audit reports RUSTSEC-2024-0429 (glib
  unsound, no known exploit); both are tracked for removal.
- `fuzz/` and `profiles/` hold READMEs only; the fuzz README promises
  targets and a nightly job that do not exist yet, and the usage
  profiles live in code (both noted in the F10c plan).

## Pending / next

0. Release `v0.1.0` is published (deb, rpm and Arch packages, tarball,
   eBPF object, SBOM, provenance). Installed from the release on Fedora
   45 and Ubuntu 26.10 (KDE): daemon, 32 plugins, no SELinux or AppArmor
   denials, `audit verify` valid. The install test found and fixed a
   fresh-install bug (audit verify reported a broken chain). Open: the
   rpm carries the builder's dist tag (`fc45`); the packages are not in
   `SHA256SUMS` (attested instead); the resolver log line "answers
   channel unavailable: Permission denied" is not investigated.
0b. Blocking for v0.1.1 (found installing v0.1.0 as a desktop user):
   nothing can be changed from the app. The daemon asks polkit with no
   interactive flag, so actions that need `auth_admin_keep` (apply,
   rollback, plugins.manage) are denied and no password prompt appears.
   ADR-0045 and `docs/plans/v0.1.1-desktop-fixes.md` cover it. Also: the sidebar
   scrolls with the page and its "protection active" footer is a fixed
   string; Organisation shows in the main menu without managed mode; no
   first-run onboarding for dependencies and permissions; the VM matrix
   runs as root and cannot catch any of this.
   The resolver answers socket never opens in a packaged install:
   `/run/ibexwall/dns` is `ibexwall-dns` 0750 and ibexwalld has no
   CAP_DAC_OVERRIDE, so the monitor gets no DNS answers.
1. The maintainer's call on `docs/plans/F10c-audit-fixes.md`, then its
   M1 (P0) and M2 (transaction engine) before any v1.0 tag; M3 and M4
   (the rest of the audit, fuzz decision) after.
2. External, with the maintainer: the official release key
   (`packaging/release.pub` plus the `RELEASE_SIGNING_KEY` secret),
   COPR/PPA/OBS/AUR accounts to publish the packages, the from-source
   package builds on a builder with `bpf-linker`, and the manual runs on
   EndeavourOS and with real assistant clients. Omarchy (Arch) is
   validated: the Arch package built from the staged tree via makepkg,
   installed, and the checks ran against the real system. The run found
   and fixed a real bug: the manifest `default_enabled` flag was never
   honored, so a fresh install enabled no plugins and the first run
   measured nothing.
3. Translations: the docs guides are English so far (the generated
   reference, including plugins, is in all five); on the site, articles
   are complete in en and es and partial in pt-BR, fr and de with an
   English fallback that says so.
4. Cloudflare Pages git integration for preview deploys (production
   deploys are manual `wrangler pages deploy`).
5. CI VM jobs on a KVM-capable runner.
6. `ibexwall-proto` and `ibexwall-sdk` on crates.io when the contracts
   stabilize.

History of F0 to F3: `docs/archive/STATUS-history-F0-F3.md`.
