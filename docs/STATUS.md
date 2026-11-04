<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# STATUS

Last updated: 2026-11-04 (F9 delivered, report ready for acceptance)

## Current phase

**F3: secure DNS, delivered (report: `docs/reports/F3-report.md`, awaiting
maintainer acceptance).** 13 VM scenarios green on five distros. F0 to F2
accepted (F2 report: `docs/reports/F2-report.md`); the F3 core (resolver,
lists, resolved backend, enforcement, DNS screen) is accepted and the
remainder (DoH endpoints, browser policies, captive portal, counters,
latency evidence) is being finished. Plan: `docs/plans/F3-secure-dns.md`.
Run the app with `scripts/dev-sandbox.sh` (sandboxed daemon, host
untouched). Manual runs on Omarchy and EndeavourOS are deferred by the
maintainer. **F4 accepted. F5: inbound firewall, delivered** (report:
`docs/reports/F5-report.md`, awaiting acceptance): `--phase f5` green on
five distros (firewalld, ufw and the pure-nftables adapter; Docker
coexistence; byte-exact rollback; foreign tables untouched). Plan:
`docs/plans/F5-inbound-firewall.md`; ADRs 0031 to 0034. Open: profiles per
connection (NetworkManager zones), rich-rule editing, ufw app profiles.

**F6: per-app enforcement and Ask mode, delivered** (report:
`docs/reports/F6-report.md`, awaiting acceptance; plan:
`docs/plans/F6-app-enforcement.md`; ADRs 0035 to 0037). `--phase f6` green
on five distros (8 scenarios): block over TCP, UDP, QUIC and IPv6 for the
target only, Ask held until answered with scopes and a 30 s fallback, fail
open when the unit or the daemon stops, Docker and Podman coexistence, 5000
connections a second all recorded. ADR-0036 (Ask chains are derived state),
ADR-0037 (no nft fallback without eBPF) and the plugin-id naming (ADR-0038,
hyphens) were decided on 2026-11-04.

**F7: hardening and system plugins, delivered** (report:
`docs/reports/F7-report.md`, awaiting acceptance; plan:
`docs/plans/F7-hardening-and-system.md`; ADR-0038). Sixteen plugins
(sysctl, coredump, mounts, ssh, accounts, updates, firmware, audit,
session-lock, usb, wifi, nts, camera-mic, telemetry, flatpak-perms, cves);
`--phase f7` green on five distros (15 scenarios), including chrony
authenticating Cloudflare, Netnod, PTB and NTP.br. Open: pending firmware
and HSI, a plugin monitor interface (camera and microphone events), GNOME
user lock settings through the agent, telemetry control, OSV lookup, a unit
of their own for each plugin (F10).

**F8: AI assistant (MCP) and the proposal queue, delivered** (report:
`docs/reports/F8-report.md`, awaiting acceptance; plan:
`docs/plans/F8-assistant-mcp.md`; ADR-0039). `ibexwall-mcp` (stdio, no
root, nine tools, no way to apply, approve or revert), the core's proposal
queue (irreversible plans refused, approval re-plans and compares),
`ListAudit`, `ibexctl proposals` and `ibexctl mcp config`, the Assistant
screen. Every call is logged before it runs in a hash-chained file;
`--phase f8` green on five distros (4 scenarios) with a scripted client
(no language model), and an injection corpus in the suite. Open: manual
runs with Claude Code, OpenCode and VS Code, a packaged polkit rule for the
user that runs an assistant (F10), Streamable HTTP and OAuth (off by spec).

**F9: VPN and endpoint, delivered** (report: `docs/reports/F9-report.md`,
awaiting acceptance; plan: `docs/plans/F9-vpn-and-endpoint.md`; ADR-0040
proposed). `endpoint.isolate`, `net.vpn` (WireGuard through NetworkManager and
a kill switch), `endpoint.persistence`, `endpoint.integrity`, `endpoint.av`;
engine groundwork (address and interface matches in nft rules, private-file
previews, symmetric execs). `--phase f9` green on five distros, including a
`tcpdump` proof that a dropped tunnel leaks nothing under the kill switch and
the EICAR file flagged by ClamAV and YARA. The F8 polkit rule and group for
assistants (`ibexwall-assistants`) was accepted and shipped. Open: OpenVPN
import (ADR-0040), scan folders discovery and a file watcher (need plugin
units, F10), manual runs with real assistant clients.

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

## Verified (2026-11-01)

- `cargo fmt --all --check` clean
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo nextest run --workspace`: 35/35 passed
- `cargo deny check`: advisories, bans, licenses, sources ok
- `cargo xtask schemas --check`: spec/ up to date (29 files)
- `cargo xtask vm-test --distro fedora`: PASS (image cached under
  `~/.cache/ibexwall/vm/`)
- `scripts/ci/check-commits.sh "" HEAD`: all commits DCO + Conventional

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

- F1 plan (`docs/plans/F1-core-cli.md`): varlink framing decision
  (zlink spike), polkit pidfd subject verification, change engine,
  SQLite + audit chain, plugin supervisor, `dev.echo` plugin,
  transient-unit executor spike. Threat model review point applies.
- CI VM jobs on a KVM-capable runner (spike S0-b, F1).
- P-01 domains (affects `com.ibexwall` prefix, ADR-0021).
- `ibexwall-proto`/`ibexwall-sdk` publication to crates.io when
  contracts stabilize.

## F1 (core + CLI)

Done: varlink framing crate, ibexwall-sys traits, daemon (config layers,
SQLite, audit chain, change engine, supervisor, events), ibexctl,
dev.echo, xtask devkey and `vm-test --phase f1`.

Verified: 81 workspace tests; clippy, fmt, deny, schema drift clean;
`cargo xtask vm-test --phase f1` PASS (8 scenarios on Fedora 44).

Pending items closed (2026-11-01):
- Daemon now runs under its systemd socket and unit in the VM suite
  (`systemd-analyze security` 2.7); packaging/ holds the units, polkit
  policy (all ten actions, test-checked).
- ADR-0026 (transient-unit executor) written after a VM spike; status
  Proposed, needs a maintainer decision.
- Coverage measured: core 90.5%, engine+ops 95.7%, proto 89.8%, sys 80.8%,
  varlink at the target after added tests (see docs/testing.md).
- F1 suite passes on Fedora 44, Ubuntu 24.04, Ubuntu 26.04, Debian 13, Arch.

Findings worth remembering:
- systemd `RestrictSUIDSGID=` makes `openat2` return ENOSYS, so
  `write_atomic` walks the path with `O_NOFOLLOW`.
- ibexwalld built on Fedora 44 needs glibc 2.39 (the Ubuntu 24.04 floor);
  per-distro packages (F10) remove this coupling.
- Rollback bugs fixed: previously inactive or masked units were left active.

Still open:
- Decision on ADR-0026.
- Omarchy and EndeavourOS manual runs on the user's hosts.
- Adapter ops stay validate-only until F3-F5.
- Fedora VM first provision needs network (also true for every distro
  now: polkit and python3 are installed from the distro mirror).

## F2 progress (2026-11-01)

Done and verified (workspace 157 tests, clippy/fmt/deny clean, pushed):
- M1 SDK + check results contract + real score (ADR-0027 permissive
  varlink crate; core stores results, computes the spec formula).
- M2 system.ports; M3 system.posture (14 checks) with real fixtures from
  five distros collected by `xtask vm-test --phase fixtures`; two check
  bugs found and fixed by those fixtures (suid_dumpable=2 is safe;
  ufw.service runs even when ufw is disabled).
- M4/M5 UI (Svelte 5): tokens, Fluent en/pt-BR, generated TS contracts,
  fixture transport, Overview, Posture (formula disclosed), Plugins
  (permissions, simulate/apply/confirm/undo), History; StateMessage for
  loading/empty/error/denied.
- M6 (part): Playwright e2e with axe (12 tests, 2 themes x 2 locales,
  keyboard, skip link) against the built app.
- M7 TUI behind `ibexctl tui` (ratatui 0.30; bumped to drop the
  unmaintained `paste` crate, RUSTSEC-2024-0436).
- M8 session agent (user unit, notifications for high/critical, .desktop
  inventory with proptest-hardened parser).

- M6 Tauri shell (com.ibexwall.IbexWall, strict CSP, core:default only,
  no updater); RUSTSEC-2024-0370 ignored in deny.toml (GTK stack).
- M9 ADR-0026 executor: ibexwall-exec in a transient unit; daemon unit
  no longer writes /etc; VM scenario s8 proves out-of-dir writes fail.
- M10 VM phase f2 (posture/ports through the daemon, UI contract) and
  F1 suite (9/9) pass on fedora, ubuntu-24.04, ubuntu-26.04, debian, arch.
  Threat model section 11 and capabilities matrix updated.

Pending for the user: manual runs on Omarchy/EndeavourOS, visual review
against mockups, running the Tauri app on a real desktop session, F2
acceptance, then F3 planning.

Notes:
- Local lesson: pipe-to-tail masks exit codes; the CI workflow runs the
  checks directly, so it does not have this problem.
- `cargo deny` flags nothing; coverage numbers from F1 still hold for the
  core (the new UI/TUI/agent are not in the 80% core target).

## F3 progress (2026-11-02)

Done and verified (workspace 202 tests, clippy/fmt/deny clean, pushed):
- `ibexwall-dns` forwarding stub (hickory 0.26, ADR-0028): block policy,
  encrypted upstreams (DoT, DoH, DoQ, DoH3 probed against Cloudflare and
  Quad9), counters without query logs, 5 s upstream cap, `--failsafe`.
- Block lists: parser for hosts, domain and adblock formats, counts match
  the declared sizes of HaGeZi, OISD and StevenBlack; https-only download
  with a 64 MiB cap, atomic replace, jitter, a bad download never replaces
  a good list.
- `net.dns` plugin for systemd-resolved (ADR-0029), Quad9 and Cloudflare
  presets with sources and dates, hardened units (exposure 1.4 and 1.1).
- Core: units restarted by a transaction are restarted again after
  rollback; fixed an F1 defect where a disabled unit was snapshotted as
  not found (rollback never disabled it).
- `cargo xtask vm-test --phase f3` (8 scenarios) passes on fedora,
  ubuntu-24.04, ubuntu-26.04, debian, arch; `--phase f1` regression 5/5.

- nft enforcement: typed fragment (loopback, uid, protocol, ports,
  verdict), checked batch, prior chain captured so rollback is exact
  (`nft list ruleset` identical after rollback); the failsafe removes the
  chain first.

- Known DoH endpoints refused through the stub (HaGeZi's list) and browser
  policies with explicit consent, one file per browser from each vendor's
  documentation; Firefox's policies.json is never taken from an admin.
- Counters: the resolver publishes them, `GetDnsStatus` exposes them and
  the DNS screen shows them; no query names are ever recorded.
- AdGuard and DNS4EU presets with vendor-verified facts (Mullvad rejected:
  its public encrypted DNS is discontinued as of 2026-11-02).
- Latency targets measured in VM: warm p99 under 2 ms, uncached overhead
  under 5 ms versus direct DoT from the exempt user.
- Product fixes found by the scenarios: the failsafe now clears resolved's
  start rate limit; `--set` sends typed values; a sandbox root no longer
  breaks manifest path checks.

- Both failure modes (`restore` by default, `block` failing closed) are
  proven in VM (d5, d10); the agent detects captive portals and announces
  the relief steps (ADR-0030, never auto-relieved).

Next (see `docs/plans/F3-secure-dns.md`): the TUI DNS view (M7), M4 adapters B2 to B4; M6 captive portal and
`block` mode; M7 DNS screen; more provider presets after their docs are
read (Mullvad, AdGuard, DNS4EU, NextDNS/Control D).
