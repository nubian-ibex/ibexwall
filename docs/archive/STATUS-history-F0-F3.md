<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# STATUS history, F0 to F3

Moved out of `docs/STATUS.md` on 2026-11-04 when the phases it describes were
accepted. Kept as the record of how F1 to F3 were built; the current state is
in `docs/STATUS.md` and the reports in `docs/reports/`.

## Verified (2026-11-01)

- `cargo fmt --all --check` clean
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- `cargo nextest run --workspace`: 35/35 passed
- `cargo deny check`: advisories, bans, licenses, sources ok
- `cargo xtask schemas --check`: spec/ up to date (29 files)
- `cargo xtask vm-test --distro fedora`: PASS (image cached under
  `~/.cache/ibexwall/vm/`)
- `scripts/ci/check-commits.sh "" HEAD`: all commits DCO + Conventional

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
- the transient-unit executor written after a VM spike; status
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
- Omarchy and EndeavourOS manual runs on the user's hosts.
- Adapter ops stay validate-only until F3-F5.
- Fedora VM first provision needs network (also true for every distro
  now: polkit and python3 are installed from the distro mirror).

## F2 progress (2026-11-01)

Done and verified (workspace 157 tests, clippy/fmt/deny clean, pushed):
- M1 SDK + check results contract + real score (permissive
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
- M9 executor: ibexwall-exec in a transient unit; daemon unit
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
- `ibexwall-dns` forwarding stub (hickory 0.26): block policy,
  encrypted upstreams (DoT, DoH, DoQ, DoH3 probed against Cloudflare and
  Quad9), counters without query logs, 5 s upstream cap, `--failsafe`.
- Block lists: parser for hosts, domain and adblock formats, counts match
  the declared sizes of HaGeZi, OISD and StevenBlack; https-only download
  with a 64 MiB cap, atomic replace, jitter, a bad download never replaces
  a good list.
- `net.dns` plugin for systemd-resolved, Quad9 and Cloudflare
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
  the relief steps (never auto-relieved).

Next (see `docs/archive/plans/F3-secure-dns.md`): the TUI DNS view (M7), M4 adapters B2 to B4; M6 captive portal and
`block` mode; M7 DNS screen; more provider presets after their docs are
read (Mullvad, AdGuard, DNS4EU, NextDNS/Control D).
