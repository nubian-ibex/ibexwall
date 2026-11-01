<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# STATUS

Last updated: 2026-11-01 (F0 complete, awaiting review)

## Current phase

**F0 — Foundation: done.** Next: F1 (core `ibexwalld` + `ibexctl`
minimal) pending plan approval (`docs/plans/F1-*.md` to be written).

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
