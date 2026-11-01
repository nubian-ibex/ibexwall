<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Contributing to IbexWall

Thanks for helping build a security center for Linux desktops. This project
runs as root on non-technical people's machines, so we hold changes to a
high bar: safety and reversibility come before features and speed.

## Ground rules

1. **Never modify the developer's host.** No `sudo` in scripts, no applying
   nftables/sysctl/DNS/units/eBPF on your own machine. System behavior is
   tested in QEMU VMs (`cargo xtask vm-test`) or with `IBEXWALL_ROOT` plus
   the fake system implementations.
2. **Only own artifacts.** The daemon writes exclusively to `table inet
   ibexwall` and files with `ibexwall` in the name. Never touch files,
   tables or units owned by the distro or other programs.
3. **Plugins propose, the core executes.** New system effects need a typed
   operation, manifest privileges, an inverse and tests, not a shell call.
4. **Fail open.** Features that could lock someone out of networking or DNS
   must default to the restoring/open failure mode, with tests proving it.
5. **Untrusted input stays data.** Domains, SSIDs, process names, log
   lines and AI justifications are never concatenated into instructions,
   HTML or shell strings.

## Setup

- Rust with the pinned toolchain (`rust-toolchain.toml`).
- `cargo install cargo-nextest cargo-deny` (used by CI).
- For VM tests: `qemu-system-x86_64`, `qemu-img`, `genisoimage`, `curl`
  and `/dev/kvm` (Linux).

## Workflow

1. Pick an issue or a task from `docs/plans/`; phase plans list acceptance
   criteria.
2. Small commits on a feature branch, Conventional Commits style
   (`feat:`, `fix:`, `docs:`, `ci:`, ...), subject in the imperative mood.
3. Every commit needs a DCO sign-off: `git commit -s` (or `--amend -s`).
   The trailer must match the commit author.
4. Tests with the change: unit tests for logic; VM or fake-backed tests
   for anything touching the system; chaos tests when touching networking
   or DNS. Run:

   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo nextest run --workspace
   cargo deny check
   cargo xtask schemas --check
   ```

5. Contracts never drift: if you change a type in `ibexwall-proto`, run
   `cargo xtask schemas` and commit the regenerated `spec/` in the same
   commit.
6. Every UI string ships `en` plus `pt-BR` translations in the same commit.
7. New dependencies need a justification in the PR; licenses must match
   `deny.toml` (permissive only; no GPL in dependencies).

## Commit certificate (DCO)

By signing off you certify the contributions are yours (or properly
licensed) and agree they are contributed under the project licenses. We do
not use a CLA.

## Reporting security issues

See `SECURITY.md`. Please do not open public issues for vulnerabilities.
