# F0 — Foundation

Goal: create the OSS foundation (repo, contracts, CI, VM harness) with zero
system-changing code. Everything runs unprivileged; VMs are the only place
where anything is installed or exercised against a real system.

Status: approved on 2026-11-01 (assisted mode; stop for review at phase end).

## Preconditions

- [x] Network approved for crates.io, `cargo install` and the Fedora cloud
      image download (user decision, 2026-11-01)
- [x] sudo approved for dev tooling only (`qemu-img`, `genisoimage`);
      system-level changes (nftables, sysctl, units, DNS, eBPF) remain
      forbidden on the dev host, in any case
- [x] GitHub org `nubian-ibex` exists and belongs to the user; `gh` is
      authenticated. Pushes happen only on explicit request
- Extra test resources offered by the user (recorded for later phases):
      other hosts with Omarchy and EndeavourOS, VirtualBox VMs, and
      docker/podman. QEMU/KVM via `xtask vm-test` remains the canonical
      automated path; VirtualBox/docker/podman are manual complementary
      environments (coexistence tests arrive at F5+)

## Tasks (in order)

1. Scaffold monorepo
   - git repo (branch `main`), `.gitignore`, `rust-toolchain.toml` (stable
     pinned), Cargo workspace with all crates from the spec tree
   - per-crate licenses: GPL-3.0-or-later default; `ibexwall-proto` and
     `ibexwall-sdk` Apache-2.0 OR MIT; `ibexwall-ebpf` GPL-2.0-only OR MIT
   - `deny.toml` (license allowlist per spec §9), workspace lints
     (`unsafe_code = forbid`), REUSE.toml + SPDX headers, LICENSES/
2. Community files: README, CONTRIBUTING (DCO + VM test setup), SECURITY.md,
   CODE_OF_CONDUCT.md, repo AGENTS.md, docs/STATUS.md
3. ADRs (MADR): D-001..D-022, numbered 1:1 with the internal decision log;
   short form for organizational decisions, full form (options + tradeoffs)
   for: plugins-propose/core-executes, varlink+polkit/pidfd, change engine,
   own nft table + adapters, licensing/dual-license eBPF, monorepo, single
   Web UI
4. docs/threat-model.md v1: STRIDE per component and trust boundary; failure
   modes; honest limits (SEC-15)
5. ibexwall-proto: types for Core, Plugin (manifest), Policy, Op, Finding,
   Event, Proposal, Report; `names` module with every canonical identifier
   and path (IBEXWALL_ROOT-aware); serde + schemars, deny_unknown_fields,
   round-trip and validation unit tests
6. xtask `schemas`: export JSON Schemas + varlink IDL to `spec/`,
   deterministic output; `--check` mode for drift detection
7. CI base (GitHub Actions, actions pinned by SHA, least permissions):
   fmt, clippy -D warnings, nextest, cargo-deny, schemas drift, DCO +
   Conventional Commits check. No VM jobs at F0 (hosted runners expose no
   nested KVM; revisit with self-hosted/larger runner in F1)
8. xtask `vm-test --distro fedora`: download Fedora cloud image (checksum
   verified), cloud-init seed, QEMU/KVM boot, SSH smoke test that runs a
   workspace binary inside the VM; distro matrix arrives in F1+
9. `.github-org` repo: org profile README, SECURITY.md, code of conduct,
   issue/PR templates
10. Verification (commands + results recorded in the phase report),
    docs/STATUS.md updated

## Deliverables (spec §15 F0)

- `ibexwall/` with git, Cargo workspace, toolchains and per-crate licenses
  (REUSE/SPDX)
- README, CONTRIBUTING (DCO), SECURITY, code of conduct, repo AGENTS.md,
  docs/STATUS.md
- Initial ADRs for D-001..D-022
- docs/threat-model.md v1
- ibexwall-proto with Core/Plugin/Policy/Op/Finding/Event/Proposal/Report
  types, `names`, schema + IDL export
- CI base
- `xtask vm-test` harness booting a Fedora VM and running a smoke test
- `.github-org/` repo

## Acceptance criteria

- [ ] `cargo test --workspace` green (fmt and clippy clean)
- [ ] `cargo xtask schemas` produces zero drift (enforced in CI)
- [ ] Fedora VM boots via `cargo xtask vm-test` and the smoke test passes
- [ ] `cargo deny check` clean

## Spikes

- S0-a (0.5d): direct QEMU + cloud-init boot without libvirt; the result is
  promoted into xtask (not discarded)
- S0-b (optional, F1): CI runner with nested KVM (self-hosted or larger
  runner) for vm-tests in CI

## Risks

- Hosted CI has no KVM: VM tests stay local-only at F0
- Schema export non-determinism would break the CI drift check: use
  canonical/ordered serialization plus a stability test
- 22 ADRs can inflate the phase: short-form MADR for organizational
  decisions
- VM harness depends on host tools (`qemu-img`, `genisoimage`) that are not
  preinstalled here
- proto scope creep: F0 ships types only, no business logic
