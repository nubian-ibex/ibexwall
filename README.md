<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# IbexWall: Security Center for Linux

[![CI](https://github.com/nubian-ibex/ibexwall/actions/workflows/ci.yml/badge.svg)](https://github.com/nubian-ibex/ibexwall/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/nubian-ibex/ibexwall/badge)](https://securityscorecards.dev/viewer/?uri=github.com/nubian-ibex/ibexwall)
[![REUSE compliant](https://img.shields.io/badge/REUSE-compliant-green.svg)](https://reuse.software/)

IbexWall is an open source security center for the Linux desktop. It brings
the firewall, per-app network control, secure DNS, system posture, updates,
endpoint protection and compliance evidence together in one place: a desktop
app, web UI, CLI, TUI, and an MCP server for AI assistants.

It orchestrates the tools your distro already ships (firewalld/ufw,
systemd-resolved, chrony, fwupd, PackageKit, USBGuard, ClamAV) instead of
replacing them, and it is extensible through sandboxed plugins.

**Status: version 1.0 in preparation.** The daemon, CLI, desktop app, secure
DNS, firewalling, hardening and endpoint plugins, and the AI assistant server
are built and tested in virtual machines on Fedora, Ubuntu 24.04 and 26.04,
Debian and Arch, with packages, an SELinux module and AppArmor profiles,
signed releases, an SBOM and reproducibility (F0 to F10). See
`docs/STATUS.md` for where things stand, `docs/release-checklist.md` for what
v1.0 still needs, and `docs/reports/` for what each phase proved.

## Guarantees

- Nothing changes on your system without an explicit, previewed
  (diff) approval; every change creates a restore point.
- Everything is reversible: automatic rollback on failure, timed
  confirmation for network changes, crash recovery.
- Local-first: zero telemetry, zero phone-home. Your data stays on your
  machine.
- An AI assistant can read and suggest, never apply: every suggestion waits
  for a person, can be undone, and every call it makes is logged.
- Security is not a premium feature: all protections are free and open.

## Architecture (short)

- `ibexwalld` (root, hardened) is the only component that executes changes.
- Plugins run as separate sandboxed processes and **propose** typed
  operations; the core validates them against each plugin's manifest and
  executes with snapshot, diff, confirmation window and rollback.
- IPC is varlink over a unix socket; per-method authorization via polkit.
- Clients (Tauri app, `ibexctl`, TUI, MCP) are thin and share the same
  contracts in `ibexwall-proto` (exported to `spec/`).

See `docs/threat-model.md` and the ADRs in `docs/adr/` for details.

## Development

Requirements: Rust (toolchain pinned in `rust-toolchain.toml`), plus QEMU
tooling for the VM smoke tests.

```sh
cargo build --workspace
cargo nextest run --workspace     # or: cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask schemas --check       # contracts must not drift
cargo xtask vm-test --distro fedora
```

The dev host is never modified: system-level behavior is exercised only
inside QEMU VMs or under `IBEXWALL_ROOT` with fakes. Never run the daemon
against your own machine.

## Contributing

See `CONTRIBUTING.md` (DCO sign-off required, Conventional Commits) and
`docs/plans/` for the current phase. Security reports: `SECURITY.md`.

## License

GPL-3.0-or-later for the client as a whole; `ibexwall-proto` and
`ibexwall-sdk` are Apache-2.0 OR MIT so third-party plugins may link them;
`ibexwall-ebpf` is GPL-2.0-only OR MIT. See `LICENSE` and `LICENSES/`.
