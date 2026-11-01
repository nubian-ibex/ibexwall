<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# IbexWall — Security Center for Linux

IbexWall is an open source security center for the Linux desktop. It brings
the firewall, per-app network control, secure DNS, system posture, updates,
endpoint protection and compliance evidence together in one place: a desktop
app, web UI, CLI, TUI, and an MCP server for AI assistants.

It orchestrates the tools your distro already ships (firewalld/ufw,
systemd-resolved, chrony, fwupd, PackageKit, USBGuard, ClamAV) instead of
replacing them, and it is extensible through sandboxed plugins.

**Status: pre-alpha.** Foundations are being laid (phase F0). There is
nothing to install or run yet; see `docs/STATUS.md` and `docs/plans/`.

## Guarantees

- Nothing changes on your system without an explicit, previewed
  (diff) approval; every change creates a restore point.
- Everything is reversible: automatic rollback on failure, timed
  confirmation for network changes, crash recovery.
- Local-first: zero telemetry, zero phone-home. Your data stays on your
  machine.
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
