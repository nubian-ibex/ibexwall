<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Testing

- Unit and e2e (unprivileged, sandbox root, fake polkit):
  `cargo nextest run --workspace`
- VM acceptance (real systemd, polkit, socket activation):
  `cargo xtask vm-test --phase f1` (Fedora; other distros pending)
- Coverage: `rustup component add llvm-tools-preview`,
  `cargo install cargo-llvm-cov --locked`, then
  `cargo llvm-cov nextest --workspace --summary-only`

Coverage targets (spec): >= 80% in core crates, >= 90% in the change
engine and operation validation. Measured 2026-11-01 (lines, including
inline test code): core crate 90.5% (excluding `main.rs`), engine plus op
validation 95.7%, proto 89.8%, sys 80.8%. Not covered by unit tests: the
real `nft` apply path (needs root; exercised in a VM from F3) and the
daemon `main.rs` entry point (exercised by the VM suite).
