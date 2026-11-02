<!-- SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors -->
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Testing

- Unit and e2e (unprivileged, sandbox root, fake polkit):
  `cargo nextest run --workspace`
- VM acceptance (real systemd, polkit, socket activation):
  `cargo xtask vm-test --distro <id> --phase f1` with id one of
  `fedora`, `ubuntu-24.04`, `ubuntu-26.04`, `debian` (13), `arch`.
  Images are the official cloud images, checksum-verified, cached under
  `~/.cache/ibexwall/vm/`. All five pass the F1 suite (2026-11-01).
  Omarchy and EndeavourOS follow Arch and are tested by hand on real
  hosts, not in the harness (no cloud images).
- Coverage: `rustup component add llvm-tools-preview`,
  `cargo install cargo-llvm-cov --locked`, then
  `cargo llvm-cov nextest --workspace --summary-only`

Coverage targets (spec): >= 80% in core crates, >= 90% in the change
engine and operation validation. Measured 2026-11-01 (lines, including
inline test code): core crate 90.5% (excluding `main.rs`), engine plus op
validation 95.7%, proto 89.8%, sys 80.8%. Not covered by unit tests: the
real `nft` apply path (needs root; exercised in a VM from F3) and the
daemon `main.rs` entry point (exercised by the VM suite).
