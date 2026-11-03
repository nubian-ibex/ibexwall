// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask ebpf`: builds the eBPF programs for the little-endian
//! BPF target into `target/bpf/`, so nothing else in the workspace needs
//! the nightly toolchain, `rust-src` or `bpf-linker`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

pub fn run() -> Result<()> {
    let workspace = workspace_root();
    let crate_dir = workspace.join("crates/ibexwall-ebpf");
    let target_dir = workspace.join("target/bpf-build");
    let artifact = target_dir.join("bpfel-unknown-none/release/ibexwall-ebpf");
    let out = workspace.join("target/bpf");
    std::fs::create_dir_all(&out)?;

    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
            "--manifest-path",
        ])
        .arg(crate_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .status()
        .context("running rustup; is it installed?")?;
    if !status.success() {
        bail!(
            "building the eBPF programs failed; needs the nightly toolchain \
             (rustup component rust-src) and bpf-linker on PATH"
        );
    }
    let destination = out.join("ibexwall-ebpf.o");
    std::fs::copy(&artifact, &destination).with_context(|| artifact.display().to_string())?;
    println!("wrote {}", destination.display());
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the workspace")
        .to_path_buf()
}
