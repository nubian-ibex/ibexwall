// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-exec`: executes one transaction's operations (or the
//! inverses of its snapshot) inside a transient systemd unit whose
//! `ReadWritePaths` are limited to that transaction (ADR-0026). The core
//! launches it via `systemd-run --wait`; the exit status is the verdict.
//!
//! It reads ops/manifests the core wrote under /run/ibexwall and
//! /var/lib/ibexwall (reads are allowed under ProtectSystem=strict) and
//! never decides anything: validation, snapshotting and auditing all
//! happened in the core before this process started.

use std::path::Path;

use anyhow::{Context, Result};
use ibexwall_proto::Op;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verdict = run(&args);
    if let Err(err) = verdict {
        eprintln!("ibexwall-exec: {err:#}");
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> Result<()> {
    let mode = args
        .first()
        .context("usage: ibexwall-exec apply <ops.json> | rollback <snapshot-dir>")?;
    match mode.as_str() {
        "apply" => {
            let ops_file = args.get(1).context("apply needs an ops file")?;
            let ops: Vec<Op> = serde_json::from_str(&std::fs::read_to_string(ops_file)?)?;
            let sys = ibexwall_sys::SysBundle::real();
            for op in &ops {
                ibexwall_sys::execute(op, &sys)
                    .with_context(|| "executing in transient unit".to_string())?;
            }
            Ok(())
        }
        "rollback" => {
            let snapshot_dir = args.get(1).context("rollback needs a snapshot dir")?;
            let manifest: ibexwall_sys::SnapshotManifest = serde_json::from_str(
                &std::fs::read_to_string(Path::new(snapshot_dir).join("manifest.json"))?,
            )?;
            let sys = ibexwall_sys::SysBundle::real();
            let root = Path::new(snapshot_dir)
                .parent()
                .context("snapshot dir has no parent")?;
            ibexwall_sys::apply_snapshot_inverses(&sys, root, &manifest)
        }
        other => Err(anyhow::anyhow!("unknown mode `{other}`")),
    }
}
