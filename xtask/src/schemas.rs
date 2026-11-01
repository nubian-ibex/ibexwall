// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask schemas`: deterministic export of the contract surface to
//! `spec/`. CI runs with `--check` and fails on drift.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::idl;

pub fn run(check: bool) -> Result<()> {
    let spec_dir = workspace_root().join("spec");
    let mut generated: BTreeMap<PathBuf, String> = BTreeMap::new();

    for (name, schema) in ibexwall_proto::export::schemas() {
        let path = spec_dir.join("schemas").join(format!("{name}.schema.json"));
        let mut body = serde_json::to_string_pretty(&schema)
            .with_context(|| format!("serializing schema for {name}"))?;
        body.push('\n');
        generated.insert(path, body);
    }

    for (file, content) in idl::interfaces()? {
        generated.insert(spec_dir.join("idl").join(file), content);
    }

    if check {
        check_drift(&spec_dir, &generated)
    } else {
        write_all(&generated)
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the workspace")
        .to_path_buf()
}

fn write_all(generated: &BTreeMap<PathBuf, String>) -> Result<()> {
    for (path, body) in generated {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(path, body)?;
        println!("wrote {}", path.display());
    }
    println!("{} files written", generated.len());
    Ok(())
}

fn check_drift(spec_dir: &Path, generated: &BTreeMap<PathBuf, String>) -> Result<()> {
    let mut drifted = false;
    for (path, body) in generated {
        match fs::read_to_string(path) {
            Ok(committed) if committed == *body => {}
            _ => {
                eprintln!("drift: {}", path.display());
                drifted = true;
            }
        }
    }
    for sub in ["schemas", "idl"] {
        let dir = spec_dir.join(sub);
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry?.path();
            if !generated.contains_key(&path) {
                eprintln!("stale: {}", path.display());
                drifted = true;
            }
        }
    }
    if drifted {
        bail!("spec/ differs from generated output; run `cargo xtask schemas` and commit");
    }
    println!("spec/ up to date ({} files)", generated.len());
    Ok(())
}
