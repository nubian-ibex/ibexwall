// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask plugin-units [--out DIR]`: writes the socket and service
//! unit of every plugin, generated from its `plugin.toml`. Packaging and the
//! VM harness both use it, so the sandbox a plugin runs in is the one its
//! manifest asks for.

use std::path::Path;

use anyhow::{Context, Result};
use ibexwall_core::plugins::{PluginUnits, generate_units};
use ibexwall_proto::Manifest;

/// Units for every `plugins/*/plugin.toml`, as `(plugin id, units)`.
pub fn all(root: &Path) -> Result<Vec<(String, PluginUnits)>> {
    let mut out = Vec::new();
    let mut dirs: Vec<_> = std::fs::read_dir(root.join("plugins"))?
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    for dir in dirs {
        let manifest = dir.join("plugin.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let parsed: Manifest =
            toml::from_str(&text).with_context(|| format!("parsing {}", manifest.display()))?;
        out.push((parsed.id.clone(), generate_units(&parsed)));
    }
    Ok(out)
}

pub fn run(out: &Path) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    std::fs::create_dir_all(out)?;
    let units = all(&root)?;
    for (_, unit) in &units {
        std::fs::write(out.join(format!("{}.service", unit.name)), &unit.service)?;
        std::fs::write(out.join(format!("{}.socket", unit.name)), &unit.socket)?;
    }
    println!(
        "wrote {} plugin unit pairs to {}",
        units.len(),
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_plugin_gets_units_with_unique_names_and_its_own_socket() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let units = all(&root).unwrap();
        assert!(units.len() >= 27);
        let mut names: Vec<_> = units.iter().map(|(_, u)| u.name.clone()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), units.len(), "two plugins share a unit name");
        for (id, u) in &units {
            assert!(
                u.socket
                    .contains(&format!("/run/ibexwall/plugins/{id}.sock"))
            );
            assert!(u.service.contains("NoNewPrivileges=yes"));
            assert!(u.service.contains(&format!("{}.socket", u.name)));
        }
    }
}
