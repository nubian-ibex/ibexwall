// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the access-control policies need from the plugin manifests: the
//! daemon may write the paths and run the commands the manifests declare, so
//! the AppArmor include that says so is generated from them instead of kept
//! by hand. A new plugin path then reaches the profile with the plugin.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use ibexwall_proto::Manifest;

pub fn manifests(root: &Path) -> Result<Vec<Manifest>> {
    let mut dirs: Vec<_> = std::fs::read_dir(root.join("plugins"))?
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(text) = std::fs::read_to_string(dir.join("plugin.toml")) else {
            continue;
        };
        let manifest: Manifest = toml::from_str(&text)
            .with_context(|| format!("parsing {}", dir.join("plugin.toml").display()))?;
        // The development plugin is a test fixture and never ships.
        if manifest.id != "dev.echo" {
            out.push(manifest);
        }
    }
    Ok(out)
}

/// The daemon's rules for the paths it writes and the commands it runs, for
/// `/etc/apparmor.d/ibexwall/plugin-paths`.
pub fn apparmor_plugin_paths(manifests: &[Manifest]) -> String {
    let mut writes = BTreeSet::new();
    let mut commands = BTreeSet::new();
    for manifest in manifests {
        for path in &manifest.privileges.write_paths {
            writes.insert(path.trim_end_matches('/').to_string());
        }
        for exec in &manifest.privileges.exec {
            commands.insert(exec.path.clone());
        }
    }
    let mut out = String::from(
        "# Generated from the plugin manifests by `cargo xtask stage`; do not edit.\n\
         # What the daemon may write, and the commands it may run, for the\n\
         # changes the plugins propose.\n",
    );
    for path in &writes {
        // A manifest names a file or a directory; a directory gets its contents too.
        out.push_str(&format!("  {path} rwkl,\n  {path}/** rwkl,\n"));
    }
    for command in &commands {
        out.push_str(&format!("  {command} ix,\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_include_covers_every_declared_path_and_command_and_only_those() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let manifests = manifests(&root).unwrap();
        assert!(manifests.len() >= 30);
        let text = apparmor_plugin_paths(&manifests);
        assert!(text.contains("/etc/sysctl.d rwkl,"), "{text}");
        assert!(text.contains("/etc/sysctl.d/** rwkl,"));
        assert!(text.contains("/usr/bin/nmcli ix,"));
        // Nothing outside a manifest, and no development plugin path.
        assert!(!text.contains("/etc/ibexwall-tests"));
        assert!(!text.contains(" / rwkl"));
    }
}
