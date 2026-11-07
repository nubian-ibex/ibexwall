// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Loading compliance profiles (F11a): the shipped profiles and the
//! operator's overrides, parsed from YAML. A profile is data, trusted the
//! way configuration is; signature verification is a release concern.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};
use ibexwall_proto::{ComplianceProfile, names};

/// Every profile the operator's directory and the shipped directory
/// provide, the operator's file shadowing the shipped one by name.
pub fn discover(root: &Path) -> Result<Vec<ComplianceProfile>> {
    let mut profiles = Vec::new();
    let mut seen = BTreeSet::new();
    for dir in [
        names::path_under(root, names::PROFILE_CONFIG_DIR),
        names::path_under(root, names::PROFILE_INSTALL_DIR),
    ] {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if seen.contains(&name) {
                continue;
            }
            match parse(&path) {
                Ok(profile) => {
                    seen.insert(name);
                    profiles.push(profile);
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping a broken compliance profile");
                }
            }
        }
    }
    profiles.sort_by(|a, b| a.framework.cmp(&b.framework));
    Ok(profiles)
}

/// One profile file, parsed strictly.
fn parse(path: &Path) -> Result<ComplianceProfile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_file_parses() {
        let yaml = "framework: X\nversion: \"1\"\ncontrols:\n  - control_id: x.c\n    title: t\n    kind: automated\n    checks: [a.b]\n    references:\n      - id: \"art. 1\"\n        url: \"https://example.com/x\"\n        date: \"2026-11-06\"\n";
        let profile: ComplianceProfile = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(profile.framework, "X");
        assert_eq!(profile.controls.len(), 1);
        assert_eq!(profile.controls[0].references[0].date, "2026-11-06");
    }
}
