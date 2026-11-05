// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! What a plugin found already on the machine, said the same way by every
//! plugin: an information finding `detect.<area>` whose arguments are the
//! facts, optionally with a `patch` that pre-fills the change it suggests.
//! It is never a failure and never changes anything; the person reviews the
//! suggested change like any other.

use std::collections::BTreeMap;

use ibexwall_proto::{Finding, FindingStatus, Severity};
use serde_json::Value;

use crate::Sandbox;

/// One "we found" note. The title is `detect-<area>-title` and the summary
/// `detect-<area>-<case>`, both in the plugin's own locale files.
pub fn detected(
    plugin: &str,
    area: &str,
    case: &str,
    mut args: BTreeMap<String, String>,
    patch: Option<Value>,
    detected_at: &str,
) -> Finding {
    if let Some(patch) = patch {
        args.insert("patch".into(), patch.to_string());
    }
    args.insert("case".into(), case.into());
    Finding {
        id: format!("detect.{area}"),
        plugin: plugin.into(),
        severity: Severity::Info,
        title_key: format!("detect-{area}-title"),
        summary_key: format!("detect-{area}-{case}"),
        args,
        references: vec![],
        remediation: None,
        status: FindingStatus::Open,
        detected_at: detected_at.into(),
    }
}

/// The command that installs `package` with this distribution's own package
/// manager, for the person to run. IbexWall installs nothing itself.
pub fn install_command(sandbox: &Sandbox, package: &str) -> Option<String> {
    if !package
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.'))
    {
        return None;
    }
    let release = sandbox.read("/etc/os-release")?;
    let field = |name: &str| {
        release
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .map(|v| v.trim_matches('"').to_ascii_lowercase())
            .unwrap_or_default()
    };
    let family = format!("{} {}", field("ID"), field("ID_LIKE"));
    let has = |word: &str| family.split_whitespace().any(|w| w == word);
    if has("fedora") || has("rhel") || has("centos") {
        Some(format!("sudo dnf install {package}"))
    } else if has("debian") || has("ubuntu") {
        Some(format!("sudo apt install {package}"))
    } else if has("arch") {
        Some(format!("sudo pacman -S {package}"))
    } else if has("opensuse") || has("suse") {
        Some(format!("sudo zypper install {package}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_release(text: &str) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!(
            "ibx-sdk-detect-{}-{}",
            std::process::id(),
            text.len()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/os-release"), text).unwrap();
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    #[test]
    fn the_install_command_is_the_distros_own_and_never_built_from_odd_input() {
        for (release, want) in [
            ("ID=fedora\n", "sudo dnf install chrony"),
            ("ID=ubuntu\nID_LIKE=debian\n", "sudo apt install chrony"),
            (
                "ID=\"linuxmint\"\nID_LIKE=\"ubuntu debian\"\n",
                "sudo apt install chrony",
            ),
            ("ID=endeavouros\nID_LIKE=arch\n", "sudo pacman -S chrony"),
            (
                "ID=opensuse-tumbleweed\nID_LIKE=\"opensuse suse\"\n",
                "sudo zypper install chrony",
            ),
        ] {
            let (root, sandbox) = with_release(release);
            assert_eq!(
                install_command(&sandbox, "chrony").as_deref(),
                Some(want),
                "{release}"
            );
            std::fs::remove_dir_all(root).unwrap();
        }
        let (root, sandbox) = with_release("ID=plan9\n");
        assert_eq!(install_command(&sandbox, "chrony"), None);
        assert_eq!(install_command(&sandbox, "x; rm -rf /"), None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_note_is_information_with_the_facts_the_case_and_the_patch_as_text() {
        let note = detected(
            "net.dns",
            "dns",
            "resolved-plain",
            BTreeMap::from([("servers".to_string(), "192.168.1.1".to_string())]),
            Some(serde_json::json!({ "provider": "quad9" })),
            "2026-11-05T00:00:00Z",
        );
        assert_eq!(note.id, "detect.dns");
        assert_eq!(note.severity, Severity::Info);
        assert_eq!(note.title_key, "detect-dns-title");
        assert_eq!(note.summary_key, "detect-dns-resolved-plain");
        assert_eq!(note.args["case"], "resolved-plain");
        assert_eq!(note.args["patch"], r#"{"provider":"quad9"}"#);
        assert!(note.remediation.is_none());
    }
}
