// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `.desktop` entry parsing and the application inventory. The agent runs
//! in the user session and reads the user's own files; the core never
//! reads homes (ProtectHome=yes). Entries are untrusted input: values are
//! never executed, only listed, and never grow into markup.

/// One application in the inventory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DesktopEntry {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub icon: String,
    /// The exec line is kept for display/identification only.
    #[serde(default)]
    pub exec: String,
    #[serde(default)]
    pub flatpak: bool,
}

/// Parses the entries of a `.desktop` file. Untrusted input: unknown keys
/// are ignored, values are trimmed, nothing is executed.
pub fn parse_desktop_file(id: &str, text: &str) -> Option<DesktopEntry> {
    let mut in_main_section = false;
    let mut name = String::new();
    let mut icon = String::new();
    let mut exec = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_main_section = line == "[Desktop Entry]";
            continue;
        }
        if !in_main_section {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "Name" => name = unquote_localized(value).to_string(),
                "Icon" => icon = value.to_string(),
                "Exec" => exec = value.to_string(),
                "Type" if value != "Application" => return None,
                "NoDisplay" if value.eq_ignore_ascii_case("true") => return None,
                _ => {}
            }
        }
    }
    if exec.is_empty() {
        return None;
    }
    Some(DesktopEntry {
        // The id is the file name without `.desktop`; flatpak ids contain
        // a dot already, which is fine (they are their own namespace).
        id: id.strip_suffix(".desktop").unwrap_or(id).to_string(),
        name,
        icon,
        flatpak: exec.contains("flatpak run") || id.contains(':'),
        exec,
    })
}

/// `Name[pt_BR]=x` localization keys never reach this parser: we take the
/// plain `Name`. Locale-qualified duplicates look like `Name[pt_BR]` which
/// the key match above already skips.
fn unquote_localized(value: &str) -> &str {
    value
}

/// Scans `dirs` (absolute) for `applications/*.desktop` and returns the
/// inventory, newest id first is not needed; sorted by id for stability.
pub fn scan(dirs: &[std::path::PathBuf]) -> Vec<DesktopEntry> {
    let mut entries = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for dir in dirs {
        let applications = dir.join("applications");
        let Ok(files) = std::fs::read_dir(&applications) else {
            continue;
        };
        for file in files.flatten() {
            let file_name = file.file_name().to_string_lossy().into_owned();
            if !file_name.ends_with(".desktop") || seen.contains(&file_name) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(file.path())
                && let Some(entry) = parse_desktop_file(&file_name, &text)
            {
                seen.insert(file_name);
                entries.push(entry);
            }
        }
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const FILE: &str = "\
[Desktop Entry]
Type=Application
Name=Firefox
Name[pt_BR]=Firefox
Icon=firefox
Exec=firefox %u
Terminal=false
";

    #[test]
    fn parses_the_basics_and_skips_localized_duplicates() {
        let entry = parse_desktop_file("firefox.desktop", FILE).unwrap();
        assert_eq!(entry.name, "Firefox");
        assert_eq!(entry.icon, "firefox");
        assert_eq!(entry.exec, "firefox %u");
        assert!(!entry.flatpak);
        assert_eq!(entry.id, "firefox");
    }

    #[test]
    fn non_applications_and_hidden_entries_are_skipped() {
        assert!(
            parse_desktop_file("x.desktop", "[Desktop Entry]\nType=Link\nName=x\nExec=y\n")
                .is_none()
        );
        assert!(
            parse_desktop_file(
                "x.desktop",
                "[Desktop Entry]\nType=Application\nNoDisplay=true\nExec=y\n"
            )
            .is_none()
        );
        assert!(parse_desktop_file("x.desktop", "[Other]\nExec=y\n").is_none());
    }

    #[test]
    fn hostile_values_never_leave_as_anything_but_text() {
        // A crafted name is data: it parses, and stays a plain string.
        let entry = parse_desktop_file(
            "evil.desktop",
            "[Desktop Entry]\nName=<img onerror=1>\nExec=/bin/evil\n",
        )
        .unwrap();
        assert_eq!(entry.name, "<img onerror=1>");
        assert_eq!(entry.exec, "/bin/evil");
    }

    #[test]
    fn scan_deduplicates_and_sorts() {
        let root = std::env::temp_dir().join(format!("ibx-agent-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (sub, name) in [("a", "b.desktop"), ("b", "a.desktop"), ("b", "b.desktop")] {
            let dir = root.join(sub).join("applications");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(name), FILE).unwrap();
        }
        let entries = scan(&[root.join("a"), root.join("b")]);
        assert_eq!(
            entries.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    proptest! {
        #[test]
        fn parsing_never_panics_on_arbitrary_input(text in ".{0,600}") {
            let _ = parse_desktop_file("x.desktop", &text);
        }
    }
}
