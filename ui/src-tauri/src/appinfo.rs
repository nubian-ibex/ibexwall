// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The name and icon of an application, from the desktop entries and icon
//! themes on this machine. It runs in the person's session (the daemon
//! never reads a home directory for this), reads files only, and returns
//! the icon as a data URL: an image shown in an `<img>` runs no script,
//! SVG included. Anything it cannot find is left out; the screen falls
//! back to a letter.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// What the screen knows about an app: enough to find its entry.
#[derive(Debug, Deserialize)]
pub struct AppRef {
    pub key: String,
    pub kind: String,
    pub id: String,
    pub exe_path: Option<String>,
}

#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct AppInfo {
    pub key: String,
    pub name: Option<String>,
    /// `data:image/...;base64,...`
    pub icon: Option<String>,
}

/// An icon file larger than this is not worth a data URL.
const MAX_ICON_BYTES: u64 = 512 * 1024;
const MAX_ENTRY_BYTES: u64 = 64 * 1024;
const SIZES: [&str; 8] = [
    "scalable", "512x512", "256x256", "128x128", "64x64", "48x48", "32x32", "24x24",
];

#[derive(Debug, Default, Clone)]
struct Entry {
    name: Option<String>,
    exec: Option<String>,
    icon: Option<String>,
}

/// The `[Desktop Entry]` keys that matter, from the file's text.
fn parse_entry(text: &str, locale: &str) -> Entry {
    let mut entry = Entry::default();
    let mut localized: Option<String> = None;
    let mut inside = false;
    let lang = locale.split(['.', '@']).next().unwrap_or("");
    let short = lang.split('_').next().unwrap_or("");
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == "[Desktop Entry]";
            continue;
        }
        if !inside || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() {
            continue;
        }
        match key {
            "Name" => entry.name = Some(value.to_string()),
            "Exec" => entry.exec = Some(value.to_string()),
            "Icon" => entry.icon = Some(value.to_string()),
            _ => {
                if let Some(wanted) = key
                    .strip_prefix("Name[")
                    .and_then(|rest| rest.strip_suffix(']'))
                    && (wanted == lang || wanted == short)
                    && (localized.is_none() || wanted == lang)
                {
                    localized = Some(value.to_string());
                }
            }
        }
    }
    entry.name = localized.or(entry.name);
    entry
}

/// The program an `Exec` line starts: past `env`, `flatpak run` and
/// wrappers, and without arguments.
fn exec_program(exec: &str) -> Option<String> {
    let mut words = exec
        .split_whitespace()
        .filter(|word| !word.starts_with('%'));
    let mut program = words.next()?.trim_matches('"').to_string();
    if program == "env" || program.ends_with("/env") {
        program = words
            .by_ref()
            .find(|word| !word.contains('='))?
            .trim_matches('"')
            .to_string();
    }
    Some(program)
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Every desktop entry under `dirs`, by file stem (`org.mozilla.firefox`).
fn read_entries(dirs: &[PathBuf], locale: &str) -> HashMap<String, Entry> {
    let mut entries = HashMap::new();
    for dir in dirs {
        let Ok(listing) = std::fs::read_dir(dir) else {
            continue;
        };
        for item in listing.flatten() {
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let small = std::fs::metadata(&path).is_ok_and(|m| m.len() <= MAX_ENTRY_BYTES);
            if !small {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path) {
                // An earlier directory (the person's own) wins.
                entries
                    .entry(stem.to_string())
                    .or_insert_with(|| parse_entry(&text, locale));
            }
        }
    }
    entries
}

fn find_entry<'a>(app: &AppRef, entries: &'a HashMap<String, Entry>) -> Option<&'a Entry> {
    if matches!(app.kind.as_str(), "flatpak" | "desktop_app")
        && let Some(entry) = entries.get(&app.id)
    {
        return Some(entry);
    }
    if app.kind == "snap" {
        // snap.<name>.<app> is exported as <name>_<app>.desktop
        let parts: Vec<&str> = app.id.split('.').collect();
        if let [_, name, program] = parts.as_slice() {
            if let Some(entry) = entries.get(&format!("{name}_{program}")) {
                return Some(entry);
            }
            if let Some(entry) = entries.get(&format!("{name}_{name}")) {
                return Some(entry);
            }
        }
    }
    let exe = app.exe_path.as_deref()?;
    entries.values().find(|entry| {
        entry
            .exec
            .as_deref()
            .and_then(exec_program)
            .is_some_and(|program| program == exe || basename(&program) == basename(exe))
    })
}

fn mime(path: &Path) -> Option<&'static str> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("png") => Some("image/png"),
        Some("svg") => Some("image/svg+xml"),
        _ => None,
    }
}

fn data_url(path: &Path) -> Option<String> {
    let mime = mime(path)?;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_ICON_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    Some(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

/// The icon file for an `Icon=` value: an absolute path, or a name looked
/// up in the icon directories.
fn find_icon(icon: &str, icon_roots: &[PathBuf]) -> Option<String> {
    let given = Path::new(icon);
    if given.is_absolute() {
        return data_url(given);
    }
    if icon.contains('/') || icon.contains("..") {
        return None;
    }
    for root in icon_roots {
        for size in SIZES {
            for extension in ["svg", "png"] {
                let path = root
                    .join("hicolor")
                    .join(size)
                    .join("apps")
                    .join(format!("{icon}.{extension}"));
                if let Some(url) = data_url(&path) {
                    return Some(url);
                }
            }
        }
        for extension in ["svg", "png"] {
            let path = root.join(format!("{icon}.{extension}"));
            if let Some(url) = data_url(&path) {
                return Some(url);
            }
        }
    }
    for pixmaps in ["/usr/share/pixmaps"] {
        for extension in ["svg", "png"] {
            let path = Path::new(pixmaps).join(format!("{icon}.{extension}"));
            if let Some(url) = data_url(&path) {
                return Some(url);
            }
        }
    }
    None
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home() {
        dirs.push(home.join(".local/share/applications"));
        dirs.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    for dir in [
        "/var/lib/flatpak/exports/share/applications",
        "/var/lib/snapd/desktop/applications",
        "/usr/local/share/applications",
        "/usr/share/applications",
    ] {
        dirs.push(PathBuf::from(dir));
    }
    dirs
}

fn icon_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home() {
        dirs.push(home.join(".local/share/icons"));
        dirs.push(home.join(".local/share/flatpak/exports/share/icons"));
    }
    for dir in [
        "/var/lib/flatpak/exports/share/icons",
        "/usr/local/share/icons",
        "/usr/share/icons",
    ] {
        dirs.push(PathBuf::from(dir));
    }
    dirs
}

/// Resolves a list of apps against the given directories.
fn resolve(
    apps: &[AppRef],
    application_dirs: &[PathBuf],
    icon_dirs: &[PathBuf],
    locale: &str,
) -> Vec<AppInfo> {
    let entries = read_entries(application_dirs, locale);
    apps.iter()
        .filter_map(|app| {
            let entry = find_entry(app, &entries)?;
            let info = AppInfo {
                key: app.key.clone(),
                name: entry.name.clone(),
                icon: entry
                    .icon
                    .as_deref()
                    .and_then(|icon| find_icon(icon, icon_dirs)),
            };
            (info.name.is_some() || info.icon.is_some()).then_some(info)
        })
        .collect()
}

/// For the screen: the names and icons that could be found.
pub fn app_info(apps: &[AppRef]) -> Vec<AppInfo> {
    let locale = std::env::var("LC_MESSAGES")
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default();
    resolve(apps, &application_dirs(), &icon_dirs(), &locale)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ibx-appinfo-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn app(key: &str, kind: &str, id: &str, exe: Option<&str>) -> AppRef {
        AppRef {
            key: key.into(),
            kind: kind.into(),
            id: id.into(),
            exe_path: exe.map(str::to_string),
        }
    }

    #[test]
    fn an_entry_gives_its_name_in_the_language_asked() {
        let text = "[Desktop Entry]\nName=Files\nName[pt_BR]=Arquivos\nName[pt]=Ficheiros\nExec=nautilus %U\nIcon=org.gnome.Nautilus\n[Desktop Action new]\nName=Ignored\n";
        assert_eq!(
            parse_entry(text, "pt_BR.UTF-8").name.as_deref(),
            Some("Arquivos")
        );
        assert_eq!(
            parse_entry(text, "pt_PT.UTF-8").name.as_deref(),
            Some("Ficheiros")
        );
        assert_eq!(
            parse_entry(text, "en_US.UTF-8").name.as_deref(),
            Some("Files")
        );
        assert_eq!(
            parse_entry(text, "").icon.as_deref(),
            Some("org.gnome.Nautilus")
        );
    }

    #[test]
    fn the_program_is_found_past_wrappers_and_arguments() {
        assert_eq!(exec_program("firefox %u").as_deref(), Some("firefox"));
        assert_eq!(
            exec_program("env GDK_BACKEND=x11 /usr/bin/code --new-window %F").as_deref(),
            Some("/usr/bin/code")
        );
        assert_eq!(
            exec_program("\"/opt/app/run\" %U").as_deref(),
            Some("/opt/app/run")
        );
        assert_eq!(exec_program("%U"), None);
    }

    #[test]
    fn a_flatpak_a_cli_program_and_a_snap_find_their_entries() {
        let apps_dir = scratch("entries");
        let icons_dir = scratch("icons");
        std::fs::write(
            apps_dir.join("org.telegram.desktop.desktop"),
            "[Desktop Entry]\nName=Telegram\nExec=flatpak run org.telegram.desktop\nIcon=org.telegram.desktop\n",
        )
        .unwrap();
        std::fs::write(
            apps_dir.join("firefox.desktop"),
            "[Desktop Entry]\nName=Firefox\nExec=/usr/lib/firefox/firefox %u\nIcon=firefox\n",
        )
        .unwrap();
        std::fs::write(
            apps_dir.join("spotify_spotify.desktop"),
            "[Desktop Entry]\nName=Spotify\nExec=spotify\nIcon=/nope/spotify.png\n",
        )
        .unwrap();
        let hicolor = icons_dir.join("hicolor/64x64/apps");
        std::fs::create_dir_all(&hicolor).unwrap();
        std::fs::write(hicolor.join("firefox.png"), b"\x89PNG fake").unwrap();

        let found = resolve(
            &[
                app(
                    "flatpak:org.telegram.desktop",
                    "flatpak",
                    "org.telegram.desktop",
                    None,
                ),
                app(
                    "cli:/usr/lib/firefox/firefox",
                    "cli",
                    "firefox",
                    Some("/usr/lib/firefox/firefox"),
                ),
                app("snap:spotify", "snap", "snap.spotify.spotify", None),
                app("cli:/usr/bin/curl", "cli", "curl", Some("/usr/bin/curl")),
            ],
            std::slice::from_ref(&apps_dir),
            std::slice::from_ref(&icons_dir),
            "en_US",
        );
        let by_key: HashMap<&str, &AppInfo> = found.iter().map(|i| (i.key.as_str(), i)).collect();
        assert_eq!(
            by_key["flatpak:org.telegram.desktop"].name.as_deref(),
            Some("Telegram")
        );
        // No icon file for Telegram, but the name is still given.
        assert!(by_key["flatpak:org.telegram.desktop"].icon.is_none());
        let firefox = by_key["cli:/usr/lib/firefox/firefox"];
        assert_eq!(firefox.name.as_deref(), Some("Firefox"));
        assert!(
            firefox
                .icon
                .as_deref()
                .unwrap()
                .starts_with("data:image/png;base64,")
        );
        assert_eq!(by_key["snap:spotify"].name.as_deref(), Some("Spotify"));
        // Nothing is invented for a program with no entry.
        assert!(!by_key.contains_key("cli:/usr/bin/curl"));
        std::fs::remove_dir_all(apps_dir).unwrap();
        std::fs::remove_dir_all(icons_dir).unwrap();
    }

    #[test]
    fn an_icon_name_cannot_walk_out_of_the_icon_directories() {
        let icons_dir = scratch("walk");
        std::fs::write(icons_dir.join("secret.png"), b"x").unwrap();
        assert!(find_icon("../secret", &[icons_dir.join("hicolor")]).is_none());
        assert!(find_icon("a/b", std::slice::from_ref(&icons_dir)).is_none());
        assert!(find_icon("secret", std::slice::from_ref(&icons_dir)).is_some());
        std::fs::remove_dir_all(icons_dir).unwrap();
    }

    #[test]
    fn a_huge_or_unknown_image_is_not_returned() {
        let dir = scratch("big");
        let big = dir.join("big.png");
        std::fs::write(&big, vec![0u8; (MAX_ICON_BYTES + 1) as usize]).unwrap();
        assert!(data_url(&big).is_none());
        let exotic = dir.join("icon.xpm");
        std::fs::write(&exotic, b"x").unwrap();
        assert!(data_url(&exotic).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
