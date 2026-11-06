// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Every language the app ships is complete: the same folders, the same
//! messages, and a name and description in each plugin manifest. A language
//! is added by listing it in `names::LOCALES` and adding its files; this
//! test then says what is still missing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ibexwall_proto::names::LOCALES;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn ids(path: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .filter(|l| !l.starts_with([' ', '#', '\t']) && l.contains('='))
        .filter_map(|l| l.split('=').next())
        .map(|id| id.trim().to_string())
        .collect()
}

#[test]
fn the_ui_has_a_folder_for_exactly_the_shipped_languages() {
    let mut folders: Vec<String> = std::fs::read_dir(repo().join("ui/locales"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    folders.sort();
    let mut shipped: Vec<String> = LOCALES.iter().map(|s| (*s).to_string()).collect();
    shipped.sort();
    assert_eq!(folders, shipped);
}

#[test]
fn every_language_defines_the_same_ui_messages() {
    let source = ids(&repo().join("ui/locales/en/ui.ftl"));
    for locale in LOCALES {
        let found = ids(&repo().join(format!("ui/locales/{locale}/ui.ftl")));
        let missing: Vec<_> = source.difference(&found).collect();
        let extra: Vec<_> = found.difference(&source).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "{locale}: missing {missing:?}, not in English {extra:?}"
        );
    }
}

#[test]
fn every_plugin_has_its_messages_and_its_names_in_every_language() {
    let plugins = repo().join("plugins");
    let mut checked = 0;
    for entry in std::fs::read_dir(&plugins).unwrap().filter_map(Result::ok) {
        let dir = entry.path();
        let manifest = dir.join("plugin.toml");
        if !manifest.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&manifest).unwrap();
        let value: toml::Table = text.parse().unwrap();
        let id = value["id"].as_str().unwrap().to_string();
        // The development plugin is a test fixture and never ships.
        if value["category"].as_str() == Some("dev") {
            continue;
        }
        for table in ["name", "description"] {
            let map = value[table].as_table().unwrap();
            for locale in LOCALES {
                assert!(
                    map.get(locale)
                        .and_then(toml::Value::as_str)
                        .is_some_and(|s| !s.is_empty()),
                    "{id}: {table} in {locale}"
                );
            }
        }
        let source = dir.join("locales/en.ftl");
        if source.is_file() {
            let wanted = ids(&source);
            for locale in LOCALES {
                let found = ids(&dir.join(format!("locales/{locale}.ftl")));
                let missing: Vec<_> = wanted.difference(&found).collect();
                let extra: Vec<_> = found.difference(&wanted).collect();
                assert!(
                    missing.is_empty() && extra.is_empty(),
                    "{id} {locale}: missing {missing:?}, not in English {extra:?}"
                );
            }
        }
        checked += 1;
    }
    assert!(checked >= 30, "only {checked} plugins were found");
}
