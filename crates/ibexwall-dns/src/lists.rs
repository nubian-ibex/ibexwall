// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Block list presets, the on-disk store and the update step.
//!
//! An update never degrades protection: the download is size-capped and
//! parsed first, and only a valid, non-empty list replaces the file, by an
//! atomic rename. Starting the resolver needs no network: it loads what the
//! store already has.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::blocklist::{self, MAX_LIST_BYTES, ParseError, Parsed};

/// A list the user can pick without typing a URL. Facts below come from
/// each project's own documentation, consulted 2026-11-02.
#[derive(Debug, Clone, Copy)]
pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    /// License of the list data (users download it; IbexWall does not ship
    /// it).
    pub license: &'static str,
}

/// Preset lists. HaGeZi names its tiers by cleaning tool: "multi" is the
/// Normal tier.
pub const PRESETS: &[Preset] = &[
    Preset {
        id: "hagezi-light",
        name: "HaGeZi Light",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
        license: "GPL-3.0",
    },
    Preset {
        id: "hagezi-normal",
        name: "HaGeZi Normal",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
        license: "GPL-3.0",
    },
    Preset {
        id: "hagezi-pro",
        name: "HaGeZi Pro",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
        license: "GPL-3.0",
    },
    Preset {
        id: "hagezi-pro-plus",
        name: "HaGeZi Pro++",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        license: "GPL-3.0",
    },
    Preset {
        id: "hagezi-ultimate",
        name: "HaGeZi Ultimate",
        url: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        license: "GPL-3.0",
    },
    Preset {
        id: "oisd-small",
        name: "OISD small",
        url: "https://small.oisd.nl/domainswild2",
        license: "see https://github.com/sjhgvr/oisd/blob/main/LICENSE",
    },
    Preset {
        id: "oisd-big",
        name: "OISD big",
        url: "https://big.oisd.nl/domainswild2",
        license: "see https://github.com/sjhgvr/oisd/blob/main/LICENSE",
    },
    Preset {
        id: "stevenblack",
        name: "StevenBlack unified hosts",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        license: "MIT",
    },
];

pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.id == id)
}

/// A list entry in the settings: a preset by id, or a custom HTTPS URL
/// under a user-chosen id.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRef {
    pub id: String,
    /// Required for custom lists; ignored for presets.
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("list id `{0}` must be 1 to 64 characters of a-z, 0-9, `.`, `_` or `-`")]
    BadId(String),
    #[error("list `{0}` is not a preset and has no url")]
    UnknownList(String),
    #[error("list urls must use https: `{0}`")]
    NotHttps(String),
    #[error("download failed: {0}")]
    Fetch(String),
    #[error("downloaded list rejected: {0}")]
    Parse(#[from] ParseError),
    #[error("store error: {0}")]
    Io(#[from] std::io::Error),
}

/// Ids become file names, so they are restricted to a safe alphabet.
pub fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !id.starts_with('.')
}

impl ListRef {
    /// Resolves the URL to download, validating id and scheme.
    pub fn resolve(&self) -> Result<String, ListError> {
        if !valid_id(&self.id) {
            return Err(ListError::BadId(self.id.clone()));
        }
        let url = match (preset(&self.id), &self.url) {
            (Some(preset), _) => preset.url.to_string(),
            (None, Some(url)) => url.clone(),
            (None, None) => return Err(ListError::UnknownList(self.id.clone())),
        };
        if !url.starts_with("https://") {
            return Err(ListError::NotHttps(url));
        }
        Ok(url)
    }
}

/// Where lists are kept (`/var/lib/ibexwall/blocklists`).
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, id: &str) -> Result<PathBuf, ListError> {
        if !valid_id(id) {
            return Err(ListError::BadId(id.to_string()));
        }
        Ok(self.dir.join(format!("{id}.list")))
    }

    /// Loads and parses a stored list; `None` when it was never fetched
    /// or no longer parses (the caller keeps protecting with the rest).
    pub fn load(&self, id: &str) -> Option<Parsed> {
        let bytes = std::fs::read(self.path(id).ok()?).ok()?;
        blocklist::parse(&bytes).ok()
    }

    /// Writes already-validated bytes atomically: temp file in the same
    /// directory, fsync, rename.
    fn write_atomic(&self, id: &str, bytes: &[u8]) -> Result<(), ListError> {
        let target = self.path(id)?;
        std::fs::create_dir_all(&self.dir)?;
        let temporary = self.dir.join(format!(".{id}.{}.tmp", std::process::id()));
        let mut file = std::fs::File::create(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &target).inspect_err(|_| {
            let _ = std::fs::remove_file(&temporary);
        })?;
        Ok(())
    }
}

/// Downloads a URL with a size cap. Implementations must be HTTPS-only.
pub trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, ListError>;
}

/// The real fetcher: HTTPS only, few redirects, bounded time and size.
pub struct HttpsFetcher {
    agent: ureq::Agent,
}

impl Default for HttpsFetcher {
    fn default() -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(3)
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .into();
        Self { agent }
    }
}

impl Fetcher for HttpsFetcher {
    fn fetch(&self, url: &str, max_bytes: usize) -> Result<Vec<u8>, ListError> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| ListError::Fetch(e.to_string()))?;
        response
            .body_mut()
            .with_config()
            .limit(max_bytes as u64)
            .read_to_vec()
            .map_err(|e| ListError::Fetch(e.to_string()))
    }
}

/// Downloads one list and replaces the stored copy only if it parses.
/// Returns the number of block entries now stored.
pub fn update(store: &Store, fetcher: &dyn Fetcher, list: &ListRef) -> Result<usize, ListError> {
    let url = list.resolve()?;
    let bytes = fetcher.fetch(&url, MAX_LIST_BYTES)?;
    let parsed = blocklist::parse(&bytes)?;
    store.write_atomic(&list.id, &bytes)?;
    Ok(parsed.block.len())
}

/// Update delay with jitter so many machines do not hit a list host at the
/// same second: the interval plus up to a tenth of it, derived from `seed`.
pub fn next_delay(interval: Duration, seed: u64) -> Duration {
    let tenth = interval.as_secs() / 10;
    interval + Duration::from_secs(if tenth == 0 { 0 } else { seed % tenth })
}

/// Where a list's directory lives under the state dir.
pub fn default_dir() -> PathBuf {
    ibexwall_proto::names::blocklists_dir()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Fake {
        body: Mutex<Result<Vec<u8>, String>>,
    }

    impl Fake {
        fn ok(text: &str) -> Self {
            Self {
                body: Mutex::new(Ok(text.as_bytes().to_vec())),
            }
        }
    }

    impl Fetcher for Fake {
        fn fetch(&self, _url: &str, _max: usize) -> Result<Vec<u8>, ListError> {
            self.body.lock().unwrap().clone().map_err(ListError::Fetch)
        }
    }

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ibexwall-lists-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn custom(id: &str) -> ListRef {
        ListRef {
            id: id.into(),
            url: Some("https://lists.example/hosts".into()),
        }
    }

    #[test]
    fn presets_are_https_with_unique_safe_ids() {
        let mut seen = std::collections::HashSet::new();
        for preset in PRESETS {
            assert!(preset.url.starts_with("https://"), "{}", preset.id);
            assert!(valid_id(preset.id));
            assert!(seen.insert(preset.id), "duplicate {}", preset.id);
        }
        assert!(
            preset("hagezi-normal")
                .unwrap()
                .url
                .ends_with("/multi-onlydomains.txt")
        );
    }

    #[test]
    fn ids_cannot_escape_the_store() {
        for bad in [
            "",
            "../etc/passwd",
            "a/b",
            ".hidden",
            "UPPER",
            "a b",
            &"x".repeat(65),
        ] {
            assert!(!valid_id(bad), "{bad:?}");
            assert!(matches!(custom(bad).resolve(), Err(ListError::BadId(_))));
        }
    }

    #[test]
    fn only_https_urls_and_known_lists_resolve() {
        let http = ListRef {
            id: "mine".into(),
            url: Some("http://x.example/l".into()),
        };
        assert!(matches!(http.resolve(), Err(ListError::NotHttps(_))));
        let none = ListRef {
            id: "mine".into(),
            url: None,
        };
        assert!(matches!(none.resolve(), Err(ListError::UnknownList(_))));
        let preset = ListRef {
            id: "oisd-small".into(),
            url: Some("http://evil.example".into()),
        };
        assert_eq!(
            preset.resolve().unwrap(),
            "https://small.oisd.nl/domainswild2"
        );
    }

    #[test]
    fn a_valid_download_is_stored_and_loads_back() {
        let store = Store::new(dir("ok"));
        let count = update(
            &store,
            &Fake::ok("0.0.0.0 ads.example\ntracker.net\n"),
            &custom("mine"),
        )
        .unwrap();
        assert_eq!(count, 2);
        let loaded = store.load("mine").unwrap();
        assert!(loaded.block.contains("ads.example"));
        assert!(store.load("never-fetched").is_none());
    }

    #[test]
    fn a_bad_download_never_replaces_a_good_list() {
        let store = Store::new(dir("keep"));
        update(&store, &Fake::ok("ads.example\n"), &custom("mine")).unwrap();
        for bad in ["# nothing useful\n", "<html>error page</html>"] {
            let result = update(&store, &Fake::ok(bad), &custom("mine"));
            assert!(result.is_err(), "{bad:?}");
        }
        let failing = Fake {
            body: Mutex::new(Err("connection reset".into())),
        };
        assert!(update(&store, &failing, &custom("mine")).is_err());
        assert!(store.load("mine").unwrap().block.contains("ads.example"));
    }

    #[test]
    fn no_temporary_files_are_left_behind() {
        let path = dir("clean");
        let store = Store::new(&path);
        update(&store, &Fake::ok("ads.example\n"), &custom("mine")).unwrap();
        let names: Vec<_> = std::fs::read_dir(&path)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, vec!["mine.list".to_string()]);
    }

    #[test]
    fn jitter_stays_within_a_tenth_of_the_interval() {
        let interval = Duration::from_secs(3600);
        for seed in [0, 1, 359, 360, u64::MAX] {
            let delay = next_delay(interval, seed);
            assert!(delay >= interval && delay < interval + Duration::from_secs(360));
        }
        assert_eq!(
            next_delay(Duration::from_secs(5), 99),
            Duration::from_secs(5)
        );
    }
}
