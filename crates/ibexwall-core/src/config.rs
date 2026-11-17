// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Configuration in layers (spec §4.6): `default` (plugin) < `profile`
//! < `user` < `org` (with locks). F1 stores layers as TOML files under
//! the config directory; the org layer is empty in production but the
//! precedence and lock enforcement are fully implemented and tested
//! with local fixtures.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;

use ibexwall_proto::names;

/// Layer precedence, lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    Default,
    Profile,
    User,
    Org,
}

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Default => "default",
            Layer::Profile => "profile",
            Layer::User => "user",
            Layer::Org => "org",
        }
    }
}

/// One layer file: `<plugin id>.<setting key> = <value>` tables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LayerFile {
    /// e.g. `["net.dns"]` sections with settings inside.
    #[serde(default)]
    pub plugins: BTreeMap<String, BTreeMap<String, Value>>,
}

/// Effective settings plus lock bookkeeping.
#[derive(Debug, Clone, Default)]
pub struct Layers {
    pub user: LayerFile,
    pub profile: LayerFile,
    pub org: LayerFile,
    /// Glob patterns locked by the org layer (`net.firewall.*`).
    pub locks: Vec<String>,
    /// Layer files that could not be read at start: the daemon runs on the
    /// others rather than not at all, and says so in `GetInfo`.
    pub problems: Vec<String>,
    root: PathBuf,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum LockError {
    #[error("key `{key}` is locked by the organization layer ({pattern})")]
    Locked { key: String, pattern: String },
}

impl Layers {
    /// Like [`Layers::load`], but a layer file that cannot be read or parsed
    /// is left out and reported in `problems`. Used at start: a truncated
    /// `org.toml` (a crash during a write, a hand edit) must not keep the
    /// daemon, and with it the recovery of interrupted changes, from
    /// running. The bad file is left as it is for the person to fix.
    pub fn load_lenient(root: &Path) -> Self {
        let config_dir = ibexwall_proto::names::path_under(root, names::CONFIG_DIR);
        let mut problems = Vec::new();
        let mut layer = |name: &str| match load_layer(&config_dir.join(name)) {
            Ok(layer) => layer,
            Err(error) => {
                tracing::error!(file = name, error = %format!("{error:#}"), "unusable configuration file, ignoring it");
                problems.push(format!("configuration {name} is unusable and ignored"));
                LayerFile::default()
            }
        };
        let user = layer("config.toml");
        let profile = layer("profiles.d/active.toml");
        let org = layer("org.toml");
        Self {
            user,
            profile,
            org,
            locks: org_locks(&config_dir),
            problems,
            root: root.to_path_buf(),
        }
    }

    /// Loads `user`, `profile` and `org` layer files if present.
    pub fn load(root: &Path) -> Result<Self> {
        let config_dir = ibexwall_proto::names::path_under(root, names::CONFIG_DIR);
        let layers = Self {
            user: load_layer(&config_dir.join("config.toml"))?,
            profile: load_layer(&config_dir.join("profiles.d/active.toml"))?,
            org: load_layer(&config_dir.join("org.toml"))?,
            locks: org_locks(&config_dir),
            problems: Vec::new(),
            root: root.to_path_buf(),
        };
        Ok(layers)
    }

    /// Merged effective settings for one plugin: profile over user over
    /// defaults (defaults come from plugin manifests, passed by the
    /// caller as `default`).
    pub fn effective(
        &self,
        plugin: &str,
        default: &BTreeMap<String, Value>,
    ) -> BTreeMap<String, Value> {
        let mut merged = default.clone();
        for layer in [&self.profile, &self.user, &self.org] {
            if let Some(section) = layer.plugins.get(plugin) {
                merged.extend(section.clone());
            }
        }
        merged
    }

    /// Is `plugin.key` (or the whole plugin via `plugin.*`) locked?
    pub fn is_locked(&self, plugin: &str, key: &str) -> Option<&str> {
        for pattern in &self.locks {
            let plugin_glob = format!("{plugin}.*");
            let exact_key = format!("{plugin}.{key}");
            let matches = match pattern.as_str() {
                p if p == plugin_glob => true,
                p if p == exact_key => true,
                p if p.ends_with(".*") && p.trim_end_matches(".*") == plugin => true,
                _ => false,
            };
            if matches {
                return Some(pattern);
            }
        }
        None
    }

    /// Writes a user-layer setting, enforcing org locks first.
    pub fn set_user(&mut self, plugin: &str, key: &str, value: Value) -> Result<(), LockError> {
        if let Some(pattern) = self.is_locked(plugin, key) {
            return Err(LockError::Locked {
                key: format!("{plugin}.{key}"),
                pattern: pattern.to_string(),
            });
        }
        self.user
            .plugins
            .entry(plugin.into())
            .or_default()
            .insert(key.into(), value);
        self.persist_user_layer().expect("user layer dir exists");
        Ok(())
    }

    fn persist_user_layer(&self) -> Result<()> {
        let config_dir = ibexwall_proto::names::path_under(&self.root, names::CONFIG_DIR);
        std::fs::create_dir_all(&config_dir)?;
        let text = toml::to_string_pretty(&self.user)?;
        std::fs::write(config_dir.join("config.toml"), text)?;
        Ok(())
    }

    /// Stable fingerprint over all layers (feeds plan staleness).
    pub fn fingerprint(&self) -> String {
        let canonical = serde_json::json!({
            "user": &self.user,
            "profile": &self.profile,
            "org": &self.org,
            "locks": &self.locks,
        });
        let bytes = serde_jcs::to_vec(&canonical).unwrap_or_default();
        let digest = sha2::Sha256::digest(&bytes);
        hex::encode(digest)
    }

    pub fn user_toml(&self) -> String {
        toml::to_string_pretty(&self.user).unwrap_or_default()
    }
}

/// Replaces `path` without ever exposing a half-written file: the data goes
/// to a sibling temp file, is synced, then renamed over the target. A crash
/// leaves the old file or the new one, never a truncated `org.toml`.
pub fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("toml.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Locks travel with the org layer: `lock = ["net.dns.*"]`.
fn org_locks(config_dir: &Path) -> Vec<String> {
    if let Ok(text) = std::fs::read_to_string(config_dir.join("org.toml"))
        && let Ok(doc) = text.parse::<toml::Table>()
        && let Some(toml::Value::Array(list)) = doc.get("lock")
    {
        return list
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    Vec::new()
}

fn load_layer(path: &Path) -> Result<LayerFile> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LayerFile::default()),
        Err(e) => Err(anyhow::Error::new(e).context(format!("reading {}", path.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_corrupt_layer_is_ignored_and_reported_at_start() {
        let root = std::env::temp_dir().join(format!("ibexwall-lenient-{}", std::process::id()));
        let config_dir = root.join("etc/ibexwall");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            "[plugins.\"net.dns\"]\nprovider = \"quad9\"\n",
        )
        .unwrap();
        // A write that stopped half way.
        std::fs::write(
            config_dir.join("org.toml"),
            "lock = [\"net.dns.*\"\n[\"net.fi",
        )
        .unwrap();
        assert!(Layers::load(&root).is_err());
        let layers = Layers::load_lenient(&root);
        assert!(layers.user.plugins.contains_key("net.dns"));
        assert!(layers.org.plugins.is_empty());
        assert_eq!(layers.problems.len(), 1, "{:?}", layers.problems);
        assert!(layers.problems[0].contains("org.toml"));
        // The file is left for the person to fix.
        assert!(config_dir.join("org.toml").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    fn layers_with_org_lock(lock: &str) -> Layers {
        let root = std::env::temp_dir().join(format!("ibexwall-layers-{}", std::process::id()));
        let config_dir = root.join("etc/ibexwall");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("org.toml"),
            format!(
                "lock = [\"{lock}\"]\n[net.dns]\nupstream = \"https://dns.example/dns-query\"\n"
            ),
        )
        .unwrap();
        Layers::load(&root).unwrap()
    }

    #[test]
    fn write_atomic_replaces_the_file_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!("ibexwall-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("org.toml");
        std::fs::write(&path, "old").unwrap();
        write_atomic(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert!(!dir.join("org.toml.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn higher_layers_override_lower_ones() {
        let mut layers = Layers::default();
        layers.user.plugins.insert(
            "net.dns".into(),
            BTreeMap::from([("blocklists".into(), json!(["hagezi-light"]))]),
        );
        layers.org.plugins.insert(
            "net.dns".into(),
            BTreeMap::from([("blocklists".into(), json!(["hagezi-pro"]))]),
        );
        let default = BTreeMap::from([("upstream".into(), json!("quad9"))]);
        let effective = layers.effective("net.dns", &default);
        assert_eq!(effective["upstream"], json!("quad9"));
        assert_eq!(effective["blocklists"], json!(["hagezi-pro"]));
    }

    #[test]
    fn locks_are_enforced_on_write() {
        let mut layers = layers_with_org_lock("net.dns.upstream");
        // Locked key refuses the write.
        let err = layers
            .set_user("net.dns", "upstream", json!("quad9"))
            .unwrap_err();
        assert!(matches!(err, LockError::Locked { .. }));
        // Unlocked key is fine.
        layers
            .set_user("net.dns", "blocklists", json!(["hagezi-light"]))
            .unwrap();
        assert_eq!(
            layers.user.plugins["net.dns"]["blocklists"],
            json!(["hagezi-light"])
        );
    }

    #[test]
    fn wildcard_locks_cover_whole_plugins() {
        let layers = layers_with_org_lock("device.usb.*");
        assert!(layers.is_locked("device.usb", "enabled").is_some());
        assert!(layers.is_locked("device.usb", "new_keyboards").is_some());
        assert!(layers.is_locked("net.dns", "upstream").is_none());
    }

    #[test]
    fn fingerprint_is_stable_and_changes_with_layers() {
        let mut layers = Layers::default();
        let first = layers.fingerprint();
        assert_eq!(first, layers.fingerprint());
        layers
            .user
            .plugins
            .insert("x".into(), BTreeMap::from([("k".into(), json!(1))]));
        assert_ne!(first, layers.fingerprint());
    }
}
