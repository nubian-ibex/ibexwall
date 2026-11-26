// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The portable state file (ADR-0049): `ibexctl export` writes it,
//! `ibexctl import` reads it back. It holds the app's own state only: the
//! user and profile layers, the plugin enabled states and the restore
//! point names. The machine never changes on an import; the person then
//! reviews and applies through the normal flow. The organization layer is
//! refused outright (its locks belong to the organization), and the digest
//! is checked so a truncated or hand-edited file is caught.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result};
use serde_json::{Map, Value, json};

use super::*;
use crate::config::LayerFile;

const SCHEMA: u64 = 1;

pub(crate) async fn export(core: &Arc<Core>) -> Result<Reply, VarlinkError> {
    reload_config_blocking(core).await;
    let file = build(core).map_err(internal)?;
    Ok(Reply::result(json!({ "file": file })))
}

/// The file's content: `digest` covers the canonical form of everything
/// else, so a hand edit or a truncation is caught at import.
pub(super) fn build(core: &Core) -> Result<Value> {
    let config = core.config.read().expect("config lock poisoned");
    let plugins: Vec<Value> = core
        .plugins
        .plugins()
        .map(|e| {
            json!({
                "id": e.manifest.id,
                "enabled": core.state.plugin_enabled(&e.manifest.id).unwrap_or(false),
            })
        })
        .collect();
    let restore_points: Vec<Value> = core
        .state
        .list_restore_points()?
        .into_iter()
        .map(|(name, tx, created_at)| json!({ "name": name, "tx": tx, "created_at": created_at }))
        .collect();
    let mut effective = Map::new();
    for entry in core.plugins.plugins() {
        let manifest = &entry.manifest;
        effective.insert(
            manifest.id.clone(),
            Value::Object(
                config
                    .effective(&manifest.id, &std::collections::BTreeMap::new())
                    .into_iter()
                    .collect(),
            ),
        );
    }
    drop(config);
    let base = json!({
        "schema": SCHEMA,
        "ibexwall": env!("CARGO_PKG_VERSION"),
        "exported_at": ibexwall_sys::RealClock.rfc3339_now(),
        "layers": {
            "user": core_user_layer(core)?,
            "profile": core_profile_layer(core)?,
        },
        "effective": Value::Object(effective),
        "plugins": plugins,
        "restore_points": restore_points,
    });
    let digest = sha_digest(&base)?;
    Ok(json_with_digest(&base, &digest))
}

fn core_user_layer(core: &Core) -> Result<Value> {
    let config = core.config.read().expect("config lock poisoned");
    serde_json::to_value(&config.user).context("serializing the user layer")
}

fn core_profile_layer(core: &Core) -> Result<Value> {
    let config = core.config.read().expect("config lock poisoned");
    serde_json::to_value(&config.profile).context("serializing the profile layer")
}

/// JCS over the base object, hex encoded, like the plan fingerprint.
fn sha_digest(base: &Value) -> Result<String> {
    use sha2::Digest as _;
    let bytes = serde_jcs::to_vec(base)?;
    Ok(hex::encode(sha2::Sha256::digest(&bytes)))
}

fn json_with_digest(base: &Value, digest: &str) -> Value {
    let mut out = base.clone();
    if let Some(map) = out.as_object_mut() {
        map.insert("digest".into(), Value::String(digest.into()));
    }
    out
}

pub(crate) async fn import(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    // The whole file text travels as one parameter, so no length cap here
    // (the wire frame itself is bounded, A-11).
    let text = parameters
        .get("file")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| VarlinkError::invalid_parameter("file"))?;
    let apply = parameters.get("apply").and_then(Value::as_bool) == Some(true);
    let parsed: Value = serde_json::from_str(&text)
        .map_err(|e| invalid_argument("file", format!("not a JSON document: {e}")))?;
    if parsed.get("schema").and_then(Value::as_u64) != Some(SCHEMA) {
        return Err(invalid_argument(
            "file",
            format!("unsupported schema; this IbexWall reads schema {SCHEMA}"),
        ));
    }
    let layers = parsed
        .get("layers")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_argument("file", "the file has no layers".into()))?;
    if layers.contains_key("org") || parsed.get("org").is_some() || parsed.get("locks").is_some() {
        return Err(invalid_argument(
            "file",
            "the organization layer and its locks are not importable; they belong to the organization".into(),
        ));
    }
    let mut user: LayerFile =
        serde_json::from_value(layers.get("user").cloned().unwrap_or(json!({}))).map_err(|e| {
            invalid_argument("file", format!("the user layer is not readable: {e}"))
        })?;
    let mut profile: LayerFile = serde_json::from_value(
        layers.get("profile").cloned().unwrap_or(json!({})),
    )
    .map_err(|e| invalid_argument("file", format!("the profile layer is not readable: {e}")))?;
    check_digest(&parsed).map_err(|e| invalid_argument("file", e))?;

    // What differs from this machine, in both layers and both directions: the
    // import replaces each layer whole, so a key the file lacks goes away. A
    // key the organization locks keeps what this machine has.
    reload_config_blocking(core).await;
    let mut changed = BTreeSet::new();
    let mut locked = BTreeSet::new();
    {
        let config = core.config.read().expect("config lock poisoned");
        for (imported, current) in [(&mut user, &config.user), (&mut profile, &config.profile)] {
            for (plugin, key) in differing(imported, current) {
                match config.is_locked(&plugin, &key) {
                    Some(pattern) => {
                        locked.insert(format!("{plugin}.{key} ({pattern})"));
                        keep_current(imported, current, &plugin, &key);
                    }
                    None => {
                        changed.insert((plugin, key));
                    }
                }
            }
        }
    }
    let settings: Vec<Value> = changed
        .into_iter()
        .map(|(plugin, key)| json!({ "plugin": plugin, "key": key }))
        .collect();

    let mut plugin_changes: Vec<Value> = Vec::new();
    if let Some(list) = parsed.get("plugins").and_then(Value::as_array) {
        for entry in list {
            let Some(id) = entry.get("id").and_then(Value::as_str) else {
                continue;
            };
            let enabled = entry.get("enabled").and_then(Value::as_bool);
            let Some(enabled) = enabled else { continue };
            let known = core.plugins.plugins().any(|e| e.manifest.id == id);
            if !known {
                return Err(invalid_argument(
                    "file",
                    format!("the file enables `{id}`, which this IbexWall does not have"),
                ));
            }
            let current = core.state.plugin_enabled(id).map_err(internal)?;
            if current != enabled {
                plugin_changes.push(json!({ "id": id, "enabled": enabled }));
            }
        }
    }

    if !apply {
        return Ok(Reply::result(json!({
            "dry_run": true,
            "settings": settings,
            "plugins": plugin_changes,
            "locked": locked,
            "note": "nothing on the machine changes; the person then reviews and applies",
        })));
    }

    // No record, no change (the rule from A-13): the audit entry goes first.
    core.try_audit(actor, "core", None, "", "state-import-started")
        .map_err(internal)?;

    core.state
        .import_layers(
            &ibexwall_proto::names::path_under(&core.root, ibexwall_proto::names::CONFIG_DIR),
            &user,
            &profile,
        )
        .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
    for entry in &plugin_changes {
        let id = entry["id"].as_str().unwrap_or_default().to_string();
        let enabled = entry["enabled"].as_bool().unwrap_or(false);
        if let Err(error) = core.state.set_plugin_enabled(&id, enabled) {
            core.audit(actor, "core", None, "", "state-import-failed");
            return Err(err(
                "Conflict",
                json!({ "reason": format!("setting {id} enabled={enabled} failed: {error}") }),
            ));
        }
    }
    core.audit(actor, "core", None, "", "state-imported");
    core.reload_config();
    Ok(Reply::result(json!({
        "imported": true,
        "settings": settings.len(),
        "plugins": plugin_changes.len(),
        "locked_kept": locked.len(),
    })))
}

/// The `(plugin, key)` pairs whose value is not the same in both layers.
fn differing(a: &LayerFile, b: &LayerFile) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for (from, other) in [(a, b), (b, a)] {
        for (plugin, keys) in &from.plugins {
            for (key, value) in keys {
                if other.plugins.get(plugin).and_then(|k| k.get(key)) != Some(value) {
                    out.insert((plugin.clone(), key.clone()));
                }
            }
        }
    }
    out
}

fn keep_current(imported: &mut LayerFile, current: &LayerFile, plugin: &str, key: &str) {
    let section = imported.plugins.entry(plugin.into()).or_default();
    match current.plugins.get(plugin).and_then(|k| k.get(key)) {
        Some(value) => section.insert(key.into(), value.clone()),
        None => section.remove(key),
    };
}

fn check_digest(parsed: &Value) -> Result<(), String> {
    let Some(claimed) = parsed.get("digest").and_then(Value::as_str) else {
        return Err("the file has no digest".into());
    };
    let mut base = parsed.clone();
    if let Some(map) = base.as_object_mut() {
        map.remove("digest");
    }
    let actual = sha_digest(&base).map_err(|e| e.to_string())?;
    if actual != claimed {
        return Err(
            "the digest does not match the content (the file was truncated or edited)".into(),
        );
    }
    Ok(())
}
