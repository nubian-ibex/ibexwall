// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.assistant`: what an AI assistant may do through the MCP server,
//! and who may reach it from another machine. The plugin owns
//! `/etc/ibexwall/mcp.toml` and changes it only through a plan, so turning on
//! remote access is reviewed, approved and reversible like any other change.
//!
//! A client gets one of three presets (read; read and plan; read, plan and
//! propose), never a free list of scopes. A token arrives as its Argon2id
//! hash: the secret is made where the person is, shown once, and never
//! crosses this plugin, a plan or a log. The file keeps its comments.

use std::collections::BTreeMap;

use ibexwall_proto::{CheckReport, Finding, FindingStatus, Op, Severity};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use ibexwall_token as token;
use serde::Deserialize;
use serde_json::Value;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

const CONFIG: &str = "/etc/ibexwall/mcp.toml";
const ID: &str = "system.assistant";

/// What a client may do. The names are the only choice the person has.
pub const PRESETS: &[(&str, &[&str])] = &[
    (
        "read",
        &[
            "read:posture",
            "read:findings",
            "read:events:dns",
            "read:events:apps",
        ],
    ),
    (
        "plan",
        &[
            "read:posture",
            "read:findings",
            "read:events:dns",
            "read:events:apps",
            "plan",
        ],
    ),
    (
        "propose",
        &[
            "read:posture",
            "read:findings",
            "read:events:dns",
            "read:events:apps",
            "plan",
            "propose:*",
        ],
    ),
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Config {
    /// `client`, `http`, `token_add` or `token_revoke`.
    action: String,
    /// The client a preset or a token is for: letters, digits, `-` and `_`.
    client: String,
    preset: String,
    /// `http`: whether the HTTPS transport is on, and where it listens.
    enabled: bool,
    listen: String,
    /// `token_add` / `token_revoke`.
    id: String,
    name: String,
    hash: String,
    expires: Option<String>,
}

struct Assistant;

pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Assistant)) {
        eprintln!("ibexwall-plugin-assistant: {err}");
        std::process::exit(1);
    }
}

impl Plugin for Assistant {
    fn id(&self) -> &'static str {
        ID
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(CheckReport {
            results: vec![],
            findings: report(&Sandbox::system(), "1970-01-01T00:00:00Z"),
        })
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }
}

fn client_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 60
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn load(sandbox: &Sandbox) -> Result<DocumentMut, PluginError> {
    match sandbox.read(CONFIG) {
        Some(text) => text
            .parse::<DocumentMut>()
            .map_err(|e| PluginError::invalid("config", format!("mcp.toml is not valid: {e}"))),
        None => {
            let mut doc = DocumentMut::new();
            doc.decor_mut().set_prefix(
                "# IbexWall MCP access (managed by the AI assistants screen).\n# Clients choose what an assistant may do; tokens let one reach this machine.\n\n",
            );
            Ok(doc)
        }
    }
}

fn clients(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if !doc.contains_key("client") {
        doc.insert("client", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["client"]
        .as_array_of_tables_mut()
        .expect("client is an array of tables")
}

fn tokens(doc: &mut DocumentMut) -> &mut ArrayOfTables {
    if !doc.contains_key("token") {
        doc.insert("token", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    doc["token"]
        .as_array_of_tables_mut()
        .expect("token is an array of tables")
}

fn set_preset(doc: &mut DocumentMut, client: &str, preset: &str) -> Result<(), PluginError> {
    if !client_ok(client) {
        return Err(PluginError::invalid(
            "client",
            "letters, digits, `-` and `_`, up to 60",
        ));
    }
    let scopes = PRESETS
        .iter()
        .find(|(name, _)| *name == preset)
        .map(|(_, scopes)| *scopes)
        .ok_or_else(|| {
            PluginError::invalid("preset", "the presets are `read`, `plan` and `propose`")
        })?;
    let mut array = Array::new();
    for scope in scopes {
        array.push(*scope);
    }
    let list = clients(doc);
    if let Some(existing) = list
        .iter_mut()
        .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(client))
    {
        existing.insert("scopes", value(array));
    } else {
        let mut table = Table::new();
        table.insert("name", value(client));
        table.insert("scopes", value(array));
        list.push(table);
    }
    Ok(())
}

fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    let mut doc = load(sandbox)?;
    match config.action.as_str() {
        "client" => set_preset(&mut doc, &config.client, &config.preset)?,
        "http" => {
            if config.enabled {
                config.listen.parse::<std::net::SocketAddr>().map_err(|_| {
                    PluginError::invalid("listen", "an address and a port, like 127.0.0.1:8765")
                })?;
                if tokens(&mut doc).is_empty() {
                    return Err(PluginError::invalid(
                        "enabled",
                        "create a token first: remote access needs one",
                    ));
                }
                for path in ["/etc/ibexwall/mcp/tls.crt", "/etc/ibexwall/mcp/tls.key"] {
                    if !sandbox.exists(path) {
                        return Err(PluginError::invalid(
                            "enabled",
                            format!(
                                "{path} is missing: make the certificate first (ibexwall-mcp tls-init)"
                            ),
                        ));
                    }
                }
            }
            if !doc.contains_key("http") {
                doc.insert("http", Item::Table(Table::new()));
            }
            let http = doc["http"]
                .as_table_mut()
                .ok_or_else(|| PluginError::invalid("config", "[http] is not a table"))?;
            http.insert("enabled", value(config.enabled));
            if config.enabled {
                http.insert("listen", value(config.listen.as_str()));
            }
        }
        "token_add" => {
            if !token::valid_id(&config.id) {
                return Err(PluginError::invalid(
                    "id",
                    "3 to 16 lowercase letters or digits",
                ));
            }
            if config.name.is_empty()
                || config.name.len() > 60
                || config.name.chars().any(|c| c.is_control() || c == '"')
            {
                return Err(PluginError::invalid(
                    "name",
                    "1 to 60 characters, without quotes",
                ));
            }
            if !config.hash.starts_with("$argon2id$") || config.hash.len() > 300 {
                return Err(PluginError::invalid(
                    "hash",
                    "an Argon2id hash; the secret itself is never sent",
                ));
            }
            if let Some(day) = &config.expires
                && !token::valid_day(day)
            {
                return Err(PluginError::invalid("expires", "a date, YYYY-MM-DD"));
            }
            if config.preset.is_empty() {
                return Err(PluginError::invalid("preset", "read, plan or propose"));
            }
            // The token's client is the one the preset names, so the token
            // can never carry more than the person chose.
            set_preset(&mut doc, &config.client, &config.preset)?;
            let list = tokens(&mut doc);
            if list
                .iter()
                .any(|t| t.get("id").and_then(|i| i.as_str()) == Some(config.id.as_str()))
            {
                return Err(PluginError::invalid("id", "a token with this id exists"));
            }
            let mut table = Table::new();
            table.insert("id", value(config.id.as_str()));
            table.insert("name", value(config.name.as_str()));
            table.insert("client", value(config.client.as_str()));
            table.insert("hash", value(config.hash.as_str()));
            if let Some(day) = &config.expires {
                table.insert("expires", value(day.as_str()));
            }
            list.push(table);
        }
        "token_revoke" => {
            let list = tokens(&mut doc);
            let before = list.len();
            let keep: Vec<Table> = list
                .iter()
                .filter(|t| t.get("id").and_then(|i| i.as_str()) != Some(config.id.as_str()))
                .cloned()
                .collect();
            if keep.len() == before {
                return Err(PluginError::invalid("id", "no token has this id"));
            }
            let mut rest = ArrayOfTables::new();
            for table in keep {
                rest.push(table);
            }
            doc.insert("token", Item::ArrayOfTables(rest));
            // The client this screen made for the key goes with it. Clients
            // the person named themselves are left alone.
            let in_use: Vec<String> = doc["token"]
                .as_array_of_tables()
                .map(|t| {
                    t.iter()
                        .filter_map(|t| t.get("client").and_then(|c| c.as_str()).map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some(list) = doc
                .get_mut("client")
                .and_then(|c| c.as_array_of_tables_mut())
            {
                let mut kept = ArrayOfTables::new();
                for table in list.iter() {
                    let name = table.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if !name.starts_with("remote-") || in_use.iter().any(|c| c == name) {
                        kept.push(table.clone());
                    }
                }
                *list = kept;
            }
            // Turning a transport on with no token left would be refused by
            // the server; turn it off with the last token.
            if doc["token"]
                .as_array_of_tables()
                .is_some_and(|t| t.is_empty())
                && let Some(http) = doc.get_mut("http").and_then(|h| h.as_table_mut())
            {
                http.insert("enabled", value(false));
            }
        }
        _ => {
            return Err(PluginError::invalid(
                "action",
                "action is `client`, `http`, `token_add` or `token_revoke`",
            ));
        }
    }
    Ok(vec![Op::FileWrite {
        path: CONFIG.into(),
        content: doc.to_string(),
        mode: "0640".into(),
        owner: "root".into(),
        group: "ibexwall-assistants".into(),
    }])
}

fn info(
    id: String,
    title: &str,
    summary: &str,
    args: BTreeMap<String, String>,
    at: &str,
) -> Finding {
    Finding {
        id,
        plugin: ID.into(),
        severity: Severity::Info,
        title_key: title.into(),
        summary_key: summary.into(),
        args,
        references: vec![],
        remediation: None,
        status: FindingStatus::Open,
        detected_at: at.into(),
    }
}

/// What is set today, for the screen: the transport, and each token without
/// its hash. Information only.
fn report(sandbox: &Sandbox, at: &str) -> Vec<Finding> {
    let Some(text) = sandbox.read(CONFIG) else {
        return vec![];
    };
    let Ok(doc) = text.parse::<DocumentMut>() else {
        return vec![];
    };
    let mut out = Vec::new();
    let http = doc.get("http").and_then(|h| h.as_table());
    let enabled = http
        .and_then(|h| h.get("enabled"))
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    let listen = http
        .and_then(|h| h.get("listen"))
        .and_then(|l| l.as_str())
        .unwrap_or("127.0.0.1:8765");
    out.push(info(
        "assistant.http".into(),
        "assistant-http-title",
        "assistant-http-summary",
        BTreeMap::from([
            ("enabled".to_string(), enabled.to_string()),
            ("listen".to_string(), listen.to_string()),
        ]),
        at,
    ));
    let preset_of = |client: &str| -> String {
        let scopes: Vec<String> = doc
            .get("client")
            .and_then(|c| c.as_array_of_tables())
            .and_then(|list| {
                list.iter()
                    .find(|t| t.get("name").and_then(|n| n.as_str()) == Some(client))
            })
            .and_then(|t| t.get("scopes"))
            .and_then(|s| s.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        PRESETS
            .iter()
            .find(|(_, preset)| {
                preset.len() == scopes.len() && preset.iter().all(|p| scopes.iter().any(|s| s == p))
            })
            .map_or("custom", |(name, _)| *name)
            .to_string()
    };
    if let Some(list) = doc.get("token").and_then(|t| t.as_array_of_tables()) {
        for t in list.iter() {
            let get = |k: &str| t.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let client = get("client");
            out.push(info(
                format!("assistant.token.{}", get("id")),
                "assistant-token-title",
                "assistant-token-summary",
                BTreeMap::from([
                    ("id".to_string(), get("id")),
                    ("name".to_string(), get("name")),
                    ("preset".to_string(), preset_of(&client)),
                    ("client".to_string(), client),
                    ("expires".to_string(), get("expires")),
                ]),
                at,
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests;
