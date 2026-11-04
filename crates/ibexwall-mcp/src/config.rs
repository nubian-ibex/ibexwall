// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/ibexwall/mcp.toml` (spec Appendix F): who may do what.
//!
//! A scope is `read:posture`, `read:findings`, `read:events:<source>`,
//! `read:config`, `read:audit`, `plan` or `propose:<plugin glob>`. A client
//! the file does not name gets the read-only baseline, never a proposal.
//! Sensitive plugins are denied by default, for every client.

use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Defaults {
    pub transport: String,
    pub local_model_only_warning: bool,
    pub redact: Vec<String>,
    pub deny_plugins: Vec<String>,
    /// `aggregates` (default), `none` or `full` (needs this explicit word).
    pub dns_history: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            transport: "stdio".into(),
            local_model_only_warning: true,
            redact: [
                "username",
                "hostname",
                "ssid",
                "mac",
                "private_ip",
                "home_path",
            ]
            .map(String::from)
            .to_vec(),
            // net.vpn: a profile carries a private key, which must never
            // pass through an assistant.
            deny_plugins: ["system.accounts", "disk.*", "managed", "net.vpn"]
                .map(String::from)
                .to_vec(),
            dns_history: "aggregates".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// `60/min`.
    #[serde(default)]
    pub rate_limit: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub defaults: Defaults,
    #[serde(rename = "client")]
    pub clients: Vec<Client>,
}

/// What every unnamed client may do.
pub const BASELINE_SCOPES: &[&str] = &["read:posture", "read:findings"];
pub const BASELINE_RATE: u32 = 30;

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let config: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        if config.defaults.transport != "stdio" {
            return Err("only the stdio transport is available".into());
        }
        if !matches!(
            config.defaults.dns_history.as_str(),
            "aggregates" | "none" | "full"
        ) {
            return Err("dns_history is aggregates, none or full".into());
        }
        for client in &config.clients {
            if let Some(limit) = &client.rate_limit {
                parse_rate(limit).ok_or_else(|| format!("bad rate limit `{limit}`"))?;
            }
        }
        Ok(config)
    }

    pub fn client(&self, name: &str) -> Grants {
        match self.clients.iter().find(|c| c.name == name) {
            Some(client) => Grants {
                scopes: client.scopes.clone(),
                per_minute: client
                    .rate_limit
                    .as_deref()
                    .and_then(parse_rate)
                    .unwrap_or(BASELINE_RATE),
            },
            None => Grants {
                scopes: BASELINE_SCOPES.iter().map(|s| s.to_string()).collect(),
                per_minute: BASELINE_RATE,
            },
        }
    }

    /// True when `plugin` matches a denied pattern (`disk.*`, `managed`).
    pub fn denies(&self, plugin: &str) -> bool {
        self.defaults.deny_plugins.iter().any(|p| glob(p, plugin))
    }
}

/// `60/min` as a count per minute.
pub fn parse_rate(text: &str) -> Option<u32> {
    let (n, unit) = text.split_once('/')?;
    let n: u32 = n.trim().parse().ok()?;
    match unit.trim() {
        "min" | "minute" => Some(n),
        "sec" | "s" => Some(n.saturating_mul(60)),
        "hour" | "h" => Some((n / 60).max(1)),
        _ => None,
    }
    .filter(|n| *n >= 1)
}

/// A trailing `*` matches any suffix; otherwise equality, or a dotted prefix
/// (`managed` also denies `managed.anything`).
pub fn glob(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => value == pattern || value.starts_with(&format!("{pattern}.")),
    }
}

#[derive(Debug, Clone)]
pub struct Grants {
    pub scopes: Vec<String>,
    pub per_minute: u32,
}

impl Grants {
    /// Exact scope, a `*` suffix (`propose:*`, `propose:system.*`), or for
    /// `read:events:<source>` the wildcard `read:events:*`.
    pub fn allows(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| {
            granted == scope
                || granted
                    .strip_suffix('*')
                    .is_some_and(|prefix| scope.starts_with(prefix))
        })
    }
}

pub fn window() -> Duration {
    Duration::from_secs(60)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[defaults]
transport = "stdio"
deny_plugins = ["system.accounts", "disk.*", "managed"]
dns_history = "aggregates"

[[client]]
name = "claude-code"
scopes = ["read:posture", "read:findings", "read:events:dns", "plan", "propose:*"]
rate_limit = "60/min"

[[client]]
name = "opencode"
scopes = ["read:posture", "propose:system.*"]
rate_limit = "30/min"
"#;

    #[test]
    fn the_appendix_example_parses_and_scopes_are_exact_or_wildcard() {
        let config = Config::parse(SAMPLE).unwrap();
        let claude = config.client("claude-code");
        assert_eq!(claude.per_minute, 60);
        assert!(claude.allows("read:events:dns"));
        assert!(!claude.allows("read:events:apps"));
        assert!(claude.allows("propose:net.dns"));
        let opencode = config.client("opencode");
        assert!(opencode.allows("propose:system.sysctl"));
        assert!(!opencode.allows("propose:net.dns"));
        assert!(!opencode.allows("plan"));
    }

    #[test]
    fn an_unnamed_client_is_read_only() {
        let config = Config::parse(SAMPLE).unwrap();
        let stranger = config.client("never-heard-of-it");
        assert!(stranger.allows("read:posture"));
        assert!(!stranger.allows("propose:system.sysctl"));
        assert!(!stranger.allows("plan"));
        assert!(!stranger.allows("read:events:dns"));
        // No file at all: the same.
        assert!(!Config::default().client("x").allows("propose:anything"));
    }

    #[test]
    fn sensitive_plugins_are_denied_by_default() {
        let config = Config::default();
        for denied in [
            "system.accounts",
            "disk.encryption",
            "managed",
            "managed.org",
            "net.vpn",
        ] {
            assert!(config.denies(denied), "{denied}");
        }
        for allowed in ["net.dns", "system.sysctl", "system.accountsx"] {
            assert!(!config.denies(allowed), "{allowed}");
        }
    }

    #[test]
    fn bad_files_are_refused_not_half_read() {
        assert!(Config::parse("[defaults]\ntransport = \"http\"").is_err());
        assert!(Config::parse("[defaults]\ndns_history = \"everything\"").is_err());
        assert!(Config::parse("[[client]]\nname = \"x\"\nrate_limit = \"fast\"").is_err());
        assert!(Config::parse("[[client]]\nname = \"x\"\nsurprise = 1").is_err());
        assert_eq!(parse_rate("60/min"), Some(60));
        assert_eq!(parse_rate("2/sec"), Some(120));
        assert_eq!(parse_rate("0/min"), None);
    }
}
