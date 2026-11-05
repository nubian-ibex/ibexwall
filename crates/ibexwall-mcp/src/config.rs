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

/// The HTTP transport: off unless the person turns it on, and never without
/// TLS (a token or an answer must not cross a network in the clear).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Http {
    pub enabled: bool,
    /// `127.0.0.1:8765` by default: reachable from this machine only until
    /// the person chooses an address.
    pub listen: String,
    pub tls_cert: String,
    pub tls_key: String,
    /// Browser origins allowed to call the server; none by default (a page
    /// in a browser cannot reach it).
    pub allowed_origins: Vec<String>,
    /// Failed sign-ins per minute from one address before it is refused.
    pub max_failures_per_minute: u32,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:8765".into(),
            tls_cert: "/etc/ibexwall/mcp/tls.crt".into(),
            tls_key: "/etc/ibexwall/mcp/tls.key".into(),
            allowed_origins: vec![],
            max_failures_per_minute: 10,
        }
    }
}

/// An access token: only its Argon2id hash lives here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub id: String,
    #[serde(default)]
    pub name: String,
    /// The `[[client]]` whose scopes this token gets.
    pub client: String,
    pub hash: String,
    /// `YYYY-MM-DD`; the token stops working after that day.
    #[serde(default)]
    pub expires: Option<String>,
}

impl Token {
    pub fn expired(&self, today: &str) -> bool {
        self.expires.as_deref().is_some_and(|day| day < today)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub defaults: Defaults,
    pub http: Http,
    #[serde(rename = "client")]
    pub clients: Vec<Client>,
    #[serde(rename = "token")]
    pub tokens: Vec<Token>,
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
        if config.http.enabled {
            if config.tokens.is_empty() {
                return Err("the HTTP transport is on but no [[token]] is defined".into());
            }
            if config.http.listen.parse::<std::net::SocketAddr>().is_err() {
                return Err(
                    "[http] listen must be an address and a port, like 127.0.0.1:8765".into(),
                );
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for token in &config.tokens {
            if !crate::token::valid_id(&token.id) || !seen.insert(token.id.clone()) {
                return Err(format!("token id `{}` is invalid or repeated", token.id));
            }
            if !token.hash.starts_with("$argon2id$") {
                return Err(format!("token `{}`: the hash must be Argon2id", token.id));
            }
            if token
                .expires
                .as_deref()
                .is_some_and(|d| !crate::token::valid_day(d))
            {
                return Err(format!("token `{}`: expires is YYYY-MM-DD", token.id));
            }
            if !config.clients.iter().any(|c| c.name == token.client) {
                return Err(format!(
                    "token `{}`: no [[client]] named `{}` gives it scopes",
                    token.id, token.client
                ));
            }
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

    const HTTP_ON: &str = r#"
[http]
enabled = true
listen = "0.0.0.0:8765"

[[client]]
name = "claude-code"
scopes = ["read:posture"]

[[token]]
id = "k1x"
name = "laptop"
client = "claude-code"
hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"
expires = "2026-12-31"
"#;

    #[test]
    fn http_is_off_by_default_and_a_token_must_name_a_known_client() {
        let default = Config::default();
        assert!(!default.http.enabled && default.http.listen == "127.0.0.1:8765");
        assert!(default.http.allowed_origins.is_empty());
        let on = Config::parse(HTTP_ON).unwrap();
        assert!(on.http.enabled && on.tokens[0].client == "claude-code");
        assert!(on.tokens[0].expired("2027-01-01") && !on.tokens[0].expired("2026-12-31"));
        for bad in [
            HTTP_ON.replace("client = \"claude-code\"\nhash", "client = \"ghost\"\nhash"),
            HTTP_ON.replace("$argon2id$", "$md5$"),
            HTTP_ON.replace("id = \"k1x\"", "id = \"K1\""),
            HTTP_ON.replace("expires = \"2026-12-31\"", "expires = \"soon\""),
            HTTP_ON.replace("listen = \"0.0.0.0:8765\"", "listen = \"nowhere\""),
            "[http]\nenabled = true\n".to_string(),
        ] {
            assert!(Config::parse(&bad).is_err(), "{bad}");
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
