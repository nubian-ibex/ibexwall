// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Plugin manifest (`plugin.toml`, spec §5.2 and Appendix A).
//!
//! `[privileges]` states what the **core** may execute on the plugin's
//! behalf; `[sandbox]` states how the plugin **process** itself runs.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::names;
use crate::op::{Reversible, UnitAction};

/// Localized text: locale tag to string (`en` is the source locale).
pub type LocalizedText = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PluginOrigin {
    Official,
    Community,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    Check,
    Control,
    Monitor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SandboxUser {
    /// `DynamicUser=yes`; the default and the goal whenever possible.
    Dynamic,
    /// Requires justification, surfaced in the plugin index.
    Root,
}

/// Exact exec allowlist entry: binary plus fixed argv pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecAllow {
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// This exec is its own inverse: the rollback runs it again after the
    /// files are restored (a manager told to re-read its directory).
    #[serde(default)]
    pub symmetric: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Requires {
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub packages: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Conflicts {
    #[serde(default)]
    pub units: Vec<String>,
}

/// What the core may execute on the plugin's behalf.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Privileges {
    #[serde(default)]
    pub write_paths: Vec<String>,
    #[serde(default)]
    pub units: Vec<String>,
    #[serde(default)]
    pub unit_actions: Vec<UnitAction>,
    #[serde(default)]
    pub sysctl_keys: Vec<String>,
    #[serde(default)]
    pub exec: Vec<ExecAllow>,
    #[serde(default)]
    pub nft_prefix: Option<String>,
    /// Firewall managers the plugin may drive through `firewall.adapter`
    /// (`firewalld`, `ufw`).
    #[serde(default)]
    pub firewall_backends: Vec<String>,
}

/// How the plugin process is sandboxed (reflected into its unit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub user: SandboxUser,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub read_paths: Vec<String>,
    #[serde(default)]
    pub network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RiskInfo {
    #[serde(default)]
    pub affects: Vec<String>,
    pub reversible: Reversible,
    #[serde(default)]
    pub confirm_timeout: bool,
    #[serde(default)]
    pub may_affect: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    pub icon: String,
    pub order: i32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// `<category>.<name>`, e.g. `net.dns`.
    pub id: String,
    pub version: String,
    pub api: u32,
    pub category: String,
    pub kinds: Vec<PluginKind>,
    pub origin: PluginOrigin,
    pub license: String,
    pub binary: String,
    #[serde(default)]
    pub config_schema: Option<String>,
    #[serde(default)]
    pub default_enabled: bool,
    #[serde(default)]
    pub distros: Vec<String>,
    pub name: LocalizedText,
    #[serde(default)]
    pub description: LocalizedText,
    #[serde(default)]
    pub requires: Requires,
    #[serde(default)]
    pub conflicts: Conflicts,
    pub privileges: Privileges,
    pub sandbox: Sandbox,
    pub risk: RiskInfo,
    #[serde(default)]
    pub ui: Option<Ui>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ManifestError {
    #[error("plugin id must be `<category>.<name>` with lowercase [a-z0-9-] segments, got `{0}`")]
    InvalidId(String),
    #[error("manifest `name` must include the source locale `{0}`")]
    MissingSourceLocale(String),
    #[error("manifest `binary` must be `{expected}`, got `{actual}`")]
    InvalidBinary { expected: String, actual: String },
    #[error("`version` must be a non-empty semver string")]
    InvalidVersion,
}

impl Manifest {
    /// Structural validation beyond deserialization.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let parts: Vec<&str> = self.id.split('.').collect();
        let valid_id = parts.len() == 2
            && parts.iter().all(|p| {
                !p.is_empty()
                    && p.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            });
        if !valid_id {
            return Err(ManifestError::InvalidId(self.id.clone()));
        }
        if !self.name.contains_key(names::LOCALE_SOURCE) {
            return Err(ManifestError::MissingSourceLocale(
                names::LOCALE_SOURCE.into(),
            ));
        }
        let expected = format!("{}{}", names::PLUGIN_BIN_PREFIX, parts[1]);
        if self.binary != expected {
            return Err(ManifestError::InvalidBinary {
                expected,
                actual: self.binary.clone(),
            });
        }
        if self.version.is_empty() {
            return Err(ManifestError::InvalidVersion);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NTS_MANIFEST: &str = r#"
id = "net.nts"
version = "1.0.0"
api = 1
category = "network"
kinds = ["check", "control"]
origin = "official"
license = "GPL-3.0-or-later"
binary = "ibexwall-plugin-nts"
config_schema = "schema.json"
default_enabled = false
distros = ["fedora", "ubuntu", "debian", "arch"]

[name]
en = "Secure time (NTS)"
pt-BR = "Hora segura (NTS)"

[description]
en = "Keeps the clock right using authenticated time servers."
pt-BR = "Mantém o relógio certo com servidores de hora autenticados."

[requires]
commands = ["chronyc"]
packages = { fedora = ["chrony"], arch = ["chrony"] }

[conflicts]
units = ["systemd-timesyncd.service"]

[privileges]
write_paths = ["/etc/chrony.d/ibexwall.conf"]
units = ["chronyd.service", "chrony.service", "systemd-timesyncd.service"]
unit_actions = ["start", "stop", "restart", "enable", "disable"]
sysctl_keys = []
exec = []
nft_prefix = "net_nts"

[sandbox]
user = "dynamic"
capabilities = []
read_paths = ["/etc/chrony.conf", "/run/chrony"]
network = false

[risk]
affects = ["time"]
reversible = "immediate"
confirm_timeout = false
may_affect = ["nts-may-affect-firewall-4460"]

[ui]
icon = "clock"
order = 40
"#;

    fn parse(src: &str) -> Manifest {
        toml::from_str(src).expect("manifest parses")
    }

    #[test]
    fn parses_the_reference_manifest() {
        let manifest = parse(NTS_MANIFEST);
        assert_eq!(manifest.id, "net.nts");
        assert_eq!(manifest.kinds, vec![PluginKind::Check, PluginKind::Control]);
        assert_eq!(manifest.sandbox.user, SandboxUser::Dynamic);
        assert_eq!(manifest.privileges.nft_prefix.as_deref(), Some("net_nts"));
        manifest.validate().expect("reference manifest is valid");
    }

    #[test]
    fn rejects_unknown_fields() {
        let src = format!("{NTS_MANIFEST}\n[shenanigans]\nx = 1\n");
        assert!(toml::from_str::<Manifest>(&src).is_err());
    }

    #[test]
    fn rejects_invalid_ids() {
        let mut manifest = parse(NTS_MANIFEST);
        manifest.id = "netdns".into();
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::InvalidId("netdns".into()))
        );
        manifest.id = "Net.Dns".into();
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::InvalidId("Net.Dns".into()))
        );
    }

    #[test]
    fn rejects_wrong_binary_name() {
        let mut manifest = parse(NTS_MANIFEST);
        manifest.binary = "nts-helper".into();
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidBinary { .. })
        ));
    }

    #[test]
    fn requires_the_source_locale() {
        let mut manifest = parse(NTS_MANIFEST);
        manifest.name.remove("en");
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::MissingSourceLocale("en".into()))
        );
    }
}
