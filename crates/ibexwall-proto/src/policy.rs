// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Managed-mode policy bundle (spec §4.14, Appendix D).
//!
//! The bundle is canonicalized with JCS (RFC 8785) and signed with
//! ed25519; verification happens in the open-source core against anchors
//! in `/etc/ibexwall/trust/*.pub`, with expiry and anti-rollback checks.
//! Time validation itself lands with the policy engine (F11); here we
//! validate structure only.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const POLICY_SCHEMA: &str = "com.ibexwall.policy/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrgIdentity {
    pub id: String,
    pub name: String,
}

/// Which sections the generated report may include. The report schema has
/// no fields for browsing/DNS history, files, screen, passwords or
/// keystrokes (spec §4.14).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ReportSpec {
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleSignature {
    pub alg: String,
    pub key_id: String,
    /// ed25519 over JCS(bundle without `signature`), base64.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub schema: String,
    pub org: OrgIdentity,
    pub version: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub settings: Value,
    #[serde(default)]
    pub locks: Vec<String>,
    #[serde(default)]
    pub report: ReportSpec,
    /// Detached for the signed representation (JCS excludes this field).
    #[serde(default)]
    pub signature: Option<BundleSignature>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PolicyError {
    #[error("expected schema `{0}`, got `{1}`")]
    InvalidSchema(String, String),
    #[error("version must be >= 1, got {0}")]
    InvalidVersion(u64),
    #[error("org.id must be non-empty")]
    EmptyOrgId,
    #[error("invalid lock pattern `{0}` (allowed: [a-z0-9.*_-])")]
    InvalidLock(String),
    #[error("timestamps must be non-empty RFC 3339 strings")]
    InvalidTimestamps,
}

impl PolicyBundle {
    /// Structural validation; signature and time checks live in the core.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != POLICY_SCHEMA {
            return Err(PolicyError::InvalidSchema(
                POLICY_SCHEMA.into(),
                self.schema.clone(),
            ));
        }
        if self.version < 1 {
            return Err(PolicyError::InvalidVersion(self.version));
        }
        if self.org.id.is_empty() {
            return Err(PolicyError::EmptyOrgId);
        }
        if self.issued_at.is_empty() || self.expires_at.is_empty() {
            return Err(PolicyError::InvalidTimestamps);
        }
        for lock in &self.locks {
            let valid = !lock.is_empty()
                && lock.chars().all(|c| {
                    c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || matches!(c, '.' | '*' | '_' | '-')
                });
            if !valid {
                return Err(PolicyError::InvalidLock(lock.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PolicyBundle {
        serde_json::from_value(serde_json::json!({
            "schema": "com.ibexwall.policy/v1",
            "org": { "id": "acme", "name": "Acme Tecnologia" },
            "version": 42,
            "issued_at": "2026-11-01T12:00:00Z",
            "expires_at": "2026-12-01T12:00:00Z",
            "settings": {
                "net.dns": { "upstream": "https://dns.acme.internal/dns-query" },
                "net.apps": { "unknown_apps": "ask" }
            },
            "locks": ["net.dns.upstream", "net.apps.unknown_apps"],
            "report": { "include": ["posture", "findings"] }
        }))
        .unwrap()
    }

    #[test]
    fn parses_the_reference_bundle() {
        sample().validate().expect("reference bundle is valid");
    }

    #[test]
    fn rejects_wrong_schema_tag() {
        let mut bundle = sample();
        bundle.schema = "com.ibexwall.policy/v9".into();
        assert_eq!(
            bundle.validate(),
            Err(PolicyError::InvalidSchema(
                POLICY_SCHEMA.into(),
                "com.ibexwall.policy/v9".into()
            ))
        );
    }

    #[test]
    fn rejects_invalid_lock_patterns() {
        let mut bundle = sample();
        bundle.locks.push("Net.DNS".into());
        assert_eq!(
            bundle.validate(),
            Err(PolicyError::InvalidLock("Net.DNS".into()))
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let value = serde_json::json!({
            "schema": "com.ibexwall.policy/v1",
            "org": { "id": "acme", "name": "acme" },
            "version": 1,
            "issued_at": "2026-11-01T12:00:00Z",
            "expires_at": "2026-12-01T12:00:00Z",
            "settings": {},
            "exfiltrate": true
        });
        assert!(serde_json::from_value::<PolicyBundle>(value).is_err());
    }
}
