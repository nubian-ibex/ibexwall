// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Compliance report (spec §4.14, F11).
//!
//! Privacy by schema: there are intentionally NO fields for browsing or
//! DNS history, files, screen contents, passwords or keystrokes. The
//! "Organization" screen displays exactly the last generated report.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::{HistoryEntry, ProtectionStatus};

pub const REPORT_SCHEMA: &str = "com.ibexwall.report/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppCount {
    pub app: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BlockedConnectionsSummary {
    pub total_24h: u64,
    #[serde(default)]
    pub top_apps: Vec<AppCount>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub schema: String,
    pub generated_at: String,
    #[serde(default)]
    pub policy_version: Option<u64>,
    pub score: u8,
    pub protections: Vec<ProtectionStatus>,
    pub findings_open: u32,
    #[serde(default)]
    pub findings_by_severity: BTreeMap<String, u32>,
    #[serde(default)]
    pub blocked_connections: Option<BlockedConnectionsSummary>,
    #[serde(default)]
    pub change_audit: Vec<HistoryEntry>,
    #[serde(default)]
    pub package_versions: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ReportError {
    #[error("expected schema `{0}`, got `{1}`")]
    InvalidSchema(String, String),
}

impl Report {
    pub fn validate(&self) -> Result<(), ReportError> {
        if self.schema != REPORT_SCHEMA {
            return Err(ReportError::InvalidSchema(
                REPORT_SCHEMA.into(),
                self.schema.clone(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_validate() {
        let report = Report {
            schema: REPORT_SCHEMA.into(),
            generated_at: "2026-11-01T12:00:00Z".into(),
            policy_version: Some(42),
            score: 87,
            protections: vec![],
            findings_open: 2,
            findings_by_severity: BTreeMap::from([("medium".into(), 2)]),
            blocked_connections: Some(BlockedConnectionsSummary {
                total_24h: 118,
                top_apps: vec![AppCount {
                    app: "container:evil".into(),
                    count: 118,
                }],
            }),
            change_audit: vec![],
            package_versions: BTreeMap::from([("ibexwall".into(), "0.1.0".into())]),
        };
        let value = serde_json::to_value(&report).unwrap();
        let back: Report = serde_json::from_value(value).unwrap();
        assert_eq!(report, back);
        report.validate().unwrap();
    }

    #[test]
    fn rejects_wrong_schema_tag() {
        let mut report = Report {
            schema: "wrong".into(),
            generated_at: "2026-11-01T12:00:00Z".into(),
            policy_version: None,
            score: 0,
            protections: vec![],
            findings_open: 0,
            findings_by_severity: BTreeMap::new(),
            blocked_connections: None,
            change_audit: vec![],
            package_versions: BTreeMap::new(),
        };
        assert!(report.validate().is_err());
        report.schema = REPORT_SCHEMA.into();
        report.validate().unwrap();
    }
}
