// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Compliance types (F11a): a framework's profile of controls, the
//! per-control result the core computes from the stored check results,
//! and the attestations and exceptions that a person adds. The profiles
//! themselves are data shipped by the `ibexwall-profiles` repository.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::types::CheckResult;

/// A citation for a control: the clause or article id, its URL and the
/// date it was consulted. The shared `Reference` type (framework, id) is
/// for findings; profiles carry their own shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileReference {
    pub id: String,
    pub url: String,
    pub date: String,
}

/// A framework's profile: a named set of controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceProfile {
    pub framework: String,
    pub version: String,
    pub controls: Vec<Control>,
}

/// Whether a control is decided by the machine or by a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Automated,
    Attestation,
}

/// One control: what it requires, and for an automated one the check ids
/// that prove it. `references` cite the framework clause or article.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub control_id: String,
    pub title: String,
    pub kind: ControlKind,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub references: Vec<ProfileReference>,
}

/// The state of one control after evaluation. `NotAssessed` is never a
/// pass: a control with a missing, stale or unknown check lands here, so
/// a report that cannot prove a control never claims it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    NotAssessed,
    NeedsAttestation,
    NotApplicable,
    Excepted,
}

/// One control's verdict and the checks that decided it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ControlResult {
    pub control_id: String,
    /// The control's own wording, so the report stands alone.
    pub title: String,
    pub status: ComplianceStatus,
    #[serde(default)]
    pub checks: Vec<CheckResult>,
}

/// The whole evaluation of one profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ComplianceReport {
    pub framework: String,
    pub version: String,
    pub evaluated_at: String,
    pub controls: Vec<ControlResult>,
}

/// A person's attestation that an organizational control holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub control_id: String,
    pub owner: String,
    pub statement: String,
    /// Unix seconds; `None` means it never expires.
    pub expires_at: Option<i64>,
}

/// An accepted risk: overrides a control's state until it expires. Shown
/// apart and never counted as compliant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub control_id: String,
    pub owner: String,
    pub justification: String,
    pub expires_at: i64,
}
