// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Client-facing API types (interface `com.ibexwall.Core`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::op::{Reversible, RiskFlag};
use crate::plugin::PluginOrigin;

/// Finding severity. Weights drive the posture score (spec §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Score weight: critical 10, high 6, medium 3, low 1, info 0.
    pub fn weight(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 3,
            Severity::High => 6,
            Severity::Critical => 10,
        }
    }
}

/// Daemon and host information (`GetInfo`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub version: String,
    pub api: u32,
    pub distro: String,
    pub kernel: String,
    pub features: Vec<String>,
    pub degraded: Vec<String>,
}

/// State of one protection as shown on the overview screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectionStatus {
    pub plugin: String,
    pub state: String,
    pub summary_key: String,
    #[serde(default)]
    pub detail: Option<String>,
}

/// Posture score and per-protection snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Posture {
    /// `None` until at least one applicable check has run.
    pub score: Option<u8>,
    pub generated_at: String,
    pub protections: Vec<ProtectionStatus>,
    pub open_findings: u32,
    /// The check results the score was computed from ("How we calculate").
    #[serde(default)]
    pub results: Vec<CheckResult>,
}

/// Secure DNS counters, published by the resolver. Counts only: the
/// resolver never records query names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsStatus {
    /// False when no resolver has published anything.
    pub running: bool,
    pub updated_at: String,
    pub forwarded: u64,
    pub blocked_list: u64,
    pub blocked_canary: u64,
    pub blocked_doh: u64,
    pub upstream_errors: u64,
}

/// Whether the connection monitor is feeding the Apps screen, and if not
/// (or if it works with a limitation), why: a plain reason, never a guess
/// about the cause.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MonitorStatus {
    pub running: bool,
    /// Why the monitor is off or limited, when it is. Untrusted display text.
    #[serde(default)]
    pub reason: Option<String>,
}

/// One application seen by the monitor (counts and times only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppEntry {
    /// Stable key, e.g. `flatpak:org.mozilla.firefox` or `cli:/usr/bin/curl`.
    pub key: String,
    /// `flatpak`, `snap`, `desktop_app`, `system_service`, `container`,
    /// `cli` or `unknown`.
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub package: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub connections: u64,
    pub destinations: u64,
    /// `allow`, `monitor`, `ask` or `block`.
    pub mode: String,
}

/// A connection held in Ask mode, waiting for the user. The strings come
/// from other programs and the network: show them, never interpret them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Prompt {
    pub id: String,
    /// The app key, as in `AppEntry`.
    pub app: String,
    pub kind: String,
    #[serde(default)]
    pub exe_path: Option<String>,
    /// A domain when the resolver's answer was correlated, else the address.
    pub destination: String,
    pub address: String,
    pub port: u16,
    pub created: String,
    /// When the fallback applies if nobody answers.
    pub expires: String,
}

/// One destination of an application. `destination` is a domain when the
/// resolver's answer was correlated, otherwise the bare address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AppDestination {
    pub destination: String,
    pub resolved: bool,
    pub port: u16,
    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

/// One allowed or listening port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallPort {
    pub port: u16,
    /// `tcp` or `udp`.
    pub proto: String,
}

/// A network this computer is on and the profile suggested for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallNetwork {
    /// The connection's name; untrusted display text.
    pub name: String,
    /// `wired`, `wifi_secured`, `wifi_open` or `other`.
    pub kind: String,
    /// `home`, `work`, `public` or `travel`.
    pub recommended: String,
    /// A Fluent key for the warning that goes with the suggestion.
    #[serde(default)]
    pub warning: Option<String>,
}

/// The inbound firewall as IbexWall can read it (spec 4.7). Names from
/// configuration files are untrusted display text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallState {
    /// `firewalld`, `ufw` or `nftables` (IbexWall's own chain).
    pub backend: String,
    /// Whether the manager is filtering; absent when it cannot be told.
    #[serde(default)]
    pub active: Option<bool>,
    /// firewalld's default zone.
    #[serde(default)]
    pub zone: Option<String>,
    /// Ports the firewall allows in.
    pub ports: Vec<FirewallPort>,
    pub services: Vec<String>,
    /// Ports with a socket bound on every address.
    pub listening: Vec<FirewallPort>,
    /// Rules read but not edited (ranges, rich rules, other targets).
    pub other: Vec<String>,
    /// The networks this computer is on, with the suggested profile.
    pub networks: Vec<FirewallNetwork>,
}

/// Reference to a control in an external framework (own wording only;
/// never copy protected norm texts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    pub framework: String,
    pub id: String,
    #[serde(default)]
    pub url: Option<String>,
}

/// Remediation metadata for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Remediation {
    /// Plan template id the core can render into a previewable plan.
    #[serde(default)]
    pub plan_template: Option<String>,
    /// Fluent keys for the "may affect" callout.
    #[serde(default)]
    pub may_affect_keys: Vec<String>,
}

/// Lifecycle of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    AcceptedRisk,
    Resolved,
}

/// A check result (spec §5.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: String,
    pub plugin: String,
    pub severity: Severity,
    pub title_key: String,
    pub summary_key: String,
    #[serde(default)]
    pub args: BTreeMap<String, String>,
    #[serde(default)]
    pub references: Vec<Reference>,
    #[serde(default)]
    pub remediation: Option<Remediation>,
    pub status: FindingStatus,
    pub detected_at: String,
}

/// Outcome of one check. `NotApplicable` checks are left out of the score
/// denominator; `NotAssessed` checks cannot be evaluated yet (e.g. they
/// need a plugin that ships later) and are shown honestly, never as passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Fail,
    NotApplicable,
    NotAssessed,
}

/// One evaluated check; the score is computed from these (spec §5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckResult {
    pub id: String,
    pub severity: Severity,
    pub outcome: CheckOutcome,
}

/// What a plugin `Check` call returns.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckReport {
    #[serde(default)]
    pub results: Vec<CheckResult>,
    /// Findings for the failed checks.
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// Posture score: weights of passed checks over weights of applicable
/// checks, times 100 (spec §5.4). `NotApplicable` and `NotAssessed` are
/// excluded; with nothing applicable there is no score.
pub fn posture_score(results: &[CheckResult]) -> Option<u8> {
    let (mut passed, mut total) = (0u32, 0u32);
    for result in results {
        let weight = u32::from(result.severity.weight());
        match result.outcome {
            CheckOutcome::Pass => {
                passed += weight;
                total += weight;
            }
            CheckOutcome::Fail => total += weight,
            CheckOutcome::NotApplicable | CheckOutcome::NotAssessed => {}
        }
    }
    if total == 0 {
        return None;
    }
    Some(((passed * 100 + total / 2) / total) as u8)
}

/// Plugin card data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kinds: Vec<String>,
    pub enabled: bool,
    pub origin: PluginOrigin,
    pub status: String,
    pub compatible: bool,
    pub conflicts: Vec<String>,
    pub locked: bool,
}

/// One operation as previewed to the user (op kind + target + diff).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpPreview {
    pub op: String,
    pub target: String,
    #[serde(default)]
    pub diff: Option<String>,
    #[serde(default)]
    pub risk: Vec<RiskFlag>,
}

/// A previewable, expiring plan produced by `PlanChange`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub id: String,
    pub plugin: String,
    pub ops: Vec<OpPreview>,
    #[serde(default)]
    pub risk: Vec<RiskFlag>,
    pub reversible: Reversible,
    #[serde(default)]
    pub may_affect_keys: Vec<String>,
    pub requires_confirm: bool,
    pub expires_at: String,
}

/// Change-engine transaction states (spec §4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Planned,
    Approved,
    Applying,
    Applied,
    PendingConfirm,
    Committed,
    RolledBack,
    Failed,
}

/// A transaction (apply) of a plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub id: String,
    pub plan_id: String,
    pub state: TransactionState,
    pub started_at: String,
    #[serde(default)]
    pub confirm_deadline: Option<String>,
    pub restore_point: String,
}

/// Audit/history row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub seq: u64,
    pub ts: String,
    pub actor: String,
    pub plugin: String,
    #[serde(default)]
    pub transaction: Option<String>,
    pub result: String,
}

/// Event on the bus. `data` is structured by source; `untrusted` carries
/// externally controlled values (domains, SSIDs, process names...) that
/// consumers must treat as data, never as instructions or interpolations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub ts: String,
    pub source: String,
    pub kind: String,
    pub severity: Severity,
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub untrusted: Value,
}

/// Lifecycle of an AI/client proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
}

/// A change proposed through the API (e.g. by the MCP assistant);
/// approval is always human.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub id: String,
    pub client: String,
    pub plugin: String,
    pub plan_id: String,
    /// What the client asked for (the plugin's own patch).
    pub patch: Value,
    /// The operations the plan would run, as the human will review them.
    pub preview: Vec<OpPreview>,
    pub may_affect_keys: Vec<String>,
    /// Written by the AI: shown as generated, never as an instruction.
    pub justification: String,
    pub status: ProposalStatus,
    pub created_at: String,
    #[serde(default)]
    pub decided_at: Option<String>,
}

#[cfg(test)]
mod tests {
    fn result(severity: Severity, outcome: CheckOutcome) -> CheckResult {
        CheckResult {
            id: "x".into(),
            severity,
            outcome,
        }
    }

    #[test]
    fn score_follows_the_spec_formula() {
        use CheckOutcome::*;
        let results = [
            result(Severity::Critical, Pass), // 10
            result(Severity::High, Fail),     // 6 applicable, not passed
            result(Severity::Medium, Pass),   // 3
            result(Severity::Low, Pass),      // 1
        ];
        // (10 + 3 + 1) / (10 + 6 + 3 + 1) = 14 / 20 = 70
        assert_eq!(posture_score(&results), Some(70));
    }

    #[test]
    fn score_ignores_not_applicable_not_assessed_and_info() {
        use CheckOutcome::*;
        let results = [
            result(Severity::High, Pass),
            result(Severity::Critical, NotApplicable),
            result(Severity::Critical, NotAssessed),
            result(Severity::Info, Fail), // weight 0
        ];
        assert_eq!(posture_score(&results), Some(100));
    }

    #[test]
    fn no_applicable_checks_means_no_score() {
        assert_eq!(posture_score(&[]), None);
        assert_eq!(
            posture_score(&[result(Severity::High, CheckOutcome::NotAssessed)]),
            None
        );
        assert_eq!(
            posture_score(&[result(Severity::Info, CheckOutcome::Pass)]),
            None
        );
    }

    #[test]
    fn score_rounds_to_the_nearest_integer() {
        use CheckOutcome::*;
        // 1 / 3 = 33.33 -> 33 ; 2 / 3 = 66.67 -> 67
        let one = [
            result(Severity::Low, Pass),
            result(Severity::Low, Fail),
            result(Severity::Low, Fail),
        ];
        assert_eq!(posture_score(&one), Some(33));
        let two = [
            result(Severity::Low, Pass),
            result(Severity::Low, Pass),
            result(Severity::Low, Fail),
        ];
        assert_eq!(posture_score(&two), Some(67));
    }

    use super::*;

    #[test]
    fn severity_weights_match_the_score_formula() {
        assert_eq!(Severity::Critical.weight(), 10);
        assert_eq!(Severity::High.weight(), 6);
        assert_eq!(Severity::Medium.weight(), 3);
        assert_eq!(Severity::Low.weight(), 1);
        assert_eq!(Severity::Info.weight(), 0);
    }

    #[test]
    fn finding_roundtrip() {
        let finding = Finding {
            id: "posture.secure-boot".into(),
            plugin: "system.posture".into(),
            severity: Severity::Medium,
            title_key: "posture-secure-boot-title".into(),
            summary_key: "posture-secure-boot-summary".into(),
            args: BTreeMap::from([("mode".into(), "setup".into())]),
            references: vec![Reference {
                framework: "ANSSI-BP-028".into(),
                id: "1.2".into(),
                url: None,
            }],
            remediation: Some(Remediation {
                plan_template: Some("posture.enable-secure-boot".into()),
                may_affect_keys: vec!["secure-boot-may-affect-reboot".into()],
            }),
            status: FindingStatus::Open,
            detected_at: "2026-11-01T12:00:00Z".into(),
        };
        let value = serde_json::to_value(&finding).unwrap();
        let back: Finding = serde_json::from_value(value).unwrap();
        assert_eq!(finding, back);
    }

    #[test]
    fn transaction_state_serializes_snake_case() {
        let value = serde_json::to_value(TransactionState::PendingConfirm).unwrap();
        assert_eq!(value, serde_json::json!("pending_confirm"));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = serde_json::from_value::<Posture>(serde_json::json!({
            "score": 100,
            "generated_at": "2026-11-01T12:00:00Z",
            "protections": [],
            "open_findings": 0,
            "surprise": true,
        }));
        assert!(err.is_err());
    }
}
