// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! IbexWall public contracts: API types, typed operations, the plugin
//! manifest, the managed-mode policy bundle, the report, and the canonical
//! `names` module.
//!
//! This crate is the single source of truth for every contract that crosses
//! a process boundary (client/core, core/plugin, policy provider/core).
//! `cargo xtask schemas` exports JSON Schemas and the varlink IDL from
//! these types to `spec/`; CI fails when the committed files drift.
//!
//! Dual-licensed Apache-2.0 OR MIT so that third-party and proprietary
//! plugins may link it. It must never depend on GPL-only crates.

pub mod compliance;
pub mod names;
pub mod op;
pub mod plugin;
pub mod policy;
pub mod report;
pub mod types;

pub use compliance::{
    Attestation, ComplianceProfile, ComplianceReport, ComplianceStatus, Control, ControlKind,
    ControlResult, Exception,
};
pub use op::{Op, Reversible, RiskFlag, UnitAction};
pub use plugin::{ExecAllow, Manifest, ManifestError, PluginKind, PluginOrigin, SandboxUser};
pub use policy::{PolicyBundle, PolicyError};
pub use report::{BlockedConnectionsSummary, Report, ReportError};
pub use types::{
    AppDestination, AppEntry, CheckOutcome, CheckReport, CheckResult, DnsStatus, Event, Finding,
    FindingStatus, FirewallNetwork, FirewallPort, FirewallState, HistoryEntry, Info, MonitorStatus,
    OpPreview, Plan, PluginInfo, Posture, Prompt, Proposal, ProposalStatus, ProtectionStatus,
    Reference, Remediation, Severity, Transaction, TransactionState, posture_score,
};

/// Schema export support used by `cargo xtask schemas`.
pub mod export {
    use serde_json::Value;

    macro_rules! schema_exports {
        ($($name:literal => $ty:ty),* $(,)?) => {
            /// All exported contract types in canonical order:
            /// `(type name, JSON Schema)`.
            pub fn schemas() -> Vec<(&'static str, Value)> {
                vec![
                    $(
                        (
                            $name,
                            serde_json::to_value(schemars::schema_for!($ty))
                                .expect("schema serialization cannot fail"),
                        )
                    ),*
                ]
            }
        };
    }

    schema_exports! {
        "Severity" => crate::types::Severity,
        "RiskFlag" => crate::op::RiskFlag,
        "Reversible" => crate::op::Reversible,
        "UnitAction" => crate::op::UnitAction,
        "Op" => crate::op::Op,
        "Info" => crate::types::Info,
        "ProtectionStatus" => crate::types::ProtectionStatus,
        "Posture" => crate::types::Posture,
        "DnsStatus" => crate::types::DnsStatus,
        "FirewallNetwork" => crate::types::FirewallNetwork,
        "FirewallPort" => crate::types::FirewallPort,
        "FirewallState" => crate::types::FirewallState,
        "MonitorStatus" => crate::types::MonitorStatus,
        "AppEntry" => crate::types::AppEntry,
        "AppDestination" => crate::types::AppDestination,
        "Prompt" => crate::types::Prompt,
        "Reference" => crate::types::Reference,
        "Remediation" => crate::types::Remediation,
        "FindingStatus" => crate::types::FindingStatus,
        "Finding" => crate::types::Finding,
        "CheckOutcome" => crate::types::CheckOutcome,
        "CheckResult" => crate::types::CheckResult,
        "CheckReport" => crate::types::CheckReport,
        "ComplianceProfile" => crate::compliance::ComplianceProfile,
        "ControlKind" => crate::compliance::ControlKind,
        "Control" => crate::compliance::Control,
        "ComplianceStatus" => crate::compliance::ComplianceStatus,
        "ControlResult" => crate::compliance::ControlResult,
        "ComplianceReport" => crate::compliance::ComplianceReport,
        "Attestation" => crate::compliance::Attestation,
        "Exception" => crate::compliance::Exception,
        "PluginOrigin" => crate::plugin::PluginOrigin,
        "PluginKind" => crate::plugin::PluginKind,
        "PluginInfo" => crate::types::PluginInfo,
        "OpPreview" => crate::types::OpPreview,
        "Plan" => crate::types::Plan,
        "TransactionState" => crate::types::TransactionState,
        "Transaction" => crate::types::Transaction,
        "HistoryEntry" => crate::types::HistoryEntry,
        "Event" => crate::types::Event,
        "ProposalStatus" => crate::types::ProposalStatus,
        "Proposal" => crate::types::Proposal,
        "Manifest" => crate::plugin::Manifest,
        "PolicyBundle" => crate::policy::PolicyBundle,
        "Report" => crate::report::Report,
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn schema_export_is_deterministic() {
            let a = super::schemas();
            let b = super::schemas();
            assert_eq!(a.len(), b.len());
            for ((na, va), (nb, vb)) in a.iter().zip(b.iter()) {
                assert_eq!(na, nb);
                assert_eq!(va, vb, "schema for {na} changed between calls");
            }
        }

        #[test]
        fn schema_export_covers_all_contract_groups() {
            let names: Vec<&str> = super::schemas().iter().map(|(n, _)| *n).collect();
            for expected in ["Severity", "Op", "Manifest", "PolicyBundle", "Report"] {
                assert!(names.contains(&expected), "missing {expected}");
            }
            assert!(names.len() >= 25);
        }
    }
}
