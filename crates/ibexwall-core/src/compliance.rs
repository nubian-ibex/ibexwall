// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Compliance evaluation (F11a): a pure function from the stored check
//! results, the profile and the attestations and exceptions to one state
//! per control. There is no plugin and no system effect here; a report
//! only ever reads what the plugins already measured.

use std::collections::BTreeMap;

use ibexwall_proto::{
    Attestation, CheckOutcome, CheckResult, ComplianceProfile, ComplianceReport, ComplianceStatus,
    Control, ControlKind, ControlResult, Exception, Severity,
};

/// A check result with the last time it ran (Unix seconds), for the
/// freshness rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCheck {
    pub id: String,
    pub severity: Severity,
    pub outcome: CheckOutcome,
    pub checked_at: i64,
}

/// A check older than this cannot prove a control and makes it
/// not-assessed, never a pass.
pub const STALE_AFTER_SECS: i64 = 7 * 86_400;

/// Evaluates a profile against the stored checks, attestations and
/// exceptions. Pure: the same inputs give the same report.
pub fn evaluate(
    profile: &ComplianceProfile,
    checks: &[StoredCheck],
    attestations: &[Attestation],
    exceptions: &[Exception],
    now: i64,
    stale_after: i64,
) -> ComplianceReport {
    // The latest result wins when two plugins report the same id.
    let checks_by_id: BTreeMap<&str, &StoredCheck> =
        checks.iter().map(|c| (c.id.as_str(), c)).collect();
    let attestations_by_id: BTreeMap<&str, &Attestation> = attestations
        .iter()
        .map(|a| (a.control_id.as_str(), a))
        .collect();
    let exceptions_by_id: BTreeMap<&str, &Exception> = exceptions
        .iter()
        .map(|e| (e.control_id.as_str(), e))
        .collect();

    let controls = profile
        .controls
        .iter()
        .map(|control| {
            evaluate_control(
                control,
                &checks_by_id,
                &attestations_by_id,
                &exceptions_by_id,
                now,
                stale_after,
            )
        })
        .collect();

    ComplianceReport {
        framework: profile.framework.clone(),
        version: profile.version.clone(),
        evaluated_at: ibexwall_sys::format_rfc3339(now),
        controls,
    }
}

fn evaluate_control(
    control: &Control,
    checks: &BTreeMap<&str, &StoredCheck>,
    attestations: &BTreeMap<&str, &Attestation>,
    exceptions: &BTreeMap<&str, &Exception>,
    now: i64,
    stale_after: i64,
) -> ControlResult {
    // An active exception overrides every other state; an expired one
    // falls through to the real evaluation.
    if let Some(exception) = exceptions.get(control.control_id.as_str())
        && exception.expires_at > now
    {
        return ControlResult {
            control_id: control.control_id.clone(),
            title: control.title.clone(),
            status: ComplianceStatus::Excepted,
            checks: Vec::new(),
        };
    }

    match control.kind {
        ControlKind::Attestation => {
            let status = match attestations.get(control.control_id.as_str()) {
                Some(attestation) if attestation.expires_at.is_none_or(|e| e > now) => {
                    ComplianceStatus::Compliant
                }
                _ => ComplianceStatus::NeedsAttestation,
            };
            ControlResult {
                control_id: control.control_id.clone(),
                title: control.title.clone(),
                status,
                checks: Vec::new(),
            }
        }
        ControlKind::Automated => {
            // Resolve every required check; a check that is absent or
            // stale becomes not-assessed so it can never read as a pass.
            let mut resolved = Vec::with_capacity(control.checks.len());
            for id in &control.checks {
                match checks.get(id.as_str()) {
                    None => resolved.push(CheckResult {
                        id: id.clone(),
                        severity: Severity::High,
                        outcome: CheckOutcome::NotAssessed,
                    }),
                    Some(check) if check.checked_at + stale_after < now => {
                        resolved.push(CheckResult {
                            id: id.clone(),
                            severity: check.severity,
                            outcome: CheckOutcome::NotAssessed,
                        })
                    }
                    Some(check) => resolved.push(CheckResult {
                        id: id.clone(),
                        severity: check.severity,
                        outcome: check.outcome,
                    }),
                }
            }
            let applicable: Vec<&CheckResult> = resolved
                .iter()
                .filter(|r| r.outcome != CheckOutcome::NotApplicable)
                .collect();
            let status = if resolved.is_empty() {
                ComplianceStatus::NotAssessed
            } else if applicable.is_empty() {
                ComplianceStatus::NotApplicable
            } else if applicable.iter().any(|r| r.outcome == CheckOutcome::Fail) {
                ComplianceStatus::NonCompliant
            } else if applicable
                .iter()
                .any(|r| r.outcome == CheckOutcome::NotAssessed)
            {
                ComplianceStatus::NotAssessed
            } else {
                ComplianceStatus::Compliant
            };
            ControlResult {
                control_id: control.control_id.clone(),
                title: control.title.clone(),
                status,
                checks: resolved,
            }
        }
    }
}

/// Unix seconds from a fixed-width `YYYY-MM-DDTHH:MM:SSZ` timestamp, the
/// shape `ibexwall_sys::format_rfc3339` produces.
pub(crate) fn parse_unix(ts: &str) -> i64 {
    let bytes = ts.as_bytes();
    if bytes.len() < 19 {
        return 0;
    }
    let year: i64 = ts[0..4].parse().unwrap_or(1970);
    let month: i64 = ts[5..7].parse().unwrap_or(1);
    let day: i64 = ts[8..10].parse().unwrap_or(1);
    let hour: i64 = ts[11..13].parse().unwrap_or(0);
    let minute: i64 = ts[14..16].parse().unwrap_or(0);
    let second: i64 = ts[17..19].parse().unwrap_or(0);
    days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// The export schema marker.
pub const EXPORT_SCHEMA: &str = "com.ibexwall.compliance.export/v1";

/// The device signing key, generated once and stored in the state dir as
/// a 0600 file: the secret never leaves the machine.
fn load_or_create_key(state_dir: &std::path::Path) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use std::io::{Read as _, Write as _};
    let path = state_dir.join("compliance.key");
    let secret: [u8; 32] = match std::fs::read(&path) {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("the compliance key is corrupt"))?,
        Err(_) => {
            let mut bytes = [0u8; 32];
            std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            std::fs::create_dir_all(state_dir)?;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&bytes)?;
            bytes
        }
    };
    Ok(ed25519_dalek::SigningKey::from_bytes(&secret))
}

/// A signed export: the report, the attestations, the exceptions and the
/// audit-chain head, sealed by the device key so a tampered copy fails
/// verification.
pub fn signed_envelope(
    state_dir: &std::path::Path,
    report: &ComplianceReport,
    attestations: &[Attestation],
    exceptions: &[Exception],
    audit_head: &str,
    now: i64,
) -> anyhow::Result<serde_json::Value> {
    use ed25519_dalek::Signer as _;
    let key = load_or_create_key(state_dir)?;
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let mut envelope = serde_json::json!({
        "schema": EXPORT_SCHEMA,
        "signed_at": ibexwall_sys::format_rfc3339(now),
        "report": report,
        "attestations": attestations,
        "exceptions": exceptions,
        "audit_head": audit_head,
        "public_key": public_key,
    });
    let payload = serde_jcs::to_vec(&envelope)?;
    let signature = key.sign(&payload);
    envelope["signature"] = serde_json::Value::String(hex::encode(signature.to_bytes()));
    Ok(envelope)
}

/// Verifies a signed envelope. Returns an error when the signature does
/// not cover the payload (tamper) or the schema is not ours.
pub fn verify_envelope(value: &serde_json::Value) -> Result<(), String> {
    use ed25519_dalek::Verifier as _;
    if value.get("schema").and_then(|s| s.as_str()) != Some(EXPORT_SCHEMA) {
        return Err("the export is not an IbexWall compliance export".into());
    }
    let signature = value
        .get("signature")
        .and_then(|s| s.as_str())
        .ok_or("missing signature")?;
    let public_key = value
        .get("public_key")
        .and_then(|s| s.as_str())
        .ok_or("missing public key")?;
    let mut payload = value.clone();
    payload.as_object_mut().map(|o| o.remove("signature"));
    let bytes = serde_jcs::to_vec(&payload).map_err(|e| e.to_string())?;
    let sig_bytes: [u8; 64] = hex::decode(signature)
        .map_err(|_| "bad signature encoding")?
        .try_into()
        .map_err(|_| "bad signature length")?;
    let key_bytes: [u8; 32] = hex::decode(public_key)
        .map_err(|_| "bad key encoding")?
        .try_into()
        .map_err(|_| "bad key length")?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| "bad public key")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    key.verify(&bytes, &sig)
        .map_err(|_| "the signature does not cover the report".to_string())
}

/// CSV: one row per control, with the status as a snake_case string.
pub fn csv(report: &ComplianceReport) -> String {
    let mut out = String::from("control_id,title,status\n");
    for control in &report.controls {
        let status = serde_json::to_value(control.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        out.push_str(&format!(
            "\"{}\",\"{}\",\"{}\"\n",
            control.control_id,
            control.title.replace('\"', "\'"),
            status
        ));
    }
    out
}

/// A minimal OSCAL assessment-results document (best effort; the official
/// NIST schema is not yet validated here).
pub fn oscal(report: &ComplianceReport, now: i64) -> serde_json::Value {
    let findings: Vec<serde_json::Value> = report
        .controls
        .iter()
        .enumerate()
        .map(|(i, control)| {
            let status = serde_json::to_value(control.status)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            serde_json::json!({
                "uuid": format!("f{:032x}", i + 1),
                "title": control.title,
                "description": format!("state: {status}"),
                "target": { "type": "statement-id", "target-id": control.control_id },
            })
        })
        .collect();
    let control_ids: Vec<serde_json::Value> = report
        .controls
        .iter()
        .map(|c| serde_json::json!({ "control-id": c.control_id }))
        .collect();
    serde_json::json!({
        "assessment-results": {
            "uuid": format!("a{:032x}", 1),
            "metadata": {
                "title": format!("IbexWall compliance report for {} {}", report.framework, report.version),
                "last-modified": ibexwall_sys::format_rfc3339(now),
                "version": "1.0",
                "oscal-version": "1.1.3",
            },
            "results": [{
                "uuid": format!("r{:032x}", 1),
                "title": "IbexWall compliance report",
                "description": "Technical controls evaluated against the machine's state. A result of not-assessed or needs-attestation is not a pass.",
                "start": report.evaluated_at,
                "findings": findings,
                "reviewed-controls": {
                    "control-selections": [{ "include-controls": control_ids }],
                },
            }],
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(id: &str, outcome: CheckOutcome, age: i64) -> StoredCheck {
        StoredCheck {
            id: id.into(),
            severity: Severity::Medium,
            outcome,
            checked_at: 1_000 - age,
        }
    }

    fn control(control_id: &str, kind: ControlKind, checks: &[&str]) -> Control {
        Control {
            control_id: control_id.into(),
            title: "c".into(),
            kind,
            checks: checks.iter().map(|s| s.to_string()).collect(),
            references: Vec::new(),
        }
    }

    fn profile(controls: Vec<Control>) -> ComplianceProfile {
        ComplianceProfile {
            framework: "test".into(),
            version: "1".into(),
            controls,
        }
    }

    const NOW: i64 = 1_000;

    #[test]
    fn a_control_is_compliant_only_when_every_required_check_passes_fresh() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a", "b"])]);
        let checks = vec![
            stored("a", CheckOutcome::Pass, 10),
            stored("b", CheckOutcome::Pass, 10),
        ];
        let report = evaluate(&p, &checks, &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::Compliant);
    }

    #[test]
    fn a_failed_check_is_non_compliant() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a"])]);
        let checks = vec![stored("a", CheckOutcome::Fail, 10)];
        let report = evaluate(&p, &checks, &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::NonCompliant);
    }

    #[test]
    fn a_missing_check_is_not_assessed_never_a_pass() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a", "b"])]);
        let checks = vec![stored("a", CheckOutcome::Pass, 10)];
        let report = evaluate(&p, &checks, &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::NotAssessed);
    }

    #[test]
    fn a_stale_check_is_not_assessed_never_a_pass() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a"])]);
        let checks = vec![stored("a", CheckOutcome::Pass, STALE_AFTER_SECS + 1)];
        let report = evaluate(&p, &checks, &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::NotAssessed);
    }

    #[test]
    fn all_not_applicable_is_not_applicable() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a", "b"])]);
        let checks = vec![
            stored("a", CheckOutcome::NotApplicable, 10),
            stored("b", CheckOutcome::NotApplicable, 10),
        ];
        let report = evaluate(&p, &checks, &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::NotApplicable);
    }

    #[test]
    fn a_not_assessed_check_is_not_assessed_even_with_passing_siblings() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a", "b"])]);
        let checks = vec![
            stored("a", CheckOutcome::Pass, 10),
            stored("b", CheckOutcome::NotAssessed, 10),
        ];
        let report = evaluate(&p, &checks, &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::NotAssessed);
    }

    #[test]
    fn an_attestation_control_needs_attestation_until_one_is_recorded() {
        let p = profile(vec![control("c1", ControlKind::Attestation, &[])]);
        let report = evaluate(&p, &[], &[], &[], NOW, STALE_AFTER_SECS);
        assert_eq!(
            report.controls[0].status,
            ComplianceStatus::NeedsAttestation
        );
        let attestations = vec![Attestation {
            control_id: "c1".into(),
            owner: "o".into(),
            statement: "s".into(),
            expires_at: None,
        }];
        let report = evaluate(&p, &[], &attestations, &[], NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::Compliant);
    }

    #[test]
    fn an_active_exception_overrides_and_an_expired_one_falls_through() {
        let p = profile(vec![control("c1", ControlKind::Automated, &["a"])]);
        let checks = vec![stored("a", CheckOutcome::Fail, 10)];
        let exceptions = vec![Exception {
            control_id: "c1".into(),
            owner: "o".into(),
            justification: "j".into(),
            expires_at: NOW + 100,
        }];
        let report = evaluate(&p, &checks, &[], &exceptions, NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::Excepted);
        // Expired: the real (failed) state returns.
        let exceptions = vec![Exception {
            control_id: "c1".into(),
            owner: "o".into(),
            justification: "j".into(),
            expires_at: NOW - 1,
        }];
        let report = evaluate(&p, &checks, &[], &exceptions, NOW, STALE_AFTER_SECS);
        assert_eq!(report.controls[0].status, ComplianceStatus::NonCompliant);
    }

    use proptest::prelude::*;

    // No combination of checks ever yields `Compliant` when at least one
    // required check is absent or stale, whatever the others do.
    proptest! {
        #[test]
        fn no_unknown_or_stale_check_yields_compliant(
            pass in 0..4usize,
            fail in 0..4usize,
            na in 0..4usize,
        ) {
            let control = Control {
                control_id: "c".into(),
                title: "c".into(),
                kind: ControlKind::Automated,
                checks: (0..(pass + fail + na + 1))
                    .map(|i| format!("check-{i}"))
                    .collect(),
                references: vec![],
            };
            let mut checks: Vec<StoredCheck> = Vec::new();
            for i in 0..pass { checks.push(stored(&format!("check-{}", i), CheckOutcome::Pass, 10)); }
            for i in 0..fail { checks.push(stored(&format!("check-{}", pass + i), CheckOutcome::Fail, 10)); }
            for i in 0..na { checks.push(stored(&format!("check-{}", pass + fail + i), CheckOutcome::NotApplicable, 10)); }
            // The last required check is deliberately absent.
            let report = evaluate(
                &profile(vec![control]),
                &checks,
                &[],
                &[],
                NOW,
                STALE_AFTER_SECS,
            );
            prop_assert_ne!(report.controls[0].status, ComplianceStatus::Compliant);
        }
    }

    #[test]
    fn a_signed_envelope_verifies_and_a_tampered_one_does_not() {
        let dir = std::env::temp_dir().join(format!("ibx-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let report = ComplianceReport {
            framework: "X".into(),
            version: "1".into(),
            evaluated_at: "2026-11-01T12:00:00Z".into(),
            controls: vec![ControlResult {
                control_id: "c".into(),
                title: "t".into(),
                status: ComplianceStatus::Compliant,
                checks: vec![],
            }],
        };
        let envelope = signed_envelope(&dir, &report, &[], &[], "head", 1_000).unwrap();
        assert!(verify_envelope(&envelope).is_ok());

        // Tampering with the report breaks the signature.
        let mut tampered = envelope.clone();
        tampered["report"]["controls"][0]["status"] =
            serde_json::Value::String("non_compliant".into());
        assert!(verify_envelope(&tampered).is_err());

        // A non-export document is refused outright.
        assert!(verify_envelope(&serde_json::json!({ "x": 1 })).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn csv_and_oscal_cover_every_control() {
        let report = ComplianceReport {
            framework: "X".into(),
            version: "1".into(),
            evaluated_at: "2026-11-01T12:00:00Z".into(),
            controls: vec![
                ControlResult {
                    control_id: "a.b".into(),
                    title: "A title".into(),
                    status: ComplianceStatus::Compliant,
                    checks: vec![],
                },
                ControlResult {
                    control_id: "c.d".into(),
                    title: "C title".into(),
                    status: ComplianceStatus::NotAssessed,
                    checks: vec![],
                },
            ],
        };
        let csv = csv(&report);
        assert!(csv.starts_with("control_id,title,status\n"));
        assert!(csv.contains("a.b") && csv.contains("not_assessed"));

        let oscal = oscal(&report, 1_000);
        assert_eq!(
            oscal["assessment-results"]["results"][0]["findings"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
    }
}
