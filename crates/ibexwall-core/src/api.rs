// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! varlink API surface (`com.ibexwall.Core`, F1 subset): authorization
//! per method via polkit, plan/apply/confirm/rollback orchestration,
//! checks, events and history. Proposal methods are not implemented
//! until F8 and answer MethodNotImplemented.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

use ibexwall_proto::names;
use ibexwall_proto::{Op, OpPreview, Plan, PluginInfo, Transaction, TransactionState};
use ibexwall_sys::{Clock, Decision, Identity, Polkit, RealPolkit};
use ibexwall_varlink::VarlinkError;
use ibexwall_varlink::{Call, Handler, Peer, Reply, futures_handle};

use crate::state::TxStatus;
use crate::{Core, TxRow};

/// Plan lifetime (spec §4.5: plans expire, default 10 minutes).
const PLAN_EXPIRY_SECS: i64 = 600;
/// Default confirmation window for network-risk transactions.
const CONFIRM_TIMEOUT_S: i64 = 60;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn fresh_id(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{prefix}-{nanos:x}-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

pub struct Api {
    pub core: Arc<Core>,
    polkit: Arc<dyn Polkit>,
}

impl Api {
    pub fn new(core: Core) -> Self {
        Self {
            core: Arc::new(core),
            polkit: Arc::new(RealPolkit),
        }
    }

    pub fn with_polkit(core: Core, polkit: Arc<dyn Polkit>) -> Self {
        Self {
            core: Arc::new(core),
            polkit,
        }
    }

    pub fn core(&self) -> Arc<Core> {
        Arc::clone(&self.core)
    }
}

fn err(name: &str, parameters: Value) -> VarlinkError {
    VarlinkError::new(format!("com.ibexwall.Core.{name}"), parameters)
}

fn permission_denied(action: &str) -> VarlinkError {
    err("PermissionDenied", json!({ "action": action }))
}

fn invalid_argument(field: &str, reason: String) -> VarlinkError {
    err(
        "InvalidArgument",
        json!({ "field": field, "reason": reason }),
    )
}

fn not_found(kind: &str, id: &str) -> VarlinkError {
    err("NotFound", json!({ "kind": kind, "id": id }))
}

impl Handler for Api {
    fn handle(
        &self,
        call: Call,
        out: tokio::sync::mpsc::Sender<Reply>,
    ) -> futures_handle::BoxHandle {
        let core = Arc::clone(&self.core);
        let polkit = Arc::clone(&self.polkit);
        futures_handle::BoxHandle::new(async move {
            if call.method == "com.ibexwall.Core.Subscribe" {
                // Streaming method: authorization, then the event loop
                // pushes `continues` frames until the client disconnects.
                let identity = identity_of(call.peer);
                match polkit.check(names::POLKIT_READ.to_string(), identity).await {
                    Ok(Decision::Authorized) => {}
                    _ => {
                        let _ = out
                            .send(Reply::error(
                                "com.ibexwall.Core.PermissionDenied",
                                json!({ "action": names::POLKIT_READ }),
                            ))
                            .await;
                        return;
                    }
                }
                let mut receiver = core.events.subscribe();
                while let Ok(event) = receiver.recv().await {
                    let frame =
                        Reply::result_continues(serde_json::to_value(&event).unwrap_or_default());
                    if out.send(frame).await.is_err() {
                        break; // client gone
                    }
                }
                return;
            }
            let method = call
                .method
                .strip_prefix("com.ibexwall.Core.")
                .unwrap_or(&call.method)
                .to_string();
            let reply = match dispatch(&core, &*polkit, &method, call.parameters, call.peer).await {
                Ok(reply) => reply,
                Err(e) => Reply::error(e.name, e.parameters),
            };
            let _ = out.send(reply).await;
        })
    }
}

async fn dispatch(
    core: &Arc<Core>,
    polkit: &dyn Polkit,
    method: &str,
    parameters: Value,
    peer: Peer,
) -> Result<Reply, VarlinkError> {
    // F1 scope guard: proposals land with the MCP assistant (F8).
    if matches!(
        method,
        "ListProposals" | "CreateProposal" | "DecideProposal"
    ) {
        return Err(VarlinkError::new(
            ibexwall_varlink::service_errors::METHOD_NOT_IMPLEMENTED,
            json!({ "method": method }),
        ));
    }

    let action = polkit_action(method).ok_or_else(|| {
        VarlinkError::new(
            ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
            json!({ "method": method }),
        )
    })?;

    let identity = identity_of(peer);
    if polkit
        .check(action.to_string(), identity)
        .await
        .map_err(|e| err("Conflict", json!({"reason": e.to_string()})))?
        != Decision::Authorized
    {
        return Err(permission_denied(action));
    }

    match method {
        "GetInfo" => Ok(Reply::result(info(core))),
        "GetPosture" => Ok(Reply::result(posture(core))),
        "ListPlugins" => Ok(Reply::result(json!({ "plugins": list_plugins(core) }))),
        "SetPluginEnabled" => {
            let id = str_field(&parameters, "id")?;
            let enabled = parameters
                .get("enabled")
                .and_then(Value::as_bool)
                .ok_or_else(|| invalid_argument("enabled", "boolean required".into()))?;
            authorize_plugin_change(core, &id)?;
            core.state
                .set_plugin_enabled(&id, enabled)
                .map_err(internal)?;
            core.audit(
                "user",
                "core",
                None,
                "",
                &format!("plugin {id} enabled={enabled}"),
            );
            Ok(Reply::result(json!({ "plan": null })))
        }
        "RunChecks" => run_checks(core, opt_str_field(&parameters, "plugin")?.as_deref()).await,
        "ListFindings" => {
            let plugin = opt_str_field(&parameters, "plugin")?.unwrap_or_default();
            let findings = core
                .state
                .list_findings(if plugin.is_empty() {
                    None
                } else {
                    Some(&plugin)
                })
                .map_err(internal)?;
            Ok(Reply::result(json!({ "findings": findings })))
        }
        "GetConfig" => {
            let plugin = str_field(&parameters, "plugin")?;
            let manifest = core
                .manifest(&plugin)
                .map_err(|_| not_found("plugin", &plugin))?;
            let effective = core
                .config
                .effective(&plugin, &std::collections::BTreeMap::new());
            let locks: Vec<String> = core
                .config
                .locks
                .iter()
                .filter(|l| l.starts_with(&plugin) || l.starts_with(&format!("{plugin}.")))
                .cloned()
                .collect();
            Ok(Reply::result(json!({
                "effective": effective,
                "layers": { "user": core.config.user.plugins.get(&plugin).cloned().unwrap_or_default() },
                "locks": locks,
                "reversible": manifest.risk.reversible,
            })))
        }
        "PlanChange" => plan_change(core, &parameters).await,
        "Apply" => apply(core, &parameters).await,
        "Confirm" => confirm(core, &parameters),
        "Rollback" => rollback(core, &parameters),
        "History" => {
            let limit = parameters
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(50) as usize;
            let rows = core.state.list_transactions(limit).map_err(internal)?;
            let entries: Vec<Value> = rows
                .into_iter()
                .enumerate()
                .map(|(seq, (id, plugin, state))| {
                    json!({ "seq": seq + 1, "ts": "", "actor": "", "plugin": plugin, "transaction": id, "result": state })
                })
                .collect();
            Ok(Reply::result(json!({ "entries": entries })))
        }
        "Subscribe" => subscribe(core),
        "AuditVerify" => {
            let verification = core.audit_verify();
            let value = match &verification {
                crate::audit::Verification::Valid { entries } => json!({
                    "valid": true, "entries": entries, "reason": null
                }),
                crate::audit::Verification::Broken { seq, reason } => json!({
                    "valid": false, "entries": seq, "reason": reason
                }),
            };
            Ok(Reply::result(value))
        }
        "RecentEvents" => {
            let limit = parameters
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(50) as usize;
            let events = core.state.list_events(limit).map_err(internal)?;
            Ok(Reply::result(json!({ "events": events })))
        }
        _ => Err(VarlinkError::new(
            ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
            json!({ "method": method }),
        )),
    }
}

fn polkit_action(method: &str) -> Option<&'static str> {
    Some(match method {
        "GetInfo" | "GetPosture" | "ListPlugins" | "ListFindings" | "GetConfig" | "History"
        | "Subscribe" | "RunChecks" | "AuditVerify" | "RecentEvents" => names::POLKIT_READ,
        "SetPluginEnabled" => names::POLKIT_PLUGINS_MANAGE,
        "PlanChange" => names::POLKIT_PLAN,
        "Apply" | "Confirm" => names::POLKIT_APPLY,
        "Rollback" => names::POLKIT_ROLLBACK,
        _ => return None,
    })
}

fn identity_of(peer: Peer) -> Identity {
    let start_time = ibexwall_sys::proc_start_time(peer.pid).unwrap_or(0);
    Identity {
        uid: peer.uid,
        pid: peer.pid,
        start_time,
    }
}

fn internal(e: impl Into<anyhow::Error>) -> VarlinkError {
    let e = e.into();
    tracing::error!(error = %e, "internal error");
    err("Conflict", json!({ "reason": "internal error" }))
}

fn str_field(parameters: &Value, field: &str) -> Result<String, VarlinkError> {
    parameters
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| VarlinkError::invalid_parameter(field))
}

fn opt_str_field(parameters: &Value, field: &str) -> Result<Option<String>, VarlinkError> {
    Ok(parameters
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string))
}

// method implementations -------------------------------------------------

fn info(_core: &Arc<Core>) -> Value {
    let distro = std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("ID=").map(str::to_string))
        })
        .unwrap_or_else(|| "unknown".into());
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    json!({
        "info": {
            "version": env!("CARGO_PKG_VERSION"),
            "api": 1,
            "distro": distro,
            "kernel": kernel,
            "features": [],
            "degraded": [],
        }
    })
}

fn posture(core: &Arc<Core>) -> Value {
    let findings = core.state.list_findings(None).unwrap_or_default();
    let open: Vec<&Value> = findings
        .iter()
        .filter(|f| f.get("status").and_then(Value::as_str) == Some("open"))
        .collect();
    let weight: i64 = open
        .iter()
        .filter_map(|f| f.get("severity").and_then(Value::as_str))
        .map(|sev| match sev {
            "critical" => 10,
            "high" => 6,
            "medium" => 3,
            "low" => 1,
            _ => 0,
        })
        .sum();
    let score = 100i64.saturating_sub(weight * 5).clamp(0, 100);
    let protections: Vec<Value> = core
        .plugins
        .plugins()
        .map(|entry| {
            json!({
                "plugin": entry.manifest.id,
                "state": if core.state.plugin_enabled(&entry.manifest.id).unwrap_or(false) { "on" } else { "off" },
                "summary_key": format!("plugin-{}-summary", entry.manifest.id),
            })
        })
        .collect();
    json!({
        "posture": {
            "score": score,
            "generated_at": ibexwall_sys::RealClock.rfc3339_now(),
            "protections": protections,
            "open_findings": open.len(),
        }
    })
}

fn list_plugins(core: &Arc<Core>) -> Vec<PluginInfo> {
    core.plugins
        .plugins()
        .map(|entry| PluginInfo {
            id: entry.manifest.id.clone(),
            name: entry
                .manifest
                .name
                .get(names::LOCALE_SOURCE)
                .cloned()
                .unwrap_or_default(),
            version: entry.manifest.version.clone(),
            kinds: entry
                .manifest
                .kinds
                .iter()
                .map(|k| format!("{k:?}").to_lowercase())
                .collect(),
            enabled: core
                .state
                .plugin_enabled(&entry.manifest.id)
                .unwrap_or(false),
            origin: entry.manifest.origin,
            status: "ok".into(),
            compatible: true,
            conflicts: entry.manifest.conflicts.units.clone(),
            locked: false,
        })
        .collect()
}

fn authorize_plugin_change(core: &Arc<Core>, id: &str) -> Result<(), VarlinkError> {
    core.plugins
        .manifest(id)
        .map_err(|_| not_found("plugin", id))?;
    Ok(())
}

async fn run_checks(core: &Arc<Core>, plugin: Option<&str>) -> Result<Reply, VarlinkError> {
    let targets: Vec<String> = match plugin {
        Some(one) => vec![one.to_string()],
        None => core
            .plugins
            .plugins()
            .map(|e| e.manifest.id.clone())
            .collect(),
    };
    let mut findings = Vec::new();
    for id in targets {
        if !core.state.plugin_enabled(&id).map_err(internal)? {
            continue;
        }
        let result = core.plugins.check(&id, serde_json::Value::Null).await;
        let plugin_findings =
            result.map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
        for finding in plugin_findings {
            let id = finding
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let severity = finding
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_string();
            let detected_at = ibexwall_sys::RealClock.rfc3339_now();
            core.state
                .upsert_finding(
                    &id,
                    finding.get("plugin").and_then(Value::as_str).unwrap_or(""),
                    &severity,
                    &finding.to_string(),
                    &detected_at,
                )
                .map_err(internal)?;
            findings.push(finding);
        }
    }
    core.audit("user", "core", None, "", "run-checks");
    Ok(Reply::result(json!({ "findings": findings })))
}

async fn plan_change(core: &Arc<Core>, parameters: &Value) -> Result<Reply, VarlinkError> {
    let plugin = str_field(parameters, "plugin")?;
    let patch = parameters.get("patch").cloned().unwrap_or(Value::Null);
    authorize_plugin_change(core, &plugin)?;

    // Ask the plugin for its proposed operations.
    let ops = core
        .plugins
        .plan(&plugin, patch)
        .await
        .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;

    // The gate: validate every op against the manifest.
    let manifest = core
        .plugins
        .manifest(&plugin)
        .map_err(|_| not_found("plugin", &plugin))?
        .clone();
    let risk = crate::engine::ops::validate(&ops, &manifest)
        .map_err(|e| invalid_argument("ops", e.to_string()))?;

    let engine = &core.engine;
    let preview: Vec<OpPreview> = engine.preview(&ops);
    let requires_confirm =
        risk.contains(&ibexwall_proto::RiskFlag::Network) || manifest.risk.confirm_timeout;
    let plan_id = fresh_id("plan");
    let now = ibexwall_sys::RealClock.rfc3339_now();
    let expires_at =
        ibexwall_sys::format_rfc3339(ibexwall_sys::RealClock.unix_now() + PLAN_EXPIRY_SECS);

    let persisted = crate::engine::PersistedPlan {
        id: plan_id.clone(),
        plugin: plugin.clone(),
        ops_json: serde_json::to_string(&ops).map_err(internal)?,
        requires_confirm,
        confirm_timeout_s: CONFIRM_TIMEOUT_S,
        fingerprint: core.config.fingerprint(),
        expires_at: expires_at.clone(),
        created_at: now,
    };
    core.state.save_plan(&persisted).map_err(internal)?;

    let plan = Plan {
        id: plan_id,
        plugin,
        ops: preview,
        risk: risk.clone(),
        reversible: manifest.risk.reversible,
        may_affect_keys: manifest.risk.may_affect.clone(),
        requires_confirm,
        expires_at,
    };
    core.audit(
        "user",
        &persisted.plugin,
        None,
        &crate::audit::ops_digest(&ops),
        "plan-created",
    );
    Ok(Reply::result(json!({ "plan": plan })))
}

async fn apply(core: &Arc<Core>, parameters: &Value) -> Result<Reply, VarlinkError> {
    let plan_id = str_field(parameters, "plan_id")?;
    let confirm_timeout_s = parameters
        .get("confirm_timeout_s")
        .and_then(Value::as_i64)
        .unwrap_or(CONFIRM_TIMEOUT_S);

    let plan = core
        .state
        .load_plan(&plan_id)
        .map_err(internal)?
        .ok_or_else(|| not_found("plan", &plan_id))?;
    let ops: Vec<Op> = serde_json::from_str(&plan.ops_json).map_err(internal)?;

    // Expiry and staleness (spec §4.5).
    if core.config.fingerprint() != plan.fingerprint {
        return Err(err("PlanStale", json!({ "plan_id": plan_id })));
    }
    if ibexwall_sys::RealClock.unix_now() > parse_unix(&plan.expires_at) {
        return Err(err("PlanExpired", json!({ "plan_id": plan_id })));
    }

    // Re-validate against the manifest right before applying.
    let manifest = core
        .plugins
        .manifest(&plan.plugin)
        .map_err(|_| not_found("plugin", &plan.plugin))?
        .clone();
    crate::engine::ops::validate(&ops, &manifest)
        .map_err(|e| invalid_argument("ops", e.to_string()))?;

    let tx_id = fresh_id("tx");
    let restore_point = format!("snapshots/{tx_id}");
    let now = ibexwall_sys::RealClock.rfc3339_now();
    let row = TxRow {
        id: tx_id.clone(),
        plan_id: plan_id.clone(),
        plugin: plan.plugin.clone(),
        state: TransactionState::Applying,
        restore_point: restore_point.clone(),
    };
    core.state
        .insert_transaction(&row, &now)
        .map_err(internal)?;
    core.audit(
        "user",
        &plan.plugin,
        Some(&tx_id),
        &crate::audit::ops_digest(&ops),
        "apply-start",
    );

    // Snapshot, then execute (spec §4.5 order).
    let engine_core = Arc::clone(core);
    let ops_for_exec = ops.clone();
    let tx_for_exec = tx_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let snapshot =
            engine_core
                .engine
                .snapshot(&engine_core.state, &tx_for_exec, &ops_for_exec)?;
        engine_core.engine.execute(&ops_for_exec)?;
        Ok::<_, anyhow::Error>(snapshot)
    })
    .await
    .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;

    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(e) => {
            core.rollback_transaction(&tx_id, &ops).ok();
            core.state
                .mark_transaction(&tx_id, TxStatus::Failed)
                .map_err(internal)?;
            core.audit(
                "user",
                &plan.plugin,
                Some(&tx_id),
                &crate::audit::ops_digest(&ops),
                "apply-failed",
            );
            return Err(err("Conflict", json!({ "reason": e.to_string() })));
        }
    };
    let _ = snapshot;

    // Plugin verification.
    let verified = core
        .plugins
        .verify(&plan.plugin, &tx_id, &ops)
        .await
        .unwrap_or(false);
    if !verified {
        core.rollback_transaction(&tx_id, &ops).ok();
        core.state
            .mark_transaction(&tx_id, TxStatus::Failed)
            .map_err(internal)?;
        core.audit(
            "user",
            &plan.plugin,
            Some(&tx_id),
            &crate::audit::ops_digest(&ops),
            "verify-failed",
        );
        return Err(err(
            "Conflict",
            json!({ "reason": "plugin verification failed" }),
        ));
    }

    let transaction = if plan.requires_confirm {
        let deadline = ibexwall_sys::RealClock.unix_now() + confirm_timeout_s;
        core.state
            .set_confirm_deadline(&tx_id, deadline)
            .map_err(internal)?;
        core.audit(
            "user",
            &plan.plugin,
            Some(&tx_id),
            &crate::audit::ops_digest(&ops),
            "pending-confirm",
        );
        spawn_confirmation_watchdog(Arc::clone(core), tx_id.clone(), ops.clone(), deadline);
        Transaction {
            id: tx_id.clone(),
            plan_id,
            state: TransactionState::PendingConfirm,
            started_at: now,
            confirm_deadline: Some(ibexwall_sys::format_rfc3339(deadline)),
            restore_point,
        }
    } else {
        core.state
            .mark_transaction(&tx_id, TxStatus::Committed)
            .map_err(internal)?;
        core.audit(
            "user",
            &plan.plugin,
            Some(&tx_id),
            &crate::audit::ops_digest(&ops),
            "committed",
        );
        Transaction {
            id: tx_id.clone(),
            plan_id,
            state: TransactionState::Committed,
            started_at: now,
            confirm_deadline: None,
            restore_point,
        }
    };
    core.publish_transaction_event(&transaction);
    Ok(Reply::result(json!({ "transaction": transaction })))
}

fn confirm(core: &Arc<Core>, parameters: &Value) -> Result<Reply, VarlinkError> {
    let tx_id = str_field(parameters, "transaction_id")?;
    let row = core
        .state
        .get_transaction(&tx_id)
        .map_err(internal)?
        .ok_or_else(|| not_found("transaction", &tx_id))?;
    if row.state != TransactionState::PendingConfirm {
        return Err(invalid_argument(
            "transaction_id",
            format!("transaction is {}", tx_state(&row.state)),
        ));
    }
    core.state
        .mark_transaction(&tx_id, TxStatus::Committed)
        .map_err(internal)?;
    core.audit("user", &row.plugin, Some(&tx_id), "", "confirmed");
    Ok(Reply::result(Value::Null))
}

fn rollback(core: &Arc<Core>, parameters: &Value) -> Result<Reply, VarlinkError> {
    let target = str_field(parameters, "target")?;
    let row = core
        .state
        .get_transaction(&target)
        .map_err(internal)?
        .ok_or_else(|| not_found("transaction", &target))?;
    let plan = core
        .state
        .load_plan(&row.plan_id)
        .map_err(internal)?
        .ok_or_else(|| not_found("plan", &row.plan_id))?;
    let ops: Vec<Op> = serde_json::from_str(&plan.ops_json).map_err(internal)?;
    core.rollback_transaction(&target, &ops)
        .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
    core.state
        .mark_transaction(&target, TxStatus::RolledBack)
        .map_err(internal)?;
    core.audit(
        "user",
        &row.plugin,
        Some(&target),
        &crate::audit::ops_digest(&ops),
        "rolled-back",
    );
    Ok(Reply::result(
        json!({ "transaction": { "id": target, "state": "rolled_back" } }),
    ))
}

fn subscribe(core: &Arc<Core>) -> Result<Reply, VarlinkError> {
    // Streaming is handled in the Handler loop (see Api::handle); this
    // arm is unreachable for the real method name.
    let _ = core;
    Ok(Reply::result(Value::Null))
}

fn parse_unix(rfc3339: &str) -> i64 {
    // Minimal parse of our own formatting (YYYY-MM-DDTHH:MM:SSZ).
    let bytes = rfc3339.as_bytes();
    if bytes.len() < 19 {
        return i64::MAX;
    }
    let year: i64 = rfc3339[0..4].parse().unwrap_or(1970);
    let month: i64 = rfc3339[5..7].parse().unwrap_or(1);
    let day: i64 = rfc3339[8..10].parse().unwrap_or(1);
    let hour: i64 = rfc3339[11..13].parse().unwrap_or(0);
    let minute: i64 = rfc3339[14..16].parse().unwrap_or(0);
    let second: i64 = rfc3339[17..19].parse().unwrap_or(0);
    let days = days_from_civil(year, month, day);
    days * 86_400 + hour * 3_600 + minute * 60 + second
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

fn tx_state(state: &TransactionState) -> &'static str {
    match state {
        TransactionState::Planned => "planned",
        TransactionState::Approved => "approved",
        TransactionState::Applying => "applying",
        TransactionState::Applied => "applied",
        TransactionState::PendingConfirm => "pending_confirm",
        TransactionState::Committed => "committed",
        TransactionState::RolledBack => "rolled_back",
        TransactionState::Failed => "failed",
    }
}

/// Watches a pending confirmation; on timeout rolls back automatically
/// (spec §4.5: no Confirm means rollback).
fn spawn_confirmation_watchdog(core: Arc<Core>, tx_id: String, ops: Vec<Op>, deadline_unix: i64) {
    tokio::spawn(async move {
        let now = ibexwall_sys::RealClock.unix_now();
        let wait = (deadline_unix - now).max(0) as u64;
        tokio::time::sleep(Duration::from_secs(wait)).await;
        // Refresh the decision: Confirm may have committed already.
        if let Ok(Some(row)) = core.state.get_transaction(&tx_id) {
            if row.state != TransactionState::PendingConfirm {
                return;
            }
            tracing::warn!(transaction = %tx_id, "confirmation window expired, rolling back");
            let _ = core.rollback_transaction(&tx_id, &ops);
            let _ = core.state.mark_transaction(&tx_id, TxStatus::RolledBack);
            core.audit(
                "system",
                &row.plugin,
                Some(&tx_id),
                &crate::audit::ops_digest(&ops),
                "confirm-timeout-rollback",
            );
            core.publish_transaction_event(&Transaction {
                id: tx_id.clone(),
                plan_id: row.plan_id.clone(),
                state: TransactionState::RolledBack,
                started_at: ibexwall_sys::RealClock.rfc3339_now(),
                confirm_deadline: None,
                restore_point: String::new(),
            });
        }
    });
}
