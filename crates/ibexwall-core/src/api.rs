// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! varlink API surface (`com.ibexwall.Core`, F1 subset): authorization
//! per method via polkit, plan/apply/confirm/rollback orchestration,
//! checks, events and history. Proposal methods are in the proposal queue
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

mod transactions;
mod views;

use transactions::*;
use views::*;

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

    pub fn with_polkit(core: Arc<Core>, polkit: Arc<dyn Polkit>) -> Self {
        Self { core, polkit }
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

fn proposal_error(error: crate::proposals::Error) -> VarlinkError {
    use crate::proposals::Error;
    match error {
        Error::NotFound => err("NotFound", json!({ "kind": "proposal" })),
        Error::Decided => err("Conflict", json!({ "reason": "already decided" })),
        Error::Stale => err("ProposalStale", json!({})),
        Error::Full | Error::ClientFull | Error::Irreversible => {
            err("Conflict", json!({ "reason": error.to_string() }))
        }
        Error::Other(reason) => {
            tracing::error!(%reason, "proposal error");
            err("Conflict", json!({ "reason": "internal error" }))
        }
    }
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
                loop {
                    match receiver.recv().await {
                        Ok(event) => {
                            let frame = Reply::result_continues(
                                serde_json::to_value(&event).unwrap_or_default(),
                            );
                            if out.send(frame).await.is_err() {
                                break; // client gone
                            }
                        }
                        // A subscriber that fell behind still deserves a
                        // final frame instead of a hung connection.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            let _ = out
                                .send(Reply::error(
                                    "com.ibexwall.Core.Lagged",
                                    json!({ "reason": "events were dropped for this subscriber" }),
                                ))
                                .await;
                            break;
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
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
    let action = polkit_action(method).ok_or_else(|| {
        VarlinkError::new(
            ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
            json!({ "method": method }),
        )
    })?;

    let identity = identity_of(peer);
    let actor = identity.actor();
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
        "GetDnsStatus" => Ok(Reply::result(dns_status(core))),
        "GetFirewall" => Ok(Reply::result(
            json!({ "firewall": crate::firewall::state(core).await }),
        )),
        "ListApps" => Ok(Reply::result(json!({
            "monitor": core.monitor.status(),
            "apps": crate::monitor::list_apps(core).map_err(internal)?,
        }))),
        "SetAppMode" => {
            let app = str_field(&parameters, "app")?;
            let mode = str_field(&parameters, "mode")?;
            let mode = ibexwall_apps::policy::Mode::parse(&mode)
                .ok_or_else(|| invalid_argument("mode", "allow, monitor, ask or block".into()))?;
            // A container's packets leave through another network namespace,
            // where the queue rule does not run: Ask could not hold them.
            if mode == ibexwall_apps::policy::Mode::Ask && app.starts_with("container:") {
                return Err(invalid_argument(
                    "mode",
                    "ask is not available for containers".into(),
                ));
            }
            crate::monitor::set_app_mode(core, &app, mode).map_err(internal)?;
            core.audit(
                &actor,
                "core",
                None,
                "",
                &format!("app {app} mode={}", mode.name()),
            );
            Ok(Reply::result(json!({})))
        }
        "ListProposals" => {
            let status = opt_str_field(&parameters, "status")?;
            let proposals = core.list_proposals(status.as_deref()).map_err(internal)?;
            Ok(Reply::result(json!({ "proposals": proposals })))
        }
        "CreateProposal" => {
            let plugin = str_field(&parameters, "plugin")?;
            let patch = parameters.get("patch").cloned().unwrap_or(Value::Null);
            let justification = str_field(&parameters, "justification")?;
            let client = opt_str_field(&parameters, "client")?.unwrap_or_else(|| "unknown".into());
            let (plan, ops) = build_plan(core, plugin, patch.clone(), &actor).await?;
            let digest = crate::audit::ops_digest(&ops);
            let proposal = core
                .create_proposal(&client, &plan, patch, &justification, &digest)
                .map_err(proposal_error)?;
            Ok(Reply::result(json!({ "proposal": proposal })))
        }
        "DecideProposal" => {
            let id = str_field(&parameters, "id")?;
            let decision = str_field(&parameters, "decision")?;
            let (proposal, digest) = core.pending_proposal(&id).map_err(proposal_error)?;
            // One decision per proposal: the first caller to flip it from
            // pending wins, the rest get "already decided".
            let final_status = match decision.as_str() {
                "reject" => "rejected",
                "approve" => "approved",
                _ => return Err(invalid_argument("decision", "approve or reject".into())),
            };
            if !core
                .state
                .claim_proposal(&id, final_status)
                .map_err(internal)?
            {
                return Err(proposal_error(crate::proposals::Error::Decided));
            }
            match decision.as_str() {
                "reject" => {
                    core.audit(&actor, &proposal.plugin, None, &digest, "proposal-rejected");
                    core.publish_proposal_event("proposals.decided", &proposal);
                    Ok(Reply::result(json!({ "transaction": null })))
                }
                "approve" => {
                    // Plan again from what the client asked for, and apply
                    // only if the operations are the ones that were reviewed.
                    let (plan, ops) = build_plan(
                        core,
                        proposal.plugin.clone(),
                        proposal.patch.clone(),
                        &actor,
                    )
                    .await?;
                    if crate::audit::ops_digest(&ops) != digest {
                        return Err(err("ProposalStale", json!({ "id": id })));
                    }
                    let reply = apply(core, &json!({ "plan_id": plan.id }), &actor).await;
                    match &reply {
                        Ok(_) => {
                            core.audit(
                                &actor,
                                &proposal.plugin,
                                None,
                                &digest,
                                "proposal-approved",
                            );
                            core.publish_proposal_event("proposals.decided", &proposal);
                        }
                        Err(_) => {
                            core.audit(
                                &actor,
                                &proposal.plugin,
                                None,
                                &digest,
                                "proposal-approval-failed",
                            );
                        }
                    }
                    reply
                }
                _ => unreachable!("the decision was validated above"),
            }
        }
        "SetDefaultMode" => {
            let mode = str_field(&parameters, "mode")?;
            let mode = ibexwall_apps::policy::Mode::parse(&mode)
                .filter(|mode| *mode != ibexwall_apps::policy::Mode::Block)
                .ok_or_else(|| invalid_argument("mode", "allow, monitor or ask".into()))?;
            core.state
                .with_conn(|conn| ibexwall_apps::policy::set_default_mode(conn, mode))
                .map_err(internal)?;
            core.monitor.refresh_policy(core).map_err(internal)?;
            core.audit(
                &actor,
                "core",
                None,
                "",
                &format!("default app mode={}", mode.name()),
            );
            Ok(Reply::result(json!({})))
        }
        "ListPrompts" => Ok(Reply::result(json!({
            "prompts": core.monitor.prompts(ibexwall_sys::RealClock.unix_now()),
        }))),
        "AnswerPrompt" => {
            let id = str_field(&parameters, "id")?;
            let allow = match str_field(&parameters, "decision")?.as_str() {
                "allow" => true,
                "block" => false,
                _ => return Err(invalid_argument("decision", "allow or block".into())),
            };
            let scope = crate::ask::Scope::parse(&str_field(&parameters, "scope")?)
                .ok_or_else(|| invalid_argument("scope", "once, destination or always".into()))?;
            let now = ibexwall_sys::RealClock.unix_now();
            if !core
                .monitor
                .answer_prompt(core, &id, allow, scope, now)
                .map_err(internal)?
            {
                return Err(not_found("prompt", &id));
            }
            core.audit(
                &actor,
                "core",
                None,
                "",
                &format!("prompt {id} allow={allow}"),
            );
            Ok(Reply::result(json!({})))
        }
        "GetAppDestinations" => {
            let app = str_field(&parameters, "app")?;
            Ok(Reply::result(json!({
                "destinations": crate::monitor::app_destinations(core, &app).map_err(internal)?,
            })))
        }
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
                &actor,
                "core",
                None,
                "",
                &format!("plugin {id} enabled={enabled}"),
            );
            Ok(Reply::result(json!({ "plan": null })))
        }
        "GetPlugin" => {
            let id = str_field(&parameters, "id")?;
            let manifest = core.manifest(&id).map_err(|_| not_found("plugin", &id))?;
            let plugins = list_plugins(core);
            let info = plugins
                .iter()
                .find(|p| p.id == id)
                .cloned()
                .ok_or_else(|| not_found("plugin", &id))?;
            let manifest = serde_json::to_value(&manifest).map_err(internal)?;
            Ok(Reply::result(
                json!({ "plugin": info, "manifest": manifest }),
            ))
        }
        "RunChecks" => {
            run_checks(
                core,
                opt_str_field(&parameters, "plugin")?.as_deref(),
                &actor,
            )
            .await
        }
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
            core.reload_config();
            let manifest = core
                .manifest(&plugin)
                .map_err(|_| not_found("plugin", &plugin))?;
            let config = core.config.read().expect("config lock poisoned");
            let effective = config.effective(&plugin, &std::collections::BTreeMap::new());
            let locks: Vec<String> = config
                .locks
                .iter()
                .filter(|l| l.starts_with(&plugin) || l.starts_with(&format!("{plugin}.")))
                .cloned()
                .collect();
            Ok(Reply::result(json!({
                "effective": effective,
                "layers": { "user": config.user.plugins.get(&plugin).cloned().unwrap_or_default() },
                "locks": locks,
                "reversible": manifest.risk.reversible,
            })))
        }
        "PlanChange" => plan_change(core, &parameters, &actor).await,
        "Apply" => apply(core, &parameters, &actor).await,
        "Confirm" => confirm(core, &parameters, &actor).await,
        "Rollback" => rollback(core, &parameters, &actor).await,
        "History" => {
            let limit = parameters
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                .min(500) as usize;
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
        "ListAudit" => {
            let limit = parameters
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                .min(500) as usize;
            let rows = core
                .state
                .with_conn(|conn| crate::audit::tail(conn, limit))
                .unwrap_or_default();
            let entries: Vec<Value> = rows
                .into_iter()
                .map(|e| {
                    json!({ "seq": e.seq, "ts": e.ts, "actor": e.actor, "plugin": e.plugin,
                            "transaction": e.transaction, "result": e.result })
                })
                .collect();
            Ok(Reply::result(json!({ "entries": entries })))
        }
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
                .unwrap_or(50)
                .min(500) as usize;
            let events = core.state.list_events(limit).map_err(internal)?;
            Ok(Reply::result(json!({ "events": events })))
        }
        "SetAttestation" => {
            let control_id = str_field(&parameters, "control_id")?;
            let owner = non_empty_field(&parameters, "owner")?;
            let statement = non_empty_field(&parameters, "statement")?;
            let expires_at = parameters.get("expires_at").and_then(Value::as_i64);
            let attestation = ibexwall_proto::Attestation {
                control_id,
                owner,
                statement,
                expires_at,
            };
            core.state.set_attestation(&attestation).map_err(internal)?;
            core.audit(&actor, "core", None, "", "attestation-set");
            Ok(Reply::result(Value::Null))
        }
        "SetException" => {
            let control_id = str_field(&parameters, "control_id")?;
            let owner = non_empty_field(&parameters, "owner")?;
            let justification = non_empty_field(&parameters, "justification")?;
            let expires_at = parameters
                .get("expires_at")
                .and_then(Value::as_i64)
                .ok_or_else(|| invalid_argument("expires_at", "integer required".into()))?;
            let exception = ibexwall_proto::Exception {
                control_id,
                owner,
                justification,
                expires_at,
            };
            core.state.set_exception(&exception).map_err(internal)?;
            core.audit(&actor, "core", None, "", "exception-set");
            Ok(Reply::result(Value::Null))
        }
        "ListComplianceProfiles" => {
            let profiles = crate::profiles::discover(&core.root).map_err(internal)?;
            let names: Vec<Value> = profiles
                .iter()
                .map(|p| {
                    json!({
                        "framework": p.framework,
                        "version": p.version,
                        "controls": p.controls.len(),
                    })
                })
                .collect();
            Ok(Reply::result(json!({ "profiles": names })))
        }
        "GetCompliance" => {
            let framework = str_field(&parameters, "profile")?;
            let report = compliance_report(core, &framework)?;
            Ok(Reply::result(json!({ "report": report })))
        }
        "ExportCompliance" => {
            let framework = str_field(&parameters, "profile")?;
            let report = compliance_report(core, &framework)?;
            Ok(Reply::result(json!({ "format": "json", "export": report })))
        }
        _ => Err(VarlinkError::new(
            ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
            json!({ "method": method }),
        )),
    }
}

fn polkit_action(method: &str) -> Option<&'static str> {
    Some(match method {
        "GetInfo"
        | "GetPosture"
        | "GetDnsStatus"
        | "GetFirewall"
        | "ListApps"
        | "ListPrompts"
        | "GetAppDestinations"
        | "ListPlugins"
        | "ListFindings"
        | "GetConfig"
        | "History"
        | "Subscribe"
        | "RunChecks"
        | "GetPlugin"
        | "AuditVerify"
        | "RecentEvents"
        | "ListAudit"
        | "ListComplianceProfiles"
        | "GetCompliance"
        | "ExportCompliance" => names::POLKIT_READ,
        "SetPluginEnabled" => names::POLKIT_PLUGINS_MANAGE,
        "SetAppMode" | "SetDefaultMode" | "AnswerPrompt" => names::POLKIT_APPS_DECIDE,
        "PlanChange" => names::POLKIT_PLAN,
        "ListProposals" => names::POLKIT_READ,
        "CreateProposal" => names::POLKIT_PROPOSALS_CREATE,
        "DecideProposal" => names::POLKIT_PROPOSALS_DECIDE,
        "Apply" | "Confirm" => names::POLKIT_APPLY,
        "Rollback" => names::POLKIT_ROLLBACK,
        "SetAttestation" | "SetException" => names::POLKIT_POLICY_PROVIDER,
        _ => return None,
    })
}

fn identity_of(peer: Peer) -> Identity {
    // Bound to the connection: uid and pid come from SO_PEERCRED at
    // accept, and the start time was read from /proc at the same
    // moment. Nothing here is re-read per call, so a later exec or pid
    // reuse cannot swap the identity under an authorization check.
    Identity {
        uid: peer.uid,
        pid: peer.pid,
        start_time: peer.start_time,
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

/// A required non-empty string field.
fn non_empty_field(parameters: &Value, field: &str) -> Result<String, VarlinkError> {
    let value = str_field(parameters, field)?;
    if value.trim().is_empty() {
        return Err(invalid_argument(
            field,
            "a non-empty string is required".into(),
        ));
    }
    Ok(value)
}

/// Evaluates one profile against the stored checks, attestations and
/// exceptions, and returns its report.
fn compliance_report(core: &Core, framework: &str) -> Result<Value, VarlinkError> {
    let profile = crate::profiles::discover(&core.root)
        .map_err(internal)?
        .into_iter()
        .find(|p| p.framework == framework)
        .ok_or_else(|| not_found("profile", framework))?;
    let checks = core.state.compliance_checks().map_err(internal)?;
    let attestations = core.state.list_attestations().map_err(internal)?;
    let exceptions = core.state.list_exceptions().map_err(internal)?;
    let report = crate::compliance::evaluate(
        &profile,
        &checks,
        &attestations,
        &exceptions,
        ibexwall_sys::RealClock.unix_now(),
        crate::compliance::STALE_AFTER_SECS,
    );
    serde_json::to_value(&report).map_err(internal)
}

// method implementations -------------------------------------------------

fn authorize_plugin_change(core: &Arc<Core>, id: &str) -> Result<(), VarlinkError> {
    core.plugins
        .manifest(id)
        .map_err(|_| not_found("plugin", id))?;
    Ok(())
}

async fn run_checks(
    core: &Arc<Core>,
    plugin: Option<&str>,
    actor: &str,
) -> Result<Reply, VarlinkError> {
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
        let report = core
            .plugins
            .check(&id, serde_json::Value::Null)
            .await
            .map_err(|e| err("Conflict", json!({ "reason": format!("{e:#}") })))?;
        let checked_at = ibexwall_sys::RealClock.rfc3339_now();
        core.state
            .replace_check_run(&id, &report, &checked_at)
            .map_err(internal)?;
        findings.extend(report.findings);
    }
    core.audit(actor, "core", None, "", "run-checks");
    Ok(Reply::result(json!({ "findings": findings })))
}

/// Plans a change and stores the plan; returns it with its operations.
async fn build_plan(
    core: &Arc<Core>,
    plugin: String,
    patch: Value,
    actor: &str,
) -> Result<(Plan, Vec<Op>), VarlinkError> {
    authorize_plugin_change(core, &plugin)?;
    // A config change on disk takes effect immediately, not after a
    // restart, so locks and the plan fingerprint reflect the real state.
    core.reload_config();

    // The organization layer can lock a setting; a plan that touches a
    // locked key is refused whoever asks for it.
    if let Some(keys) = patch.as_object() {
        for key in keys.keys() {
            if let Some(pattern) = core
                .config
                .read()
                .expect("config lock poisoned")
                .is_locked(&plugin, key)
            {
                return Err(err(
                    "Conflict",
                    json!({ "reason": format!("`{plugin}.{key}` is locked by the organization layer ({pattern})") }),
                ));
            }
        }
    }

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
        fingerprint: core
            .config
            .read()
            .expect("config lock poisoned")
            .fingerprint(),
        expires_at: expires_at.clone(),
        created_at: now,
    };
    core.state.save_plan(&persisted).map_err(internal)?;

    let plan = Plan {
        id: plan_id,
        plugin,
        ops: preview,
        risk: risk.clone(),
        reversible: if risk.contains(&ibexwall_proto::RiskFlag::Irreversible) {
            ibexwall_proto::Reversible::Irreversible
        } else if risk.contains(&ibexwall_proto::RiskFlag::RebootToRevert) {
            ibexwall_proto::Reversible::Reboot
        } else {
            ibexwall_proto::Reversible::Immediate
        },
        may_affect_keys: {
            let mut keys = manifest.risk.may_affect.clone();
            // Only the keys of what this plan really does: the manifest
            // lists everything the plugin can ever affect, and the one-way
            // warning belongs to the plans that carry it.
            if risk.contains(&ibexwall_proto::RiskFlag::RebootToRevert) {
                keys.push("risk-reboot-to-revert".to_string());
            }
            keys
        },
        requires_confirm,
        expires_at,
    };
    core.audit(
        actor,
        &persisted.plugin,
        None,
        &crate::audit::ops_digest(&ops),
        "plan-created",
    );
    Ok((plan, ops))
}

async fn plan_change(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    let plugin = str_field(parameters, "plugin")?;
    let patch = parameters.get("patch").cloned().unwrap_or(Value::Null);
    let (plan, _) = build_plan(core, plugin, patch, actor).await?;
    Ok(Reply::result(json!({ "plan": plan })))
}

async fn apply(core: &Arc<Core>, parameters: &Value, actor: &str) -> Result<Reply, VarlinkError> {
    let plan_id = str_field(parameters, "plan_id")?;
    // The confirmation window is bounded: a negative value would roll
    // back at once, a huge one would disable the safety net, and the
    // addition would overflow.
    let confirm_timeout_s = parameters
        .get("confirm_timeout_s")
        .and_then(Value::as_i64)
        .unwrap_or(CONFIRM_TIMEOUT_S)
        .clamp(1, 3_600);

    let plan = core
        .state
        .load_plan(&plan_id)
        .map_err(internal)?
        .ok_or_else(|| not_found("plan", &plan_id))?;
    let ops: Vec<Op> = serde_json::from_str(&plan.ops_json).map_err(internal)?;

    // Expiry and staleness (spec §4.5). The config is re-read so a
    // change since the plan was made actually fires PlanStale.
    core.reload_config();
    if core
        .config
        .read()
        .expect("config lock poisoned")
        .fingerprint()
        != plan.fingerprint
    {
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
    let flags = crate::engine::ops::validate(&ops, &manifest)
        .map_err(|e| invalid_argument("ops", e.to_string()))?;
    // The core never applies what it cannot undo. Reversibility comes
    // from the operations, not from the manifest's claim.
    if flags.contains(&ibexwall_proto::RiskFlag::Irreversible) {
        return Err(err("Conflict", json!({ "reason": "irreversible plan" })));
    }

    // One engine mutation at a time, and one shot per plan.
    let _permit = core
        .tx_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
    if !core.state.consume_plan(&plan_id).map_err(internal)? {
        return Err(err("Conflict", json!({ "reason": "plan already applied" })));
    }

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
        actor,
        &plan.plugin,
        Some(&tx_id),
        &crate::audit::ops_digest(&ops),
        "apply-start",
    );

    // Snapshot, then execute (spec §4.5 order). Execs the manifest marked
    // symmetric are re-run by the rollback once the files are back.
    let reload_execs: Vec<(String, Vec<String>)> = manifest
        .privileges
        .exec
        .iter()
        .filter(|entry| entry.symmetric)
        .map(|entry| (entry.path.clone(), entry.args.clone()))
        .collect();
    let engine_core = Arc::clone(core);
    let ops_for_exec = ops.clone();
    let tx_for_exec = tx_id.clone();
    let result = tokio::task::spawn_blocking(move || {
        let snapshot = engine_core.engine.snapshot(
            &engine_core.state,
            &tx_for_exec,
            &ops_for_exec,
            &reload_execs,
        )?;
        engine_core
            .engine
            .execute(Some(&tx_for_exec), &ops_for_exec)?;
        Ok::<_, anyhow::Error>(snapshot)
    })
    .await
    .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;

    let snapshot = match result {
        Ok(snapshot) => snapshot,
        Err(e) => {
            // A failed apply still rolls back; record the real outcome
            // rather than always saying Failed.
            let rollback = core.rollback_transaction(&tx_id, &ops);
            core.state
                .mark_transaction(
                    &tx_id,
                    if rollback.is_ok() {
                        TxStatus::RolledBack
                    } else {
                        TxStatus::Failed
                    },
                )
                .map_err(internal)?;
            core.audit(
                actor,
                &plan.plugin,
                Some(&tx_id),
                &crate::audit::ops_digest(&ops),
                "apply-failed",
            );
            return Err(err("Conflict", json!({ "reason": format!("{e:#}") })));
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
        let rollback = core.rollback_transaction(&tx_id, &ops);
        core.state
            .mark_transaction(
                &tx_id,
                if rollback.is_ok() {
                    TxStatus::RolledBack
                } else {
                    TxStatus::Failed
                },
            )
            .map_err(internal)?;
        core.audit(
            actor,
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
            actor,
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
            actor,
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
