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

/// The action needs the person to authenticate. `interactive_possible`
/// tells the client whether asking again with
/// `allowInteractiveAuthentication` can help: it cannot when this call
/// already asked and no agent answered (no graphical session, or the
/// prompt timed out).
fn authentication_required(action: &str, asked: bool) -> VarlinkError {
    err(
        "AuthenticationRequired",
        json!({ "action": action, "interactive_possible": !asked }),
    )
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
            // Policy methods are in a different interface; authorize and
            // dispatch before the Core prefix strip.
            if let Some(policy_method) = call.method.strip_prefix("com.ibexwall.Policy.") {
                let identity = identity_of(call.peer);
                // Reading the effective policy is reading: the person at
                // the machine may see what an organisation locked.
                let action = if policy_method == "GetEffective" {
                    names::POLKIT_READ
                } else {
                    names::POLKIT_POLICY_PROVIDER
                };
                match polkit.check(action.to_string(), identity).await {
                    Ok(Decision::Authorized) => {}
                    _ => {
                        let _ = out
                            .send(Reply::error(
                                "com.ibexwall.Core.PermissionDenied",
                                serde_json::json!({ "action": action }),
                            ))
                            .await;
                        return;
                    }
                }
                let actor = identity.actor();
                let reply =
                    match dispatch_policy(&core, policy_method, call.parameters, &actor).await {
                        Ok(reply) => reply,
                        Err(e) => Reply::error(e.name, e.parameters),
                    };
                let _ = out.send(reply).await;
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
    // ADR-0045: only a client that asks for it may raise a password dialog.
    let interactive = parameters
        .get("allowInteractiveAuthentication")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let decision = polkit
        .check_with(action.to_string(), identity, interactive)
        .await
        .map_err(|e| err("Conflict", json!({"reason": e.to_string()})))?;
    match decision {
        Decision::Authorized => {}
        Decision::NotAuthorized => return Err(permission_denied(action)),
        Decision::Challenge => return Err(authentication_required(action, interactive)),
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
            let format = parameters
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("json")
                .to_string();
            let (report, attestations, exceptions, audit_head) = compliance_data(core, &framework)?;
            let state_dir =
                ibexwall_proto::names::path_under(&core.root, ibexwall_proto::names::STATE_DIR);
            let now = ibexwall_sys::RealClock.unix_now();
            match format.as_str() {
                "json" => {
                    let envelope = crate::compliance::signed_envelope(
                        &state_dir,
                        &report,
                        &attestations,
                        &exceptions,
                        &audit_head,
                        now,
                    )
                    .map_err(internal)?;
                    Ok(Reply::result(
                        json!({ "format": "json", "export": envelope }),
                    ))
                }
                "csv" => Ok(Reply::result(json!({
                    "format": "csv",
                    "export": crate::compliance::csv(&report),
                }))),
                "oscal" => Ok(Reply::result(json!({
                    "format": "oscal",
                    "export": crate::compliance::oscal(&report, now),
                }))),
                _ => Err(invalid_argument("format", "json, csv or oscal".into())),
            }
        }
        _ => Err(VarlinkError::new(
            ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
            json!({ "method": method }),
        )),
    }
}

/// Policy-interface methods authorized by `POLKIT_POLICY_PROVIDER` (spec
/// §4.14, Appendix C). `ApplyBundle` verifies the bundle and applies its
/// settings and locks as the org layer; `GetEffective` reports the
/// effective config.
async fn dispatch_policy(
    core: &Arc<Core>,
    method: &str,
    parameters: Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    match method {
        "ApplyBundle" => {
            let bundle_value = parameters
                .get("bundle")
                .ok_or_else(|| VarlinkError::invalid_parameter("bundle"))?;
            let bundle: ibexwall_proto::PolicyBundle = serde_json::from_value(bundle_value.clone())
                .map_err(|e| {
                    VarlinkError::invalid_parameter("bundle");
                    err(
                        "InvalidArgument",
                        json!({ "field": "bundle", "reason": e.to_string() }),
                    )
                })?;
            let trust_dir = ibexwall_proto::names::path_under(&core.root, "/etc/ibexwall/trust");
            let current_version = core
                .state
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT value FROM config WHERE key = 'policy_version'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .ok()
                })
                .map(|v| v as u64);
            crate::policy::verify_bundle(
                &bundle,
                &trust_dir,
                current_version,
                ibexwall_sys::RealClock.unix_now(),
            )
            .map_err(|e| match &e {
                crate::policy::PolicyVerifyError::Expired(expires) => {
                    err("Expired", json!({ "expires_at": expires }))
                }
                crate::policy::PolicyVerifyError::VersionRollback { current, offered } => err(
                    "VersionRollback",
                    json!({ "current": current, "offered": offered }),
                ),
                crate::policy::PolicyVerifyError::BadSignature => {
                    let key_id = bundle
                        .signature
                        .as_ref()
                        .map(|s| s.key_id.as_str())
                        .unwrap_or("?");
                    err("InvalidSignature", json!({ "key_id": key_id }))
                }
                _ => err(
                    "InvalidArgument",
                    json!({ "field": "bundle", "reason": e.to_string() }),
                ),
            })?;
            // Apply settings as the org layer, then persist locks and version.
            let config_dir =
                ibexwall_proto::names::path_under(&core.root, ibexwall_proto::names::CONFIG_DIR);
            let org_path = config_dir.join("org.toml");
            let mut org = toml::Table::new();
            org.insert(
                "lock".into(),
                toml::Value::try_from(Vec::clone(&bundle.locks))
                    .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?,
            );
            if let Some(settings) = bundle.settings.as_object() {
                let mut plugins = toml::Table::new();
                for (plugin, value) in settings {
                    plugins.insert(
                        plugin.clone(),
                        toml::Value::try_from(value.clone())
                            .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?,
                    );
                }
                org.insert("plugins".into(), toml::Value::Table(plugins));
            }
            std::fs::create_dir_all(&config_dir)
                .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
            std::fs::write(
                &org_path,
                toml::to_string_pretty(&org)
                    .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?,
            )
            .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
            core.state
                .with_conn(|conn| {
                    conn.execute(
                        "INSERT OR REPLACE INTO config (key, value) VALUES ('policy_version', ?1)",
                        rusqlite::params![bundle.version as i64],
                    )
                })
                .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
            core.reload_config();
            core.audit(actor, "core", None, "", "policy-applied");
            let locks: Vec<String> = bundle.locks.clone();
            Ok(Reply::result(json!({
                "version": bundle.version,
                "locks": locks,
            })))
        }
        "GetEffective" => {
            let config = core.config.read().expect("config lock poisoned");
            let locks: Vec<String> = config.locks.clone();
            let managed = core
                .state
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT 1 FROM config WHERE key = 'policy_version'",
                        [],
                        |_| Ok(()),
                    )
                    .ok()
                })
                .is_some();
            Ok(Reply::result(json!({
                "config": json!({}),
                "locks": locks,
                "sources": json!({}),
                "managed": managed,
            })))
        }
        "BuildReport" => {
            let now = ibexwall_sys::format_rfc3339(ibexwall_sys::RealClock.unix_now());
            let posture_value = posture(core);
            let score = posture_value["score"].as_u64().unwrap_or(0) as u8;
            let protections: Vec<ibexwall_proto::ProtectionStatus> =
                serde_json::from_value(posture_value["protections"].clone()).unwrap_or_default();
            let findings: Vec<serde_json::Value> =
                core.state.list_findings(None).map_err(internal)?;
            let findings_open = findings.len() as u32;
            let mut findings_by_severity: std::collections::BTreeMap<String, u32> =
                std::collections::BTreeMap::new();
            for f in &findings {
                let sev = f
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_default();
                *findings_by_severity.entry(sev).or_default() += 1;
            }
            let policy_version = core
                .state
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT value FROM config WHERE key = 'policy_version'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .ok()
                })
                .map(|v| v as u64);
            let report = ibexwall_proto::Report {
                schema: ibexwall_proto::report::REPORT_SCHEMA.into(),
                generated_at: now,
                policy_version,
                score,
                protections,
                findings_open,
                findings_by_severity,
                blocked_connections: None,
                change_audit: vec![],
                package_versions: std::collections::BTreeMap::new(),
            };
            Ok(Reply::result(
                serde_json::to_value(&report).map_err(internal)?,
            ))
        }
        "UseBreakGlass" => {
            let code = str_field(&parameters, "code")?;
            let parts: Vec<&str> = code.splitn(3, ':').collect();
            let (key_id, sig_b64, scope_b64) = if parts.len() == 3 {
                (parts[0], parts[1], parts[2])
            } else {
                return Err(invalid_argument("code", "expected key_id:sig:scope".into()));
            };
            use base64::Engine as _;
            let sig_bytes = base64::engine::general_purpose::STANDARD
                .decode(sig_b64)
                .map_err(|_| invalid_argument("code", "bad signature encoding".into()))?;
            let sig_bytes: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| invalid_argument("code", "bad signature length".into()))?;
            let scope = base64::engine::general_purpose::STANDARD
                .decode(scope_b64)
                .map_err(|_| invalid_argument("code", "bad scope encoding".into()))?;
            let trust_dir = ibexwall_proto::names::path_under(&core.root, "/etc/ibexwall/trust");
            let anchor_path = trust_dir.join(format!("{key_id}.pub"));
            let key_bytes = crate::policy::anchor_public_key(&anchor_path)
                .map_err(|_| invalid_argument("code", "unknown key".into()))?;
            use ed25519_dalek::Verifier as _;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| invalid_argument("code", "bad key".into()))?;
            key.verify(&scope, &ed25519_dalek::Signature::from_bytes(&sig_bytes))
                .map_err(|_| invalid_argument("code", "bad signature".into()))?;
            let scope_value: Value = serde_json::from_slice(&scope)
                .map_err(|_| invalid_argument("code", "bad scope JSON".into()))?;
            let expires_at = scope_value["expires_at"]
                .as_str()
                .ok_or_else(|| invalid_argument("code", "missing expires_at".into()))?;
            if crate::compliance::parse_unix(expires_at) <= ibexwall_sys::RealClock.unix_now() {
                return Err(invalid_argument("code", "expired".into()));
            }
            let unlocked: Vec<String> = scope_value["lock_patterns"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect();
            if unlocked.is_empty() {
                return Err(invalid_argument("code", "no lock patterns".into()));
            }
            let config_dir =
                ibexwall_proto::names::path_under(&core.root, ibexwall_proto::names::CONFIG_DIR);
            let org_path = config_dir.join("org.toml");
            let doc_text = std::fs::read_to_string(&org_path).unwrap_or_default();
            let mut doc: toml::Table = doc_text.parse().unwrap_or_default();
            if let Some(toml::Value::Array(old_locks)) = doc.get("lock") {
                let new_locks: Vec<toml::Value> = old_locks
                    .iter()
                    .filter(|v| {
                        !unlocked
                            .iter()
                            .any(|u| v.as_str().is_some_and(|s| s == u.as_str()))
                    })
                    .cloned()
                    .collect();
                doc.insert("lock".into(), toml::Value::Array(new_locks));
            }
            std::fs::write(&org_path, toml::to_string_pretty(&doc).map_err(internal)?)
                .map_err(internal)?;
            core.reload_config();
            core.audit(actor, "core", None, "", "break-glass");
            Ok(Reply::result(json!({
                "unlocked": unlocked,
                "expires_at": expires_at,
            })))
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
/// The report, the attestations, the exceptions and the audit-chain head
/// for one profile.
fn compliance_data(
    core: &Core,
    framework: &str,
) -> Result<
    (
        ibexwall_proto::ComplianceReport,
        Vec<ibexwall_proto::Attestation>,
        Vec<ibexwall_proto::Exception>,
        String,
    ),
    VarlinkError,
> {
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
    let audit_head = core
        .state
        .with_conn(crate::audit::head_hash)
        .unwrap_or_default();
    Ok((report, attestations, exceptions, audit_head))
}

fn compliance_report(core: &Core, framework: &str) -> Result<Value, VarlinkError> {
    let (report, _, _, _) = compliance_data(core, framework)?;
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
    let ops = core.plugins.plan(&plugin, patch).await.map_err(|e| {
        // The plugin refused the request and said why: pass that on, so
        // the app shows the reason instead of a transport error.
        match e
            .chain()
            .find_map(|cause| cause.downcast_ref::<VarlinkError>())
        {
            Some(refusal) if refusal.name.ends_with(".InvalidArgument") => {
                err("InvalidArgument", refusal.parameters.clone())
            }
            _ => err("Conflict", json!({ "reason": e.to_string() })),
        }
    })?;

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
