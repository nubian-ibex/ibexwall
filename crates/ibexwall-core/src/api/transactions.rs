// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Confirming, rolling back and watching transactions.

use super::*;

pub(crate) async fn confirm(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    let tx_id = str_field(parameters, "transaction_id")?;
    let _permit = core
        .tx_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
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
    // The watchdog rolls back at the deadline; past it, a Confirm that
    // slips in before the watchdog gets the lock must not win.
    if let Some(deadline) = core.state.confirm_deadline(&tx_id).map_err(internal)?
        && ibexwall_sys::RealClock.unix_now() > deadline
    {
        return Err(err(
            "Conflict",
            json!({ "reason": "the confirmation window has expired" }),
        ));
    }
    core.state
        .mark_transaction(&tx_id, TxStatus::Committed)
        .map_err(internal)?;
    core.audit(actor, &row.plugin, Some(&tx_id), "", "confirmed");
    core.refresh_plugin_findings(&row.plugin);
    core.publish_transaction_event(&Transaction {
        id: tx_id.clone(),
        plan_id: row.plan_id.clone(),
        state: TransactionState::Committed,
        started_at: ibexwall_sys::RealClock.rfc3339_now(),
        confirm_deadline: None,
        restore_point: row.restore_point.clone(),
    });
    Ok(Reply::result(Value::Null))
}

/// A newer active transaction that touches any of `ops`' targets would
/// be destroyed by rolling back an older one over it; return its id so
/// the caller can say "roll that one back first".
fn newer_overlap(core: &Core, target: &str, ops: &[Op]) -> anyhow::Result<Option<String>> {
    let targets = crate::engine::ops::op_targets(ops);
    let active = core.state.list_active_transactions()?; // newest first
    for row in active {
        if row.id == target {
            break; // the target itself and everything older is fine
        }
        let plan = core
            .state
            .load_plan(&row.plan_id)?
            .ok_or_else(|| anyhow::anyhow!("plan {} missing", row.plan_id))?;
        let other_ops: Vec<Op> = serde_json::from_str(&plan.ops_json)?;
        if crate::engine::ops::op_targets(&other_ops)
            .intersection(&targets)
            .next()
            .is_some()
        {
            return Ok(Some(row.id));
        }
    }
    Ok(None)
}

pub(crate) async fn rollback(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    let target = str_field(parameters, "target")?;
    let _permit = core
        .tx_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
    let row = core
        .state
        .get_transaction(&target)
        .map_err(internal)?
        .ok_or_else(|| not_found("transaction", &target))?;
    // Only a change that is actually on the machine can be rolled back;
    // a rolled back or failed transaction is not, and replaying its
    // inverses would restore stale snapshots over newer changes.
    match row.state {
        TransactionState::Committed | TransactionState::PendingConfirm => {}
        other => {
            return Err(invalid_argument(
                "target",
                format!("transaction is {}", tx_state(&other)),
            ));
        }
    }
    let plan = core
        .state
        .load_plan(&row.plan_id)
        .map_err(internal)?
        .ok_or_else(|| not_found("plan", &row.plan_id))?;
    let ops: Vec<Op> = serde_json::from_str(&plan.ops_json).map_err(internal)?;
    if let Some(newer) = newer_overlap(core, &target, &ops).map_err(internal)? {
        return Err(err(
            "Conflict",
            json!({ "reason": format!("a newer transaction {newer} touches the same target; roll it back first") }),
        ));
    }
    core.rollback_transaction_blocking(&target, &ops)
        .await
        .map_err(|e| err("Conflict", json!({ "reason": e.to_string() })))?;
    core.state
        .mark_transaction(&target, TxStatus::RolledBack)
        .map_err(internal)?;
    core.audit(
        actor,
        &row.plugin,
        Some(&target),
        &crate::audit::ops_digest(&ops),
        "rolled-back",
    );
    core.refresh_plugin_findings(&row.plugin);
    core.publish_transaction_event(&Transaction {
        id: target.clone(),
        plan_id: row.plan_id.clone(),
        state: TransactionState::RolledBack,
        started_at: ibexwall_sys::RealClock.rfc3339_now(),
        confirm_deadline: None,
        restore_point: String::new(),
    });
    // The rollback restored the machine, so this snapshot is no longer
    // needed; prune now instead of waiting for the next daemon start.
    if let Err(error) = core.state.prune(ibexwall_sys::RealClock.unix_now()) {
        tracing::warn!(%error, "pruning after rollback failed");
    }
    Ok(Reply::result(
        json!({ "transaction": { "id": target, "state": "rolled_back" } }),
    ))
}

pub(crate) fn subscribe(core: &Arc<Core>) -> Result<Reply, VarlinkError> {
    // Streaming is handled in the Handler loop (see Api::handle); this
    // arm is unreachable for the real method name.
    let _ = core;
    Ok(Reply::result(Value::Null))
}

pub(crate) fn parse_unix(rfc3339: &str) -> i64 {
    // Minimal parse of our own formatting (YYYY-MM-DDTHH:MM:SSZ).
    let bytes = rfc3339.as_bytes();
    // Fixed-width ASCII only: slicing a multi-byte character would panic.
    if bytes.len() < 19 || !rfc3339.is_ascii() {
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

pub(crate) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

pub(crate) fn tx_state(state: &TransactionState) -> &'static str {
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
pub(crate) fn spawn_confirmation_watchdog(
    core: Arc<Core>,
    tx_id: String,
    ops: Vec<Op>,
    deadline_unix: i64,
) {
    tokio::spawn(async move {
        let now = ibexwall_sys::RealClock.unix_now();
        let wait = (deadline_unix - now).max(0) as u64;
        tokio::time::sleep(Duration::from_secs(wait)).await;
        // Serialize with any apply or manual rollback, then re-read the
        // state: Confirm may have committed already, and the lock is the
        // only place this decision is made.
        let _permit = match core.tx_sem.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        if let Ok(Some(row)) = core.state.get_transaction(&tx_id) {
            if row.state != TransactionState::PendingConfirm {
                return;
            }
            tracing::warn!(transaction = %tx_id, "confirmation window expired, rolling back");
            let (status, result, final_state) =
                match core.rollback_transaction_blocking(&tx_id, &ops).await {
                    Ok(()) => (
                        TxStatus::RolledBack,
                        "confirm-timeout-rollback",
                        TransactionState::RolledBack,
                    ),
                    Err(error) => {
                        tracing::error!(transaction = %tx_id, %error, "automatic rollback failed");
                        (
                            TxStatus::Failed,
                            "confirm-timeout-rollback-failed",
                            TransactionState::Failed,
                        )
                    }
                };
            let _ = core.state.mark_transaction(&tx_id, status);
            core.audit(
                "system",
                &row.plugin,
                Some(&tx_id),
                &crate::audit::ops_digest(&ops),
                result,
            );
            core.publish_transaction_event(&Transaction {
                id: tx_id.clone(),
                plan_id: row.plan_id.clone(),
                state: final_state,
                started_at: ibexwall_sys::RealClock.rfc3339_now(),
                confirm_deadline: None,
                restore_point: String::new(),
            });
            if final_state == TransactionState::RolledBack {
                core.refresh_plugin_findings(&row.plugin);
            }
        }
    });
}

/// Restore points (ADR-0048): a named marker in the transaction log, and
/// going back by undoing every committed transaction made after it, newest
/// first. Creating and listing are reads; applying needs the rollback
/// authorization, is audited before anything moves (A-13), and a failure
/// part-way stops and names the transaction, leaving what is undone
/// accurate for a retry.
pub(crate) async fn create_restore_point(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    let name = str_field(parameters, "name")?;
    core.state.create_restore_point(&name).map_err(|e| {
        err(
            "InvalidArgument",
            json!({ "field": "name", "reason": e.to_string() }),
        )
    })?;
    core.try_audit(actor, "core", None, "", "restore-point-created")
        .map_err(internal)?;
    Ok(Reply::result(Value::Null))
}

pub(crate) async fn list_restore_points(core: &Arc<Core>) -> Result<Reply, VarlinkError> {
    let points: Vec<Value> = core
        .state
        .list_restore_points()
        .map_err(internal)?
        .into_iter()
        .map(|(name, tx, created_at)| json!({ "name": name, "tx": tx, "created_at": created_at }))
        .collect();
    Ok(Reply::result(json!({ "points": points })))
}

pub(crate) async fn restore_point(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    let name = str_field(parameters, "name")?;
    let apply = parameters.get("apply").and_then(Value::as_bool) == Some(true);
    let rows = core
        .state
        .restore_set(&name)
        .map_err(|e| not_found("restore_point", &e.to_string()))?;
    if !apply {
        return Ok(Reply::result(json!({
            "plan": rows.iter().map(|(id, plugin, state)| json!({
                "transaction": id, "plugin": plugin, "state": state,
            })).collect::<Vec<_>>(),
        })));
    }
    let _permit = core
        .tx_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(internal)?;
    core.try_audit(actor, "core", None, "", "restore-point-started")
        .map_err(internal)?;
    let mut undone: Vec<String> = Vec::new();
    let remaining = rows.len();
    for (tx, plugin, _) in rows {
        let row = match core.state.get_transaction(&tx).map_err(internal)? {
            Some(row) => row,
            None => continue,
        };
        let plan = match core.state.load_plan(&row.plan_id).map_err(internal)? {
            Some(plan) => plan,
            None => continue,
        };
        let ops: Vec<Op> = serde_json::from_str(&plan.ops_json).map_err(internal)?;
        if let Err(error) = core.rollback_transaction_blocking(&tx, &ops).await {
            return Err(err(
                "Conflict",
                json!({
                    "reason": format!("restoring to `{name}` stopped at transaction {tx}: {error}; {} change(s) after it are still in place", remaining - undone.len()),
                }),
            ));
        }
        core.state
            .mark_transaction(&tx, TxStatus::RolledBack)
            .map_err(internal)?;
        core.audit(
            actor,
            &plugin,
            Some(&tx),
            &crate::audit::ops_digest(&ops),
            "rolled-back",
        );
        core.publish_transaction_event(&Transaction {
            id: tx.clone(),
            plan_id: row.plan_id.clone(),
            state: TransactionState::RolledBack,
            started_at: ibexwall_sys::RealClock.rfc3339_now(),
            confirm_deadline: None,
            restore_point: String::new(),
        });
        core.refresh_plugin_findings(&plugin);
        undone.push(tx);
    }
    if let Err(error) = core.state.prune(ibexwall_sys::RealClock.unix_now()) {
        tracing::warn!(%error, "pruning after a restore failed");
    }
    Ok(Reply::result(json!({ "undone": undone })))
}
