// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Confirming, rolling back and watching transactions.

use super::*;

pub(crate) fn confirm(core: &Arc<Core>, parameters: &Value) -> Result<Reply, VarlinkError> {
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

pub(crate) fn rollback(core: &Arc<Core>, parameters: &Value) -> Result<Reply, VarlinkError> {
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

pub(crate) fn subscribe(core: &Arc<Core>) -> Result<Reply, VarlinkError> {
    // Streaming is handled in the Handler loop (see Api::handle); this
    // arm is unreachable for the real method name.
    let _ = core;
    Ok(Reply::result(Value::Null))
}

pub(crate) fn parse_unix(rfc3339: &str) -> i64 {
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
