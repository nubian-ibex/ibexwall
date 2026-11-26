// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! System snapshots around risky changes (ADR-0050): off until the person
//! turns them on, taken by their own snapper, and a promise made in the plan:
//! when the first snapshot fails, nothing is changed.

use ibexwall_proto::{RiskFlag, SystemSnapshotStatus};
use ibexwall_sys::SnapshotKind;

use super::*;

/// The settings file written just before the first snapshot (ADR-0049), so a
/// restored system carries what had been chosen even where /var is outside it.
const STATE_EXPORT: &str = "state-export.json";

pub(crate) fn wanted(enabled: bool, risk: &[RiskFlag]) -> bool {
    enabled && !risk.is_empty()
}

/// The plan fingerprint also covers the switch: a plan reviewed without the
/// snapshot line, or with it, goes stale when the switch moves.
pub(crate) fn plan_fingerprint(core: &Core) -> anyhow::Result<String> {
    let mut fingerprint = core
        .config
        .read()
        .expect("config lock poisoned")
        .fingerprint();
    if core.state.system_snapshots_enabled()? {
        fingerprint.push_str("+system-snapshots");
    }
    Ok(fingerprint)
}

async fn availability(core: &Arc<Core>) -> Result<(), String> {
    let snapshots = Arc::clone(&core.snapshots);
    match tokio::task::spawn_blocking(move || snapshots.available()).await {
        Ok(result) => result.map_err(|e| format!("{e:#}")),
        Err(error) => Err(error.to_string()),
    }
}

pub(crate) async fn status(core: &Arc<Core>) -> Result<Reply, VarlinkError> {
    let enabled = core.state.system_snapshots_enabled().map_err(internal)?;
    let reason = availability(core).await.err();
    let status = SystemSnapshotStatus {
        enabled,
        available: reason.is_none(),
        reason,
    };
    Ok(Reply::result(json!({ "status": status })))
}

pub(crate) async fn set(
    core: &Arc<Core>,
    parameters: &Value,
    actor: &str,
) -> Result<Reply, VarlinkError> {
    let enabled = parameters
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| VarlinkError::invalid_parameter("enabled"))?;
    // Turning it off must work with a broken snapper: it is the way out.
    if enabled && let Err(reason) = availability(core).await {
        return Err(invalid_argument("enabled", reason));
    }
    let result = if enabled {
        "system-snapshots-on"
    } else {
        "system-snapshots-off"
    };
    core.try_audit(actor, "core", None, "", result)
        .map_err(internal)?;
    core.state.set_system_snapshots(enabled).map_err(internal)?;
    Ok(Reply::result(Value::Null))
}

/// Takes the `pre` snapshot for `tx`. An error means nothing may change.
pub(crate) async fn take_pre(core: &Arc<Core>, tx: &str) -> Result<u32, String> {
    let core = Arc::clone(core);
    let tx = tx.to_string();
    tokio::task::spawn_blocking(move || {
        let file = state_file::build(&core)?;
        let path = names::path_under(&core.root, names::CONFIG_DIR).join(STATE_EXPORT);
        crate::config::write_atomic(&path, &serde_json::to_string_pretty(&file)?)?;
        let number = core.snapshots.create(SnapshotKind::Pre, &tx)?;
        core.state.set_transaction_snapshot(&tx, number, None)?;
        anyhow::Ok(number)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("{e:#}"))
}

/// Closes the pair. The change has already happened (or been undone), so a
/// failure is reported, never turned into a failed apply.
pub(crate) async fn take_post(core: &Arc<Core>, tx: &str, pre: u32) -> Result<u32, String> {
    let worker = Arc::clone(core);
    let id = tx.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let number = worker.snapshots.create(SnapshotKind::Post(pre), &id)?;
        worker
            .state
            .set_transaction_snapshot(&id, pre, Some(number))?;
        anyhow::Ok(number)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r.map_err(|e| format!("{e:#}")));
    if let Err(error) = &result {
        tracing::warn!(transaction = tx, %error, "the snapshot after the change failed");
    }
    result
}
