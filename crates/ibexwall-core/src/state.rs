// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! SQLite state (spec §4.4): WAL mode, versioned migrations, and the
//! tables F1 needs. The chained audit log lives in `audit`.
//! `Connection` is `Send` but not `Sync`, so it sits behind a mutex
//! (single writer; the engine runs one transaction at a time anyway).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;

use ibexwall_proto::TransactionState;

/// One row of `transactions`.
#[derive(Debug, Clone)]
pub struct TxRow {
    pub id: String,
    pub plan_id: String,
    pub plugin: String,
    pub state: TransactionState,
    pub restore_point: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxStatus {
    Applying,
    PendingConfirm,
    Committed,
    RolledBack,
    Failed,
}

impl TxStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            TxStatus::Applying => "applying",
            TxStatus::PendingConfirm => "pending_confirm",
            TxStatus::Committed => "committed",
            TxStatus::RolledBack => "rolled_back",
            TxStatus::Failed => "failed",
        }
    }
}

pub struct State {
    conn: Mutex<Connection>,
    snapshots_dir: PathBuf,
}

const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_initial",
        "CREATE TABLE transactions (
         id TEXT PRIMARY KEY,
         plan_id TEXT NOT NULL,
         plugin TEXT NOT NULL,
         state TEXT NOT NULL,
         restore_point TEXT NOT NULL,
         confirm_deadline INTEGER,
         created_at TEXT NOT NULL
     );
     CREATE TABLE plans (
         id TEXT PRIMARY KEY,
         plugin TEXT NOT NULL,
         ops_json TEXT NOT NULL,
         requires_confirm INTEGER NOT NULL,
         confirm_timeout_s INTEGER NOT NULL,
         fingerprint TEXT NOT NULL,
         expires_at TEXT NOT NULL,
         created_at TEXT NOT NULL
     );
     CREATE TABLE findings (
         id TEXT PRIMARY KEY,
         plugin TEXT NOT NULL,
         severity TEXT NOT NULL,
         json TEXT NOT NULL,
         detected_at TEXT NOT NULL
     );
     CREATE TABLE events (
         seq INTEGER PRIMARY KEY AUTOINCREMENT,
         ts TEXT NOT NULL,
         source TEXT NOT NULL,
         kind TEXT NOT NULL,
         severity TEXT NOT NULL,
         json TEXT NOT NULL
     );
     CREATE TABLE plugins (
         id TEXT PRIMARY KEY,
         enabled INTEGER NOT NULL DEFAULT 0
     );
     ",
    ),
    (
        "0002_check_results",
        "CREATE TABLE check_results (
             plugin TEXT NOT NULL,
             id TEXT NOT NULL,
             severity TEXT NOT NULL,
             outcome TEXT NOT NULL,
             checked_at TEXT NOT NULL,
             PRIMARY KEY (plugin, id)
         );",
    ),
    ("0003_apps", ibexwall_apps::SCHEMA),
    ("0004_policy", ibexwall_apps::policy::POLICY_SCHEMA),
    (
        "0005_proposals",
        "CREATE TABLE proposals (
             id TEXT PRIMARY KEY,
             client TEXT NOT NULL,
             plugin TEXT NOT NULL,
             json TEXT NOT NULL,
             ops_digest TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             decided_at INTEGER
         );",
    ),
];

impl State {
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating {}", state_dir.display()))?;
        let conn = Connection::open(state_dir.join("state.db"))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let state = Self {
            conn: Mutex::new(conn),
            snapshots_dir: state_dir.join("snapshots"),
        };
        state.migrate()?;
        Ok(state)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.conn.lock().expect("lock poisoned");
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, name TEXT NOT NULL)",
            [],
        )?;
        let current: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;
        for (index, (name, sql)) in MIGRATIONS.iter().enumerate() {
            let version = (index + 1) as i64;
            if version <= current {
                continue;
            }
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_version (version, name) VALUES (?1, ?2)",
                rusqlite::params![version, name],
            )?;
            tx.commit()?;
            tracing::info!(version, name, "applied migration");
        }
        Ok(())
    }

    /// Runs `f` with the connection (audit helpers need it too).
    pub fn with_conn<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        f(&self.conn.lock().expect("lock poisoned"))
    }

    pub fn snapshots_dir(&self) -> &Path {
        &self.snapshots_dir
    }

    // plans -----------------------------------------------------------

    pub fn save_plan(&self, plan: &crate::engine::PersistedPlan) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO plans (id, plugin, ops_json, requires_confirm, confirm_timeout_s, fingerprint, expires_at, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    plan.id,
                    plan.plugin,
                    plan.ops_json,
                    plan.requires_confirm as i64,
                    plan.confirm_timeout_s,
                    plan.fingerprint,
                    plan.expires_at,
                    plan.created_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn load_plan(&self, id: &str) -> Result<Option<crate::engine::PersistedPlan>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, plugin, ops_json, requires_confirm, confirm_timeout_s, fingerprint, expires_at, created_at
                 FROM plans WHERE id = ?1",
            )?;
            let mut rows = stmt.query_map(rusqlite::params![id], |row| {
                Ok(crate::engine::PersistedPlan {
                    id: row.get(0)?,
                    plugin: row.get(1)?,
                    ops_json: row.get(2)?,
                    requires_confirm: row.get::<_, i64>(3)? != 0,
                    confirm_timeout_s: row.get(4)?,
                    fingerprint: row.get(5)?,
                    expires_at: row.get(6)?,
                    created_at: row.get(7)?,
                })
            })?;
            Ok(rows.next().transpose()?)
        })
    }

    // transactions ----------------------------------------------------

    pub fn insert_transaction(&self, row: &TxRow, created_at: &str) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO transactions (id, plan_id, plugin, state, restore_point, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    row.id,
                    row.plan_id,
                    row.plugin,
                    row.state_name(),
                    row.restore_point,
                    created_at,
                ],
            )?;
            Ok(())
        })
    }

    pub fn mark_transaction(&self, id: &str, status: TxStatus) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE transactions SET state = ?1 WHERE id = ?2",
                rusqlite::params![status.as_str(), id],
            )?;
            Ok(())
        })
    }

    pub fn set_confirm_deadline(&self, id: &str, deadline_unix: i64) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE transactions SET confirm_deadline = ?1, state = 'pending_confirm' WHERE id = ?2",
                rusqlite::params![deadline_unix, id],
            )?;
            Ok(())
        })
    }

    pub fn get_transaction(&self, id: &str) -> Result<Option<TxRow>> {
        self.with_conn(|conn| {
            let mut stmt =
                conn.prepare("SELECT id, plan_id, plugin, state FROM transactions WHERE id = ?1")?;
            let mut rows = stmt.query_map(rusqlite::params![id], row_to_tx)?;
            Ok(rows.next().transpose()?)
        })
    }

    /// Transactions whose changes are still on the machine, newest first:
    /// what an uninstall has to undo.
    pub fn list_active_transactions(&self) -> Result<Vec<TxRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, plan_id, plugin, state FROM transactions \
                 WHERE state IN ('committed', 'pending_confirm') ORDER BY created_at DESC, rowid DESC",
            )?;
            let rows = stmt.query_map([], row_to_tx)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// Transactions a restart must roll back (spec §4.5 recovery).
    pub fn list_recoverable_transactions(&self) -> Result<Vec<TxRow>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, plan_id, plugin, state FROM transactions
                 WHERE state IN ('applying', 'pending_confirm') ORDER BY created_at",
            )?;
            let rows = stmt.query_map([], row_to_tx)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    /// History rows for `History` (transaction events, newest first).
    pub fn list_transactions(&self, limit: usize) -> Result<Vec<(String, String, String)>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT id, plugin, state FROM transactions ORDER BY created_at DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
    }

    // findings / events / plugins --------------------------------------

    pub fn list_findings(&self, plugin: Option<&str>) -> Result<Vec<serde_json::Value>> {
        self.with_conn(|conn| {
            let (sql, param): (&str, Option<String>) = match plugin {
                Some(plugin) => (
                    "SELECT json FROM findings WHERE plugin = ?1 ORDER BY id",
                    Some(plugin.into()),
                ),
                None => ("SELECT json FROM findings ORDER BY id", None),
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(param), |row| {
                row.get::<_, String>(0)
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(serde_json::from_str(&row?)?);
            }
            Ok(out)
        })
    }

    /// Replaces everything a plugin reported in its previous check run
    /// (results and findings) with the new report, atomically.
    pub fn replace_check_run(
        &self,
        plugin: &str,
        report: &ibexwall_proto::CheckReport,
        checked_at: &str,
    ) -> Result<()> {
        self.with_conn(|conn| {
            let tx = conn.unchecked_transaction()?;
            tx.execute("DELETE FROM check_results WHERE plugin = ?1", [plugin])?;
            tx.execute("DELETE FROM findings WHERE plugin = ?1", [plugin])?;
            for result in &report.results {
                tx.execute(
                    "INSERT INTO check_results (plugin, id, severity, outcome, checked_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        plugin,
                        result.id,
                        enum_name(&result.severity)?,
                        enum_name(&result.outcome)?,
                        checked_at
                    ],
                )?;
            }
            for finding in &report.findings {
                tx.execute(
                    // A plugin that repeats a finding id must not fail the
                    // whole run: the first one is kept.
                    "INSERT OR IGNORE INTO findings (id, plugin, severity, json, detected_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        finding.id,
                        plugin,
                        enum_name(&finding.severity)?,
                        serde_json::to_string(finding)?,
                        finding.detected_at
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
    }

    /// Stored results of the enabled plugins (the score input).
    pub fn list_check_results(&self) -> Result<Vec<ibexwall_proto::CheckResult>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT r.id, r.severity, r.outcome FROM check_results r
                 JOIN plugins p ON p.id = r.plugin WHERE p.enabled = 1
                 ORDER BY r.plugin, r.id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, severity, outcome) = row?;
                out.push(ibexwall_proto::CheckResult {
                    id,
                    severity: serde_json::from_value(severity.into())?,
                    outcome: serde_json::from_value(outcome.into())?,
                });
            }
            Ok(out)
        })
    }

    pub fn append_event(&self, event: &ibexwall_proto::Event) -> Result<()> {
        self.with_conn(|conn| {
            let json = serde_json::to_string(event)?;
            conn.execute(
                "INSERT INTO events (ts, source, kind, severity, json) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    event.ts,
                    event.source,
                    event.kind,
                    serde_json::to_string(&event.severity)?,
                    json
                ],
            )?;
            Ok(())
        })
    }

    pub fn list_events(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT json FROM events ORDER BY seq DESC LIMIT ?1")?;
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                row.get::<_, String>(0)
            })?;
            let mut out = Vec::new();
            for row in rows {
                out.push(serde_json::from_str(&row?)?);
            }
            Ok(out)
        })
    }

    pub fn set_plugin_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO plugins (id, enabled) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled",
                rusqlite::params![id, enabled as i64],
            )?;
            Ok(())
        })
    }

    pub fn plugin_enabled(&self, id: &str) -> Result<bool> {
        self.with_conn(|conn| {
            let enabled: Option<i64> = conn
                .query_row(
                    "SELECT enabled FROM plugins WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .map(Some)
                .or_else(|err| match err {
                    rusqlite::Error::QueryReturnedNoRows => Ok(None),
                    other => Err(other),
                })?;
            Ok(enabled.unwrap_or(0) != 0)
        })
    }
}

/// Serializes a unit enum to its lowercase/snake_case name.
fn enum_name<T: serde::Serialize>(value: &T) -> Result<String> {
    match serde_json::to_value(value)? {
        serde_json::Value::String(name) => Ok(name),
        other => anyhow::bail!("expected a string enum, got {other}"),
    }
}

fn row_to_tx(row: &rusqlite::Row<'_>) -> rusqlite::Result<TxRow> {
    Ok(TxRow {
        id: row.get(0)?,
        plan_id: row.get(1)?,
        plugin: row.get(2)?,
        state: tx_state_from_name(&row.get::<_, String>(3)?),
        restore_point: String::new(),
    })
}

impl TxRow {
    fn state_name(&self) -> &'static str {
        tx_state_name(self.state)
    }
}

fn tx_state_name(state: TransactionState) -> &'static str {
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

fn tx_state_from_name(name: &str) -> TransactionState {
    match name {
        "planned" => TransactionState::Planned,
        "approved" => TransactionState::Approved,
        "applying" => TransactionState::Applying,
        "applied" => TransactionState::Applied,
        "pending_confirm" => TransactionState::PendingConfirm,
        "committed" => TransactionState::Committed,
        "rolled_back" => TransactionState::RolledBack,
        _ => TransactionState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state() -> (PathBuf, State) {
        let dir = std::env::temp_dir().join(format!(
            "ibexwall-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let state = State::open(&dir).unwrap();
        (dir, state)
    }

    #[test]
    fn migrations_are_idempotent() {
        let (dir, state) = temp_state();
        drop(state);
        State::open(&dir).unwrap(); // second open must not re-apply
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn transaction_lifecycle_roundtrip() {
        let (dir, state) = temp_state();
        let row = TxRow {
            id: "tx-1".into(),
            plan_id: "plan-1".into(),
            plugin: "dev.echo".into(),
            state: TransactionState::Applying,
            restore_point: "snapshots/tx-1".into(),
        };
        state
            .insert_transaction(&row, "2026-11-01T12:00:00Z")
            .unwrap();
        state
            .mark_transaction("tx-1", TxStatus::PendingConfirm)
            .unwrap();
        let recoverable = state.list_recoverable_transactions().unwrap();
        assert_eq!(recoverable.len(), 1);
        assert_eq!(recoverable[0].id, "tx-1");
        state
            .mark_transaction("tx-1", TxStatus::RolledBack)
            .unwrap();
        assert!(state.list_recoverable_transactions().unwrap().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_repeated_finding_id_keeps_the_first_and_does_not_fail_the_run() {
        use ibexwall_proto::{CheckReport, Finding, FindingStatus, Severity};
        let (dir, state) = temp_state();
        let finding = |title: &str| Finding {
            id: "dup.one".into(),
            plugin: "dev.echo".into(),
            severity: Severity::Low,
            title_key: title.into(),
            summary_key: "s".into(),
            args: Default::default(),
            references: vec![],
            remediation: None,
            status: FindingStatus::Open,
            detected_at: "2026-11-01T00:00:00Z".into(),
        };
        let report = CheckReport {
            results: vec![],
            findings: vec![finding("first"), finding("second")],
        };
        state.replace_check_run("dev.echo", &report, "now").unwrap();
        let stored = state.list_findings(Some("dev.echo")).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0]["title_key"], "first");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plugin_enabled_defaults_false() {
        let (dir, state) = temp_state();
        assert!(!state.plugin_enabled("dev.echo").unwrap());
        state.set_plugin_enabled("dev.echo", true).unwrap();
        assert!(state.plugin_enabled("dev.echo").unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn check_runs_replace_previous_results_and_only_enabled_plugins_count() {
        use ibexwall_proto::{CheckOutcome, CheckReport, CheckResult, Severity};
        let (dir, state) = temp_state();
        let result = |id: &str, outcome| CheckResult {
            id: id.into(),
            severity: Severity::High,
            outcome,
        };
        let first = CheckReport {
            results: vec![
                result("a", CheckOutcome::Fail),
                result("b", CheckOutcome::Pass),
            ],
            findings: vec![],
        };
        state.replace_check_run("p.one", &first, "t").unwrap();
        // Not enabled yet: nothing counts.
        assert!(state.list_check_results().unwrap().is_empty());
        state.set_plugin_enabled("p.one", true).unwrap();
        assert_eq!(state.list_check_results().unwrap().len(), 2);

        // A new run replaces the old one completely.
        let second = CheckReport {
            results: vec![result("a", CheckOutcome::Pass)],
            findings: vec![],
        };
        state.replace_check_run("p.one", &second, "t2").unwrap();
        let stored = state.list_check_results().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].outcome, CheckOutcome::Pass);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
