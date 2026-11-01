// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IbexWall core daemon library: configuration layers, state (SQLite),
//! the chained audit log, the change engine, the plugin supervisor and
//! the varlink API surface.

pub mod api;
pub mod audit;
pub mod config;
pub mod engine;
pub mod events;
pub mod plugins;
pub mod state;

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;

use ibexwall_proto::names;
use ibexwall_proto::{Event, Op, Severity, Transaction, TransactionState};
use ibexwall_sys::Clock;
use ibexwall_varlink::{ServiceInfo, serve as serve_varlink, serve_with_fd};

use crate::state::TxStatus;

pub use state::TxRow;

/// Everything the API dispatches against.
pub struct Core {
    pub config: config::Layers,
    pub state: state::State,
    pub engine: engine::Engine,
    pub plugins: Arc<plugins::Supervisor>,
    pub events: events::Bus,
}

/// Serves the varlink API on `socket` (dev/tests) until the process is
/// stopped.
pub async fn serve(socket: &std::path::Path, dev_key: Option<PathBuf>) -> Result<()> {
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    serve_listener(listener, dev_key).await
}

async fn serve_listener(listener: UnixListener, dev_key: Option<PathBuf>) -> Result<()> {
    let core = Core::open(names::root(), dev_key).await?;
    serve_varlink(listener, service_info(), Arc::new(api::Api::new(core))).await
}

/// Serves on an inherited listening fd (systemd socket activation).
pub async fn serve_fd(fd: OwnedFd, dev_key: Option<PathBuf>) -> Result<()> {
    let core = Core::open(names::root(), dev_key).await?;
    serve_with_fd(fd, service_info(), Arc::new(api::Api::new(core))).await
}

fn service_info() -> ServiceInfo {
    let mut interfaces = std::collections::HashMap::new();
    for (name, idl) in [
        (
            names::IFACE_CORE,
            include_str!("../../../spec/idl/com.ibexwall.Core.varlink"),
        ),
        (
            names::IFACE_PLUGIN,
            include_str!("../../../spec/idl/com.ibexwall.Plugin.varlink"),
        ),
        (
            names::IFACE_POLICY,
            include_str!("../../../spec/idl/com.ibexwall.Policy.varlink"),
        ),
    ] {
        interfaces.insert(name.to_string(), idl.to_string());
    }
    ServiceInfo {
        vendor: "Nubian Ibex".into(),
        product: names::PRODUCT_NAME.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        url: format!("https://{}", names::DOMAIN_MAIN),
        interfaces,
    }
}

impl Core {
    /// Opens state, recovers crashed transactions, loads plugins.
    pub async fn open(root: PathBuf, dev_key: Option<PathBuf>) -> Result<Self> {
        let state =
            state::State::open(&ibexwall_proto::names::path_under(&root, names::STATE_DIR))?;
        let events = events::Bus::new();
        let config = config::Layers::load(&root)?;
        let plugins = Arc::new(plugins::Supervisor::discover(&root, dev_key).await?);
        let mut core = Self {
            config,
            state,
            engine: engine::Engine::new(),
            plugins,
            events,
        };
        core.recover_pending_transactions()?;
        Ok(core)
    }

    /// Rolls back transactions left in `applying`/`pending_confirm` by a
    /// crash, and notifies (spec §4.5 recovery).
    fn recover_pending_transactions(&mut self) -> Result<()> {
        let pending = self.state.list_recoverable_transactions()?;
        for tx in pending {
            tracing::warn!(transaction = %tx.id, "recovering interrupted transaction (rollback)");
            let plan = self.state.load_plan(&tx.plan_id).ok().flatten();
            let ops: Vec<Op> = plan
                .and_then(|p| serde_json::from_str(&p.ops_json).ok())
                .unwrap_or_default();
            let result = self.rollback_transaction(&tx.id, &ops);
            self.state.mark_transaction(
                &tx.id,
                if result.is_ok() {
                    TxStatus::RolledBack
                } else {
                    TxStatus::Failed
                },
            )?;
            self.audit(
                "system",
                &tx.plugin,
                Some(&tx.id),
                "",
                "crash-recovery-rollback",
            );
            self.publish_transaction_event(&Transaction {
                id: tx.id.clone(),
                plan_id: tx.plan_id.clone(),
                state: TransactionState::RolledBack,
                started_at: now(),
                confirm_deadline: None,
                restore_point: String::new(),
            });
        }
        Ok(())
    }

    /// Applies the snapshot inverses for `tx` (no status marking; callers
    /// decide the final state).
    pub fn rollback_transaction(&self, tx: &str, ops: &[Op]) -> Result<()> {
        let _ = ops; // inverses come from the snapshot manifest
        self.engine.rollback(&self.state, tx)
    }

    pub fn manifest(&self, plugin: &str) -> Result<ibexwall_proto::Manifest> {
        Ok(self.plugins.manifest(plugin)?.clone())
    }

    /// Appends to the audit chain (spec §4.4).
    pub fn audit(
        &self,
        actor: &str,
        plugin: &str,
        transaction: Option<&str>,
        ops_digest: &str,
        result: &str,
    ) {
        let ts = now();
        let appended = self.state.with_conn(|conn| {
            audit::append(conn, &ts, actor, plugin, transaction, ops_digest, result)
        });
        if let Err(err) = appended {
            tracing::error!(error = %err, "audit append failed");
        }
    }

    pub fn audit_verify(&self) -> audit::Verification {
        self.state
            .with_conn(audit::verify)
            .unwrap_or(audit::Verification::Broken {
                seq: 0,
                reason: "verification error".into(),
            })
    }

    /// Publishes + persists a transaction lifecycle event.
    pub fn publish_transaction_event(&self, transaction: &Transaction) {
        let event = Event {
            ts: now(),
            source: "core".into(),
            kind: format!("transaction.{}", transaction_state_name(transaction.state)),
            severity: Severity::Info,
            app: None,
            data: serde_json::json!({
                "transaction": transaction.id,
                "plan": transaction.plan_id,
                "state": transaction_state_name(transaction.state),
            }),
            untrusted: serde_json::Value::Null,
        };
        self.events.publish(event.clone());
        if let Err(err) = self.state.append_event(&event) {
            tracing::error!(error = %err, "event persist failed");
        }
    }
}

fn transaction_state_name(state: TransactionState) -> &'static str {
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

fn now() -> String {
    ibexwall_sys::RealClock.rfc3339_now()
}
