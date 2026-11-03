// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IbexWall core daemon library: configuration layers, state (SQLite),
//! the chained audit log, the change engine, the plugin supervisor and
//! the varlink API surface.

pub mod api;
pub mod ask;
pub mod audit;
pub mod config;
pub mod engine;
pub mod events;
pub mod firewall;
pub mod monitor;
pub mod plugins;
pub mod state;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UnixListener;

use ibexwall_proto::names;
use ibexwall_proto::{Event, Op, Severity, Transaction, TransactionState};
use ibexwall_sys::Clock;
use ibexwall_varlink::{ServiceInfo, serve as serve_varlink};

use crate::state::TxStatus;

pub use state::TxRow;

/// Everything the API dispatches against.
pub struct Core {
    pub config: config::Layers,
    pub state: state::State,
    pub engine: engine::Engine,
    pub plugins: Arc<plugins::Supervisor>,
    pub events: events::Bus,
    pub monitor: monitor::Monitor,
    /// The root the daemon works under (`/`, or a sandbox).
    pub root: PathBuf,
}

/// Serves the varlink API on `socket` (dev/tests) until the process is
/// stopped.
pub async fn serve(socket: &std::path::Path, dev_key: Option<PathBuf>) -> Result<()> {
    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    // The socket is world-connectable; authorization is per method via
    // polkit (ibexwalld.socket uses SocketMode=0666).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))
            .with_context(|| format!("chmod {}", socket.display()))?;
    }
    serve_listener(listener, dev_key).await
}

/// Under a sandbox root (`IBEXWALL_ROOT`) the host's polkit has no
/// IbexWall policy installed, and installing it would touch the host.
/// The sandbox daemon therefore authorizes every action for its own uid
/// only; system-level executors stay disabled by the sandbox bundle.
fn sandbox_polkit() -> Option<Arc<dyn ibexwall_sys::Polkit>> {
    if names::root() == std::path::Path::new("/") {
        return None;
    }
    let mut fake = ibexwall_sys::FakePolkit::new();
    for action in names::polkit_actions() {
        fake.allow(ibexwall_sys::current_uid(), action);
    }
    Some(Arc::new(fake))
}

async fn serve_listener(listener: UnixListener, dev_key: Option<PathBuf>) -> Result<()> {
    let core = Core::open(names::root(), dev_key).await?;
    notify_ready();
    let api = match sandbox_polkit() {
        Some(polkit) => api::Api::with_polkit(Arc::new(core), polkit),
        None => api::Api::new(core),
    };
    start_monitor(api.core());
    serve_varlink(listener, service_info(), Arc::new(api)).await
}

/// Serves on a listener inherited from systemd socket activation.
pub async fn serve_activated(
    listener: std::os::unix::net::UnixListener,
    dev_key: Option<PathBuf>,
) -> Result<()> {
    listener.set_nonblocking(true)?;
    serve_listener(UnixListener::from_std(listener)?, dev_key).await
}

/// Tells systemd the daemon is ready (Type=notify) and starts the
/// watchdog heartbeat when WatchdogSec is set. No-ops outside systemd.
fn notify_ready() {
    use sd_notify::NotifyState;
    let _ = sd_notify::notify(&[NotifyState::Ready]);
    if let Some(timeout) = sd_notify::watchdog_enabled() {
        let period = timeout / 2;
        tokio::spawn(async move {
            loop {
                let _ = sd_notify::notify(&[NotifyState::Watchdog]);
                tokio::time::sleep(period).await;
            }
        });
    }
}

/// Opens the two local channels the monitor uses: the resolver's answers
/// and the monitor unit's connection lines. Both are sockets the core
/// owns; the loader itself runs in `ibexwall-monitor.service` (ADR-0032),
/// which a sandbox root never starts.
fn start_monitor(core: Arc<Core>) {
    let answers = names::dns_answers_socket();
    let answers_core = Arc::clone(&core);
    tokio::spawn(async move {
        if let Err(error) = monitor::listen_answers(answers_core, answers).await {
            tracing::warn!(%error, "resolver answers channel unavailable");
        }
    });
    let socket = names::monitor_socket();
    tokio::spawn(async move {
        if let Err(error) = monitor::serve_monitor(core, socket).await {
            tracing::warn!(%error, "monitor channel unavailable");
        }
    });
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
            engine: engine::Engine::with(ibexwall_sys::SysBundle::real_under(&root)),
            plugins,
            events,
            monitor: monitor::Monitor::new(root.clone()),
            root,
        };
        // nftables keeps nothing across a reboot: put our chains back
        // first, so that recovering an interrupted transaction (which
        // restores chains to what they were) acts on the real state.
        match core.engine.restore_nft(&core.nft_file()) {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "restored nftables chains after a restart"),
            Err(error) => tracing::error!(%error, "restoring nftables chains failed"),
        }
        core.recover_pending_transactions()?;
        core.persist_nft();
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
        let result = self.engine.rollback(&self.state, tx);
        // Whatever the inverses restored is what must survive a restart.
        self.persist_nft();
        result
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

    /// Where the active nftables chains are kept across restarts.
    fn nft_file(&self) -> PathBuf {
        self.state
            .snapshots_dir()
            .parent()
            .map(|dir| dir.join("nft-active.json"))
            .unwrap_or_else(|| PathBuf::from("nft-active.json"))
    }

    /// Records the chains as they are now; called whenever a transaction
    /// changes state, so applying, confirming and rolling back all stick.
    pub fn persist_nft(&self) {
        if let Err(error) = self.engine.persist_nft(&self.nft_file()) {
            tracing::error!(%error, "persisting nftables chains failed");
        }
    }

    /// Publishes + persists a transaction lifecycle event.
    pub fn publish_transaction_event(&self, transaction: &Transaction) {
        self.persist_nft();
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
