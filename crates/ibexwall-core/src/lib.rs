// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! IbexWall core daemon library: configuration layers, state (SQLite),
//! the chained audit log, the change engine, the plugin supervisor and
//! the varlink API surface.

pub mod api;
pub mod ask;
pub mod audit;
pub mod compliance;
pub mod config;
pub mod engine;
pub mod events;
pub mod firewall;
pub mod monitor;
pub mod plugins;
pub mod proposals;
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
    pub config: std::sync::RwLock<config::Layers>,
    pub state: state::State,
    pub engine: engine::Engine,
    pub plugins: Arc<plugins::Supervisor>,
    pub events: events::Bus,
    pub monitor: monitor::Monitor,
    /// The root the daemon works under (`/`, or a sandbox).
    pub root: PathBuf,
    /// Serializes every engine and state mutation: apply, confirm,
    /// rollback, the confirmation watchdog and proposal decisions run
    /// one at a time, so a snapshot can never capture another change
    /// mid-flight and a rollback can never interleave with an apply.
    pub tx_sem: Arc<tokio::sync::Semaphore>,
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

/// What an uninstall undid.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub rolled_back: usize,
    /// `(transaction, why)` for each one that could not be undone.
    pub failed: Vec<(String, String)>,
    pub chains_removed: usize,
}

/// Opens the state under `root` and undoes IbexWall's changes: the body of
/// `ibexwalld --cleanup`, run by the package before it removes the files.
pub async fn cleanup(root: PathBuf, dev_key: Option<PathBuf>) -> Result<CleanupReport> {
    Core::open(root, dev_key).await?.cleanup()
}

impl Core {
    /// Opens state, restores the firewall, recovers crashed transactions,
    /// then loads the configuration and plugins. The firewall restore
    /// runs first: a broken config or plugin file must not leave the
    /// machine without its kill switch after a reboot.
    pub async fn open(root: PathBuf, dev_key: Option<PathBuf>) -> Result<Self> {
        let state =
            state::State::open(&ibexwall_proto::names::path_under(&root, names::STATE_DIR))?;
        let events = events::Bus::new();
        let engine = engine::Engine::with(ibexwall_sys::SysBundle::real_under(&root));
        let nft_file = state
            .snapshots_dir()
            .parent()
            .map(|dir| dir.join("nft-active.json"))
            .unwrap_or_else(|| PathBuf::from("nft-active.json"));

        // nftables keeps nothing across a reboot: put our chains back
        // first, so that recovering an interrupted transaction (which
        // restores chains to what they were) acts on the real state.
        // A failed restore must not reach the persist step: persisting
        // after a failure would see no chains and delete the saved
        // firewall (kill switch included) for the next boot.
        let mut restored_ok = true;
        match engine.restore_nft(&nft_file) {
            Ok(0) => {}
            Ok(count) => tracing::info!(count, "restored nftables chains after a restart"),
            Err(error) => {
                restored_ok = false;
                tracing::error!(%error, "restoring nftables chains failed");
            }
        }

        let config = config::Layers::load(&root)?;
        let plugins = Arc::new(plugins::Supervisor::discover(&root, dev_key).await?);
        let mut core = Self {
            config: std::sync::RwLock::new(config),
            state,
            engine,
            plugins,
            events,
            monitor: monitor::Monitor::new(root.clone()),
            root,
            tx_sem: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        core.recover_pending_transactions()?;
        if restored_ok {
            core.persist_nft();
        }
        // Bound the tables that would otherwise grow forever.
        core.state.prune(ibexwall_sys::RealClock.unix_now())?;
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
            let (status, event_state, audit_result) = match &result {
                Ok(()) => (
                    TxStatus::RolledBack,
                    TransactionState::RolledBack,
                    "crash-recovery-rollback",
                ),
                Err(_) => (
                    TxStatus::Failed,
                    TransactionState::Failed,
                    "crash-recovery-rollback-failed",
                ),
            };
            self.state.mark_transaction(&tx.id, status)?;
            self.audit("system", &tx.plugin, Some(&tx.id), "", audit_result);
            self.publish_transaction_event(&Transaction {
                id: tx.id.clone(),
                plan_id: tx.plan_id.clone(),
                state: event_state,
                started_at: now(),
                confirm_deadline: None,
                restore_point: String::new(),
            });
        }
        Ok(())
    }

    /// Undoes everything IbexWall changed on this machine, for an
    /// uninstall (spec §4.15): every transaction still in effect is rolled
    /// back, newest first, through the snapshot it took before it ran, and
    /// whatever is left of IbexWall's nftables table is removed. The user's
    /// data (state, audit log, settings) stays until a purge. A transaction
    /// that cannot be undone is reported and does not stop the rest.
    pub fn cleanup(&self) -> Result<CleanupReport> {
        let mut report = CleanupReport::default();
        for tx in self.state.list_rollback_candidates()? {
            let ops: Vec<Op> = self
                .state
                .load_plan(&tx.plan_id)
                .ok()
                .flatten()
                .and_then(|p| serde_json::from_str(&p.ops_json).ok())
                .unwrap_or_default();
            match self.rollback_transaction(&tx.id, &ops) {
                Ok(()) => {
                    self.state.mark_transaction(&tx.id, TxStatus::RolledBack)?;
                    self.audit("system", &tx.plugin, Some(&tx.id), "", "uninstall-rollback");
                    report.rolled_back += 1;
                }
                Err(error) => {
                    tracing::error!(transaction = %tx.id, %error, "uninstall: rollback failed");
                    report.failed.push((tx.id.clone(), error.to_string()));
                }
            }
        }
        report.chains_removed = self.engine.remove_nft_table()?;
        let _ = std::fs::remove_file(self.nft_file());
        Ok(report)
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

    /// Re-reads the configuration so a change on disk (an organization
    /// lock, a user setting) takes effect without a restart. Called
    /// before planning and applying; a broken new file keeps the last
    /// good configuration and logs, rather than blocking the daemon.
    pub fn reload_config(&self) {
        match config::Layers::load(&self.root) {
            Ok(fresh) => {
                *self.config.write().expect("config lock poisoned") = fresh;
            }
            Err(error) => {
                tracing::warn!(%error, "reloading the configuration failed; keeping the last good one");
            }
        }
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
