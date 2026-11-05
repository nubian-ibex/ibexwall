// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The connection monitor, core side. The eBPF loader runs as a privileged
//! child process (its own boundary: aya and CAP_BPF stay out of the core)
//! and prints one JSON object per connection; this module reads them,
//! correlates the destination with the resolver's answers, rolls them up
//! and raises events. Monitor only: nothing here blocks traffic.
//!
//! Every field of a line is untrusted data (process names, paths, cgroup
//! text): it is parsed and stored, never interpolated into anything.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};

use ibexwall_apps::{Alert, Correlator, Observation, normalize_domain};
use ibexwall_identity::{AppKind, Identity};
use ibexwall_proto::{AppDestination, AppEntry, Event, MonitorStatus, Severity};
use ibexwall_sys::{Clock, format_rfc3339};

use crate::Core;

/// One line from the loader.
#[derive(Debug, Deserialize)]
struct Line {
    #[serde(default)]
    exe: Option<String>,
    #[serde(default)]
    exe_hash: Option<String>,
    #[serde(default)]
    package: Option<String>,
    dst: String,
    port: u16,
    kind: AppKind,
    #[serde(default)]
    id: String,
}

/// A status line from the loader instead of a connection.
#[derive(Debug, Deserialize)]
struct Meta {
    meta: String,
    #[serde(default)]
    reason: String,
}

const ASK_CHAIN: &str = "apps_ask";
const REFUSE_CHAIN: &str = "apps_ask_refuse";

/// How often the package-manager database mtime is re-read.
const DB_MTIME_TTL: i64 = 5;

pub struct Monitor {
    correlator: Mutex<Correlator>,
    status: Mutex<MonitorStatus>,
    package_db: Mutex<(i64, Option<i64>)>,
    root: PathBuf,
    /// The policy line the monitor unit should be enforcing; every
    /// connection of the unit gets the current one, then each change.
    policy: tokio::sync::watch::Sender<String>,
    /// Lines for the unit that are events, not state: answers to Ask.
    outbound: tokio::sync::broadcast::Sender<String>,
    pub(crate) asks: crate::ask::Asks,
}

impl Monitor {
    pub fn new(root: PathBuf) -> Self {
        Self {
            correlator: Mutex::new(Correlator::default()),
            status: Mutex::new(MonitorStatus {
                running: false,
                reason: Some("not started".into()),
            }),
            package_db: Mutex::new((0, None)),
            root,
            policy: tokio::sync::watch::channel(String::new()).0,
            outbound: tokio::sync::broadcast::channel(256).0,
            asks: crate::ask::Asks::default(),
        }
    }

    /// Sends a line to the monitor unit, if one is connected.
    pub(crate) fn send_to_unit(&self, line: String) {
        let _ = self.outbound.send(line);
    }

    /// The domain the resolver last answered with this address.
    pub(crate) fn lookup_domain(&self, ip: IpAddr, now: i64) -> Option<String> {
        self.correlator
            .lock()
            .expect("lock poisoned")
            .lookup(ip, now.max(0) as u64)
            .map(str::to_string)
    }

    /// Rebuilds the policy from the stored modes and pushes it.
    pub fn refresh_policy(&self, core: &Core) -> Result<()> {
        let policy = core.state.with_conn(|conn| {
            let apps = ibexwall_apps::list_apps(conn)?;
            let modes = ibexwall_apps::policy::modes(conn)?;
            let default = ibexwall_apps::policy::default_mode(conn)?;
            let (timeout, fallback) = ibexwall_apps::policy::ask_settings(conn)?;
            let mut policy = ibexwall_apps::policy::build(
                &apps,
                &modes,
                default,
                &std::collections::HashMap::new(),
            );
            policy.ask_timeout_secs = timeout;
            policy.ask_fallback = fallback;
            Ok::<_, ibexwall_apps::store::Error>(policy)
        })?;
        let wants_ask = policy.default == "ask" || policy.rules.iter().any(|r| r.verdict == "ask");
        let line = serde_json::to_string(&serde_json::json!({ "policy": policy }))?;
        self.policy.send_replace(line);
        self.reconcile_ask_chains(core, wants_ask);
        Ok(())
    }

    /// Installs the chains that hold an Ask connection's first packet while
    /// any app is in Ask mode, and removes them when none is (ADR-0036).
    /// Derived state, own table only: the queue rule carries `bypass`, so
    /// with no listener the packet is accepted.
    fn reconcile_ask_chains(&self, core: &Core, wanted: bool) {
        use ibexwall_sys::nft::Fragment;
        let engine = &core.engine;
        if !engine.sys.allow_system_executors {
            return;
        }
        let nft = &engine.sys.nft;
        let present = nft.capture(ASK_CHAIN).ok().flatten().is_some();
        let result = if wanted {
            let fragment: Fragment = serde_json::from_value(serde_json::json!({ "chains": [
                { "name": ASK_CHAIN, "priority": 5, "rules": [{
                    "ct_new": true,
                    "mark": { "mask": ibexwall_net_common::ASK_MARK_MASK,
                              "value": ibexwall_net_common::ASK_MARK_VALUE },
                    "verdict": { "queue": { "num": ibexwall_net_common::ASK_QUEUE } },
                }]},
                // A queue verdict resumes at the next hook entry, so the
                // refusal lives in a chain that runs after the queue.
                { "name": REFUSE_CHAIN, "priority": 6, "rules": [{
                    "mark": { "mask": ibexwall_net_common::ASK_MARK_MASK,
                              "value": ibexwall_net_common::REFUSED_MARK_VALUE },
                    "verdict": "reject",
                }]},
            ]}))
            .expect("the Ask fragment is well formed");
            nft.apply(&fragment)
        } else if present {
            nft.restore(ASK_CHAIN, None)
                .and_then(|()| nft.restore(REFUSE_CHAIN, None))
        } else {
            return;
        };
        match result {
            Ok(()) => core.persist_nft(),
            Err(error) => tracing::error!(%error, "reconciling the Ask chains failed"),
        }
    }

    pub fn status(&self) -> MonitorStatus {
        self.status.lock().expect("lock poisoned").clone()
    }

    pub fn set_status(&self, running: bool, reason: Option<&str>) {
        *self.status.lock().expect("lock poisoned") = MonitorStatus {
            running,
            reason: reason.map(str::to_string),
        };
    }

    /// The resolver's answer for `ip`, to be joined with later connections.
    pub fn learn(&self, ip: IpAddr, domain: &str, ttl: u32, now: i64) {
        self.correlator
            .lock()
            .expect("lock poisoned")
            .learn(ip, domain, ttl, now.max(0) as u64);
    }

    /// When the package manager's state last changed, cached briefly.
    fn package_db_changed(&self, now: i64) -> Option<i64> {
        let mut cache = self.package_db.lock().expect("lock poisoned");
        if now - cache.0 >= DB_MTIME_TTL {
            *cache = (now, newest_mtime(&self.root));
        }
        cache.1
    }

    /// Handles one loader line. Lines that are not connections the user
    /// cares about (loopback, unspecified) or not valid are skipped; a
    /// storage failure is returned.
    pub fn ingest_line(&self, core: &Core, line: &str, now: i64) -> Result<()> {
        self.ingest_batch(core, &[line], now)
    }

    /// Several lines at once. Connections are recorded in one transaction:
    /// at thousands a second, a commit per connection is the bottleneck.
    /// Questions and status lines are handled as they come.
    pub fn ingest_batch<S: AsRef<str>>(&self, core: &Core, lines: &[S], now: i64) -> Result<()> {
        let mut observations = Vec::with_capacity(lines.len());
        for line in lines {
            let line = line.as_ref();
            if let Ok(envelope) = serde_json::from_str::<crate::ask::AskEnvelope>(line) {
                if let Err(error) = self.handle_ask(core, envelope.ask, now) {
                    tracing::error!(%error, "handling an Ask request failed");
                }
            } else if let Ok(meta) = serde_json::from_str::<Meta>(line) {
                // The loader runs, with a limitation worth showing.
                if meta.meta == "degraded" {
                    self.set_status(true, Some(&meta.reason));
                }
            } else if let Some(observation) = self.observation_from(line, now) {
                observations.push(observation);
            }
        }
        if observations.is_empty() {
            return Ok(());
        }
        let recorded = core.state.with_conn(|conn| {
            let transaction = conn.unchecked_transaction()?;
            let mut all = Vec::new();
            for observation in &observations {
                for alert in ibexwall_apps::record(&transaction, observation)? {
                    all.push((observation, alert));
                }
            }
            transaction.commit()?;
            Ok::<_, anyhow::Error>(all)
        })?;
        for (observation, alert) in recorded {
            self.raise(core, observation, alert, now);
        }
        Ok(())
    }

    /// A connection line as an observation; `None` for what is not traffic
    /// (garbage, unparsable addresses, loopback and unbound sockets).
    fn observation_from(&self, line: &str, now: i64) -> Option<Observation> {
        let parsed = serde_json::from_str::<Line>(line).ok()?;
        let ip = parsed.dst.parse::<IpAddr>().ok()?;
        // Local plumbing is not network traffic: an unbound socket's
        // default destination and loopback services.
        if ip.is_unspecified() || ip.is_loopback() {
            return None;
        }
        Some(Observation {
            identity: Identity {
                kind: parsed.kind,
                id: parsed.id,
            },
            exe_path: parsed.exe.filter(|path| !path.is_empty()),
            exe_hash: parsed.exe_hash,
            package: parsed.package,
            domain: self.lookup_domain(ip, now),
            address: ip.to_string(),
            port: parsed.port,
            now,
            package_db_changed: self.package_db_changed(now),
        })
    }

    fn raise(&self, core: &Core, observation: &Observation, alert: Alert, now: i64) {
        let (kind, severity, app, data) = match &alert {
            Alert::FirstConnection { app, kind } => (
                "apps.first_connection",
                Severity::Info,
                app.clone(),
                serde_json::json!({ "app_kind": kind }),
            ),
            Alert::BinaryChanged {
                app,
                old_hash,
                new_hash,
                ..
            } => (
                "apps.binary_changed",
                Severity::High,
                app.clone(),
                serde_json::json!({ "old_hash": old_hash, "new_hash": new_hash }),
            ),
        };
        let event = Event {
            ts: format_rfc3339(now),
            source: "apps".into(),
            kind: kind.into(),
            severity,
            app: Some(app),
            data,
            untrusted: serde_json::json!({
                "exe_path": observation.exe_path,
                "package": observation.package,
            }),
        };
        core.events.publish(event.clone());
        if let Err(error) = core.state.append_event(&event) {
            tracing::error!(%error, "event persist failed");
        }
    }
}

/// The newest mtime among the package managers' databases under `root`.
fn newest_mtime(root: &Path) -> Option<i64> {
    ["var/lib/rpm", "var/lib/dpkg/status", "var/lib/pacman/local"]
        .iter()
        .filter_map(|relative| std::fs::metadata(root.join(relative)).ok())
        .filter_map(|meta| meta.modified().ok())
        .filter_map(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs() as i64)
        .max()
}

fn to_entry(summary: ibexwall_apps::AppSummary) -> AppEntry {
    AppEntry {
        kind: serde_json::to_value(summary.kind)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".into()),
        key: summary.key,
        id: summary.id,
        exe_path: summary.exe_path,
        package: summary.package,
        first_seen: format_rfc3339(summary.first_seen),
        last_seen: format_rfc3339(summary.last_seen),
        connections: summary.connections.max(0) as u64,
        destinations: summary.destinations.max(0) as u64,
        mode: String::new(),
    }
}

/// Apps for the Apps screen, most recently active first.
pub fn list_apps(core: &Core) -> Result<Vec<AppEntry>> {
    let (summaries, modes) = core.state.with_conn(|conn| {
        Ok::<_, ibexwall_apps::store::Error>((
            ibexwall_apps::list_apps(conn)?,
            ibexwall_apps::policy::modes(conn)?,
        ))
    })?;
    let default = core.state.with_conn(ibexwall_apps::policy::default_mode)?;
    Ok(summaries
        .into_iter()
        .map(|summary| {
            let mode = modes.get(&summary.key).copied().unwrap_or(default);
            let mut entry = to_entry(summary);
            entry.mode = mode.name().into();
            entry
        })
        .collect())
}

/// Stores the mode chosen for an app and pushes the new policy.
pub fn set_app_mode(core: &Core, app: &str, mode: ibexwall_apps::policy::Mode) -> Result<()> {
    let now = ibexwall_sys::RealClock.unix_now();
    core.state
        .with_conn(|conn| ibexwall_apps::policy::set_mode(conn, app, mode, now))?;
    core.monitor.refresh_policy(core)
}

pub fn app_destinations(core: &Core, app: &str) -> Result<Vec<AppDestination>> {
    let rows = core
        .state
        .with_conn(|conn| ibexwall_apps::list_destinations(conn, app))?;
    Ok(rows
        .into_iter()
        .map(|row| AppDestination {
            destination: normalize_domain(&row.destination).unwrap_or(row.destination),
            resolved: row.resolved,
            port: row.port,
            count: row.count.max(0) as u64,
            first_seen: format_rfc3339(row.first_seen),
            last_seen: format_rfc3339(row.last_seen),
        })
        .collect())
}

/// One answer from the resolver. Untrusted like everything else.
#[derive(Debug, Deserialize)]
struct Answer {
    domain: String,
    ip: String,
    ttl: u32,
}

impl Monitor {
    /// Handles one resolver datagram; anything malformed is ignored.
    pub fn ingest_answer(&self, datagram: &[u8], now: i64) {
        let Ok(answer) = serde_json::from_slice::<Answer>(datagram) else {
            return;
        };
        if let Ok(ip) = answer.ip.parse::<IpAddr>() {
            self.learn(ip, &answer.domain, answer.ttl, now);
        }
    }
}

/// Binds the datagram socket the resolver reports answers to and feeds
/// the correlator until the task is dropped. The directory belongs to the
/// resolver's user (0750), so the world-writable socket inside is only
/// reachable by it and root.
pub async fn listen_answers(core: Arc<Core>, path: PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let socket = tokio::net::UnixDatagram::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    // One DNS answer is far below this; a longer datagram is not ours.
    let mut buffer = [0u8; 1024];
    loop {
        let received = socket.recv(&mut buffer).await?;
        let now = ibexwall_sys::RealClock.unix_now();
        core.monitor.ingest_answer(&buffer[..received], now);
    }
}

/// Serves the socket the monitor unit connects to. Only root (or the
/// core's own uid, for the sandbox and tests) may feed it: the lines are
/// data about other users' processes. The loader runs under its own
/// hardened unit (ADR-0032), so systemd, not the core, restarts it.
pub async fn serve_monitor(core: Arc<Core>, path: PathBuf) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    core.monitor
        .set_status(false, Some("waiting for ibexwall-monitor"));
    let own_uid = ibexwall_sys::current_uid();
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    loop {
        let (stream, _) = listener.accept().await?;
        let allowed = stream
            .peer_cred()
            .map(|cred| cred.uid() == 0 || cred.uid() == own_uid)
            .unwrap_or(false);
        if !allowed {
            tracing::warn!("monitor socket: refused a connection from another user");
            continue;
        }
        let core = Arc::clone(&core);
        let active = Arc::clone(&active);
        tokio::spawn(async move {
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            core.monitor.set_status(true, None);
            let (read, mut write) = stream.into_split();
            // The policy goes out on connect and on every change, from
            // its own task so a slow unit never delays ingestion.
            let mut changes = core.monitor.policy.subscribe();
            let mut answers = core.monitor.outbound.subscribe();
            let writer = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;
                let mut send = async |line: &str| {
                    write.write_all(line.as_bytes()).await.is_ok()
                        && write.write_all(b"\n").await.is_ok()
                };
                let first = changes.borrow_and_update().clone();
                if !first.is_empty() && !send(&first).await {
                    return;
                }
                loop {
                    tokio::select! {
                        changed = changes.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            let line = changes.borrow_and_update().clone();
                            if !send(&line).await {
                                return;
                            }
                        }
                        answer = answers.recv() => match answer {
                            Ok(line) => {
                                if !send(&line).await {
                                    return;
                                }
                            }
                            // Lagged: some answers were dropped, which the
                            // unit's timeout covers. Closed: we are done.
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(_) => return,
                        },
                    }
                }
            });
            if let Err(error) = core.monitor.refresh_policy(&core) {
                tracing::error!(%error, "building the app policy failed");
            }
            // The reader only reads; a worker records, in batches.
            let (queue, mut incoming) = tokio::sync::mpsc::channel::<String>(65_536);
            let worker_core = Arc::clone(&core);
            let worker = tokio::task::spawn_blocking(move || {
                while let Some(first) = incoming.blocking_recv() {
                    let mut batch = vec![first];
                    while batch.len() < 1024 {
                        match incoming.try_recv() {
                            Ok(line) => batch.push(line),
                            Err(_) => break,
                        }
                    }
                    let now = ibexwall_sys::RealClock.unix_now();
                    if let Err(error) = worker_core.monitor.ingest_batch(&worker_core, &batch, now)
                    {
                        tracing::error!(%error, "monitor ingest failed");
                    }
                }
            });
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if queue.send(line).await.is_err() {
                    break;
                }
            }
            drop(queue);
            let _ = worker.await;
            writer.abort();
            if active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                core.monitor
                    .set_status(false, Some("ibexwall-monitor disconnected"));
            }
        });
    }
}
