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

/// How often the package-manager database mtime is re-read.
const DB_MTIME_TTL: i64 = 5;

pub struct Monitor {
    correlator: Mutex<Correlator>,
    status: Mutex<MonitorStatus>,
    package_db: Mutex<(i64, Option<i64>)>,
    root: PathBuf,
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
        }
    }

    pub fn status(&self) -> MonitorStatus {
        self.status.lock().unwrap().clone()
    }

    pub fn set_status(&self, running: bool, reason: Option<&str>) {
        *self.status.lock().unwrap() = MonitorStatus {
            running,
            reason: reason.map(str::to_string),
        };
    }

    /// The resolver's answer for `ip`, to be joined with later connections.
    pub fn learn(&self, ip: IpAddr, domain: &str, ttl: u32, now: i64) {
        self.correlator
            .lock()
            .unwrap()
            .learn(ip, domain, ttl, now.max(0) as u64);
    }

    /// When the package manager's state last changed, cached briefly.
    fn package_db_changed(&self, now: i64) -> Option<i64> {
        let mut cache = self.package_db.lock().unwrap();
        if now - cache.0 >= DB_MTIME_TTL {
            *cache = (now, newest_mtime(&self.root));
        }
        cache.1
    }

    /// Handles one loader line. Lines that are not connections the user
    /// cares about (loopback, unspecified) or not valid are skipped; a
    /// storage failure is returned.
    pub fn ingest_line(&self, core: &Core, line: &str, now: i64) -> Result<()> {
        if let Ok(meta) = serde_json::from_str::<Meta>(line) {
            // The loader runs, with a limitation worth showing.
            if meta.meta == "degraded" {
                self.set_status(true, Some(&meta.reason));
            }
            return Ok(());
        }
        let Ok(parsed) = serde_json::from_str::<Line>(line) else {
            return Ok(());
        };
        let Ok(ip) = parsed.dst.parse::<IpAddr>() else {
            return Ok(());
        };
        // Local plumbing is not network traffic: an unbound socket's
        // default destination and loopback services.
        if ip.is_unspecified() || ip.is_loopback() {
            return Ok(());
        }
        let domain = self
            .correlator
            .lock()
            .unwrap()
            .lookup(ip, now.max(0) as u64)
            .map(str::to_string);
        let observation = Observation {
            identity: Identity {
                kind: parsed.kind,
                id: parsed.id,
            },
            exe_path: parsed.exe.filter(|path| !path.is_empty()),
            exe_hash: parsed.exe_hash,
            package: parsed.package,
            domain,
            address: ip.to_string(),
            port: parsed.port,
            now,
            package_db_changed: self.package_db_changed(now),
        };
        let alerts = core
            .state
            .with_conn(|conn| ibexwall_apps::record(conn, &observation))?;
        for alert in alerts {
            self.raise(core, &observation, alert, now);
        }
        Ok(())
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
    }
}

/// Apps for the Apps screen, most recently active first.
pub fn list_apps(core: &Core) -> Result<Vec<AppEntry>> {
    let summaries = core.state.with_conn(ibexwall_apps::list_apps)?;
    Ok(summaries.into_iter().map(to_entry).collect())
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
            let mut lines = BufReader::new(stream).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let now = ibexwall_sys::RealClock.unix_now();
                if let Err(error) = core.monitor.ingest_line(&core, &line, now) {
                    tracing::error!(%error, "monitor ingest failed");
                }
            }
            if active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                core.monitor
                    .set_status(false, Some("ibexwall-monitor disconnected"));
            }
        });
    }
}
