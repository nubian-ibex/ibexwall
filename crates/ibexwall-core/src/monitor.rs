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
use std::time::Duration;

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

/// Runs the loader as a child, feeding the monitor, until the task is
/// dropped. A loader that exits is restarted with a growing delay; the
/// status says why it is off while it is.
pub async fn supervise(core: Arc<Core>, program: PathBuf) {
    let mut delay = Duration::from_secs(2);
    loop {
        if !program.exists() {
            core.monitor.set_status(
                false,
                Some(&format!("{} is not installed", program.display())),
            );
            tokio::time::sleep(Duration::from_secs(60)).await;
            continue;
        }
        let started = std::time::Instant::now();
        let reason = run_child(&core, &program).await;
        core.monitor.set_status(false, Some(&reason));
        tracing::warn!(%reason, "connection monitor stopped");
        // A child that ran for a while was healthy: start the backoff over.
        delay = if started.elapsed() > Duration::from_secs(60) {
            Duration::from_secs(2)
        } else {
            (delay * 2).min(Duration::from_secs(60))
        };
        tokio::time::sleep(delay).await;
    }
}

async fn run_child(core: &Arc<Core>, program: &Path) -> String {
    let mut child = match tokio::process::Command::new(program)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => return format!("cannot start: {error}"),
    };
    let Some(stdout) = child.stdout.take() else {
        return "no output pipe".into();
    };
    core.monitor.set_status(true, None);
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let now = ibexwall_sys::RealClock.unix_now();
        if let Err(error) = core.monitor.ingest_line(core, &line, now) {
            tracing::error!(%error, "monitor ingest failed");
        }
    }
    match child.wait().await {
        Ok(status) => format!("exited with {status}"),
        Err(error) => format!("wait failed: {error}"),
    }
}
