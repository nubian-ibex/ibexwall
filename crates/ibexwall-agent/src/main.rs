// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-agent`: runs in the user session (no root). It watches the
//! event stream and raises a desktop notification for new high or critical
//! findings. It also builds the application inventory from `.desktop`
//! files; the core never reads home directories.

mod desktop;

use std::path::PathBuf;

use anyhow::Result;
use ibexwall_proto::names;
use serde_json::json;

fn main() {
    if let Err(err) = ibexwall_agent::run() {
        eprintln!("ibexwall-agent: {err:#}");
        std::process::exit(1);
    }
}

/// Library form so tests can drive the pieces without spawning.
pub mod ibexwall_agent {
    use super::*;

    pub fn run() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(amain())
    }

    async fn amain() -> Result<()> {
        init_tracing();
        let socket = names::core_socket();
        let mut client = ibexwall_varlink::Client::connect(&socket).await?;

        // The inventory is printed once (stdout is captured by the
        // journal); sending it to the core arrives with net.apps in F4.
        for entry in super::desktop::scan(&xdg_data_dirs()) {
            tracing::info!(id = %entry.id, "inventory");
        }

        // Live events; a high or critical finding raises a notification.
        let mut stream = client
            .call_more("com.ibexwall.Core.Subscribe", json!({}))
            .await?;
        while let Some(event) = stream.next_reply().await? {
            if let Some(finding) = finding_from(&event) {
                notify(&finding).await?;
            }
        }
        Ok(())
    }

    /// Extracts a notifiable finding summary from an event, if it is one.
    pub fn finding_from(event: &serde_json::Value) -> Option<String> {
        let kind = event.get("kind")?.as_str()?;
        if !kind.starts_with("finding.") {
            return None;
        }
        let severity = event.get("severity")?.as_str()?;
        let notify = matches!(severity, "high" | "critical");
        notify.then(|| format!("{kind}: {severity}"))
    }

    async fn notify(summary: &str) -> Result<()> {
        // Desktop notification via the standard interface. Body is plain
        // text; notification servers do not interpret markup from us.
        let connection = zbus::Connection::session().await?;
        connection
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &(
                    "IbexWall",
                    0u32,
                    "ibexwall",
                    "IbexWall",
                    summary,
                    Vec::<String>::new(),
                    std::collections::HashMap::<String, zbus::zvariant::Variant>::new(),
                    -1i32,
                ),
            )
            .await?;
        Ok(())
    }

    fn init_tracing() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init();
    }
}

/// `$XDG_DATA_DIRS` plus the user's own data dir (first wins for dedup).
fn xdg_data_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| "/usr/local/share:/usr/share".into())
        .split(':')
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect();
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(home).join(".local/share"));
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::ibexwall_agent::finding_from;

    #[test]
    fn only_high_and_critical_findings_are_notifiable() {
        for (severity, expected) in [
            ("critical", true),
            ("high", true),
            ("medium", false),
            ("low", false),
            ("info", false),
        ] {
            let event = serde_json::json!({ "kind": "finding.new", "severity": severity });
            assert_eq!(finding_from(&event).is_some(), expected, "{severity}");
        }
        assert!(finding_from(&serde_json::json!({ "kind": "transaction.committed" })).is_none());
        assert!(finding_from(&serde_json::json!({})).is_none());
    }
}
