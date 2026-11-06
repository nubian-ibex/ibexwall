// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwalld` entry point: initializes logging, opens the listening
//! socket (systemd socket activation or `IBEXWALL_ROOT` direct bind in
//! dev/tests) and serves the varlink API until shutdown.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ibexwall_proto::names;

fn main() {
    if let Err(err) = run() {
        eprintln!("ibexwalld: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--cleanup") {
        return cleanup();
    }
    let dev_key = std::env::args()
        .nth(1)
        .and_then(|arg| arg.strip_prefix("--dev-key=").map(PathBuf::from));

    init_tracing();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    // systemd socket activation: the listening socket arrives as fd 3.
    if let Some(listener) = listenfd::ListenFd::from_env().take_unix_listener(0)? {
        return runtime.block_on(ibexwall_core::serve_activated(listener, dev_key));
    }

    // Direct-bind mode (dev/VM/tests).
    let socket = names::core_socket();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // A crashed daemon leaves the socket file behind; bind(2) would fail.
    let _ = std::fs::remove_file(&socket);
    runtime.block_on(ibexwall_core::serve(&socket, dev_key))
}

/// `ibexwalld --cleanup`: what the package runs before it removes the files.
/// It undoes what IbexWall changed and keeps the user's data. A failure is
/// said out loud but does not make the removal fail.
fn cleanup() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(ibexwall_core::cleanup(names::root(), None))?;
    println!(
        "ibexwalld: undid {} change(s), removed {} firewall chain(s)",
        report.rolled_back, report.chains_removed
    );
    for (tx, why) in &report.failed {
        eprintln!("ibexwalld: could not undo {tx}: {why}");
    }
    if report.failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("{} change(s) could not be undone", report.failed.len())
    }
}

/// journald when available (production), stderr otherwise (dev/tests).
fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let stderr_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    match tracing_journald::layer() {
        Ok(journald) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(stderr_layer)
                .with(journald)
                .init();
        }
        Err(_) => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(stderr_layer)
                .init();
        }
    }
}
