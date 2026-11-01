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
    let dev_key = std::env::args()
        .nth(1)
        .and_then(|arg| arg.strip_prefix("--dev-key=").map(PathBuf::from));

    init_tracing();

    let socket = match names::core_socket() {
        path if path.exists() => path,
        path => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            path
        }
    };
    // Direct-bind mode (dev/VM): a crashed daemon leaves the socket
    // file behind and bind(2) would fail. systemd socket activation
    // (LISTEN_FDS) does not go through this path.
    if std::env::var_os("LISTEN_FDS").is_none() {
        let _ = std::fs::remove_file(&socket);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(ibexwall_core::serve(&socket, dev_key))
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
