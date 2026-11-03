// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-dns`: reads its settings file, binds UDP and TCP on the
//! configured address and serves until SIGTERM or SIGINT.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_server::Server;
use ibexwall_dns::config::{Settings, build_resolver};
use ibexwall_dns::daemon::{build_policy, spawn_updater};
use ibexwall_dns::handler::Handler;
use ibexwall_dns::lists::{self, HttpsFetcher, Store};
use ibexwall_proto::names;
use ibexwall_sys::Clock as _;
use tokio::net::{TcpListener, UdpSocket};
use tokio::signal::unix::{SignalKind, signal};

const TCP_TIMEOUT: Duration = Duration::from_secs(5);
/// Responses queued per TCP connection before back-pressure.
const TCP_RESPONSE_BUFFER: usize = 1024;

fn settings_path() -> PathBuf {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("--config"), Some(path)) => PathBuf::from(path),
        _ => names::config_dir().join("dns").join("resolver.json"),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    if let Err(error) = run().await {
        eprintln!("ibexwall-dns: {error:#}");
        std::process::exit(1);
    }
}

/// Publishes the counters where the core can show them (spec: counters
/// only, never query names). Best effort: a failed write is logged and
/// retried on the next tick.
fn spawn_status_writer(handler: Handler) {
    tokio::spawn(async move {
        loop {
            let path = names::dns_status_file();
            let counters = handler.counters.snapshot();
            let status = serde_json::json!({
                "running": true,
                "updated_at": ibexwall_sys::RealClock.rfc3339_now(),
                "forwarded": counters.forwarded,
                "blocked_list": counters.blocked_list,
                "blocked_canary": counters.blocked_canary,
                "blocked_doh": counters.blocked_doh,
                "upstream_errors": counters.upstream_errors,
            });
            let result = std::fs::create_dir_all(path.parent().expect("parent"))
                .and_then(|_| write_replacing(&path, &status));
            if let Err(error) = result {
                tracing::warn!(%error, path = %path.display(), "writing the status file failed");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

fn write_replacing(path: &std::path::Path, status: &serde_json::Value) -> std::io::Result<()> {
    let temporary = path.with_extension("json.new");
    std::fs::write(&temporary, serde_json::to_vec(status).unwrap_or_default())?;
    std::fs::rename(&temporary, path)
}

async fn run() -> Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--failsafe") {
        ibexwall_dns::failsafe::run(&names::root()).context("failsafe")?;
        return Ok(());
    }
    let path = settings_path();
    let settings: Settings = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing {}", path.display()))?;

    let resolver = build_resolver(&settings.servers)?;
    let store = Arc::new(Store::new(lists::default_dir()));
    let mut handler = Handler::new(build_policy(&settings, &store), resolver);
    // Optional: without a listening core the sink just drops its datagrams.
    if let Ok(sink) = ibexwall_dns::answers::AnswerSink::new(names::dns_answers_socket()) {
        handler = handler.with_answer_sink(sink);
    }

    let udp = UdpSocket::bind(settings.listen)
        .await
        .with_context(|| format!("binding udp {}", settings.listen))?;
    let tcp = TcpListener::bind(settings.listen)
        .await
        .with_context(|| format!("binding tcp {}", settings.listen))?;
    let bound = udp.local_addr()?;
    let upstreams = settings.servers.len();
    let list_count = settings.lists.len();
    spawn_updater(
        Arc::new(settings),
        store,
        Arc::new(HttpsFetcher::default()),
        handler.clone(),
    );

    spawn_status_writer(handler.clone());
    let mut server = Server::new(handler);
    server.register_socket(udp);
    server.register_listener(tcp, TCP_TIMEOUT, TCP_RESPONSE_BUFFER);
    tracing::info!(listen = %bound, upstreams, lists = list_count, "serving");

    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        result = server.block_until_done() => result.map_err(Into::into),
        _ = term.recv() => Ok(()),
        _ = int.recv() => Ok(()),
    }
}
