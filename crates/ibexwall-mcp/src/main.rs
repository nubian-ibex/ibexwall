// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexwall-mcp`: started by an MCP client as the user, speaks MCP on
//! stdin/stdout. No root, no network: it only talks to the core's socket.

use std::io::{BufRead, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use ibexwall_mcp::audit::{self, Audit};
use ibexwall_mcp::config::Config;
use ibexwall_mcp::redact::Redactor;
use ibexwall_mcp::server::{Backend, Server};
use serde_json::Value;

/// A request line longer than this is dropped, not parsed.
const MAX_LINE: usize = 1024 * 1024;

struct Varlink {
    runtime: tokio::runtime::Runtime,
    socket: PathBuf,
    client: Option<ibexwall_varlink::Client>,
}

impl Backend for Varlink {
    fn call(&mut self, method: &str, parameters: Value) -> Result<Value, String> {
        let result = self.runtime.block_on(async {
            if self.client.is_none() {
                self.client = Some(
                    ibexwall_varlink::Client::connect(&self.socket)
                        .await
                        .map_err(|_| "the IbexWall core is not reachable".to_string())?,
                );
            }
            let client = self.client.as_mut().expect("connected above");
            client.call(method, parameters).await.map_err(|e| {
                let reason = e.parameters["reason"].as_str().unwrap_or_default();
                let short = e.name.rsplit('.').next().unwrap_or("error");
                format!(
                    "the core refused ({short}) {}",
                    audit::truncate(reason, 200)
                )
            })
        });
        if result.as_ref().is_err_and(|m| m.contains("not reachable")) {
            self.client = None;
        }
        result
    }
}

fn state_dir() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("ibexwall")
}

/// The local salt for pseudonyms: 32 random bytes, created once, 0600.
fn salt(dir: &std::path::Path) -> Result<Vec<u8>> {
    let path = dir.join("mcp-salt");
    if let Ok(bytes) = std::fs::read(&path)
        && bytes.len() == 32
    {
        return Ok(bytes);
    }
    let mut bytes = [0u8; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut bytes)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .context("cannot create the salt file")?;
    file.write_all(&bytes)?;
    Ok(bytes.to_vec())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// The HTTP transport (`--http`, and `[http] enabled = true` in mcp.toml):
/// TLS only, one `Server` per token behind a worker thread, one audit chain.
fn run_http(
    config: Config,
    socket: PathBuf,
    redactor: Redactor,
    audit: Audit<std::fs::File>,
) -> Result<()> {
    use ibexwall_mcp::http::{self, Gate, State};
    use std::sync::{Arc, Mutex};

    if !config.http.enabled {
        anyhow::bail!("the HTTP transport is off: set `[http] enabled = true` in mcp.toml");
    }
    let tls = http::tls_config(&config.http.tls_cert, &config.http.tls_key)
        .map_err(|e| anyhow::anyhow!("TLS: {e}"))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let listener = runtime.block_on(tokio::net::TcpListener::bind(&config.http.listen))?;
    eprintln!(
        "ibexwall-mcp: serving MCP over HTTPS on {} ({} token(s))",
        listener.local_addr()?,
        config.tokens.len()
    );
    let audit = Arc::new(Mutex::new(audit));
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let worker_config = config.clone();
    http::spawn_worker(rx, move |client, token_id| {
        let backend = Varlink {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a current-thread runtime"),
            socket: socket.clone(),
            client: None,
        };
        let mut server = Server::shared(
            worker_config.clone(),
            client,
            &format!("http:{token_id}"),
            redactor.clone(),
            Arc::clone(&audit),
            backend,
        );
        Box::new(move |line| server.handle(line))
    });
    let state = Arc::new(State {
        gate: Gate::new(Arc::new(config)),
        jobs: tx,
    });
    runtime.block_on(http::serve(listener, tls, state));
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Setting up the HTTP transport: nothing here touches /etc or the core.
    let sub: Vec<&str> = args.iter().take(2).map(String::as_str).collect();
    match sub.as_slice() {
        ["token", "create"] => {
            let text = ibexwall_mcp::admin::token_create(&args[2..], &mut std::io::stdin())
                .map_err(|e| anyhow::anyhow!(e))?;
            print!("{text}");
            return Ok(());
        }
        ["tls-init", ..] => {
            let text = ibexwall_mcp::admin::tls_init(&args[1..]).map_err(|e| anyhow::anyhow!(e))?;
            print!("{text}");
            return Ok(());
        }
        _ => {}
    }
    let dir = flag(&args, "--state-dir")
        .map(PathBuf::from)
        .unwrap_or_else(state_dir);
    std::fs::create_dir_all(&dir)?;
    let log_path = dir.join("mcp-audit.jsonl");

    if args.iter().any(|a| a == "--verify-log") {
        let text = std::fs::read_to_string(&log_path).unwrap_or_default();
        return match audit::verify(&text) {
            Ok(n) => {
                println!("{}: {n} lines, chain intact", log_path.display());
                Ok(())
            }
            Err(line) => anyhow::bail!("{}: the chain breaks at line {line}", log_path.display()),
        };
    }

    let config_path = flag(&args, "--config").unwrap_or_else(|| "/etc/ibexwall/mcp.toml".into());
    let config = match std::fs::read_to_string(&config_path) {
        Ok(text) => Config::parse(&text).map_err(|e| anyhow::anyhow!("{config_path}: {e}"))?,
        Err(_) => Config::default(),
    };
    let client = flag(&args, "--client").unwrap_or_else(|| "unknown".into());
    let socket = flag(&args, "--socket")
        .map(PathBuf::from)
        .unwrap_or_else(ibexwall_proto::names::core_socket);

    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    let redactor = Redactor::new(salt(&dir)?, &[user], &[host], &config.defaults.redact);

    let existing = std::fs::read_to_string(&log_path).unwrap_or_default();
    let (seq, prev) = Audit::<std::fs::File>::resume(&existing);
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)?;
    if args.iter().any(|a| a == "--http") {
        return run_http(config, socket, redactor, Audit::new(log, seq, prev));
    }
    let backend = Varlink {
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
        socket,
        client: None,
    };
    let mut server = Server::new(
        config,
        &client,
        redactor,
        Audit::new(log, seq, prev),
        backend,
    );

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    let mut reader = stdin.lock();
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take(MAX_LINE as u64 + 1)
            .read_line(&mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_LINE {
            // Drop the rest of the oversized line, answer once.
            while !line.ends_with('\n') {
                line.clear();
                if reader.by_ref().take(MAX_LINE as u64).read_line(&mut line)? == 0 {
                    break;
                }
            }
            writeln!(
                stdout,
                r#"{{"jsonrpc":"2.0","id":null,"error":{{"code":-32600,"message":"request too large"}}}}"#
            )?;
            stdout.flush()?;
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if let Some(answer) = server.handle(line.trim_end()) {
            writeln!(stdout, "{answer}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
