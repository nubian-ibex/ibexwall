// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexctl` — the IbexWall command line (F1 surface: status, plugins,
//! check, findings, plan, apply, confirm, rollback, history, audit
//! verify, events). Exit codes: 0 ok · 1 error · 2 usage · 3 permission
//! denied · 4 locked by org · 5 awaiting confirmation · 10 findings
//! present.

mod commands;
mod mcp_config;
mod render;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use commands::*;
use ibexwall_proto::names;
use ibexwall_varlink::VarlinkError;
use render::*;

const EXIT_ERROR: i32 = 1;
const EXIT_PERMISSION_DENIED: i32 = 3;
const EXIT_LOCKED: i32 = 4;
const EXIT_AWAITING_CONFIRM: i32 = 5;
const EXIT_FINDINGS: i32 = 10;

#[derive(Parser)]
#[command(
    name = "ibexctl",
    version,
    about = "IbexWall control CLI",
    disable_help_subcommand = true
)]
struct Cli {
    /// Emit machine-readable JSON for every command.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Daemon and host information.
    Status,
    /// Plugin management.
    Plugins {
        #[command(subcommand)]
        action: PluginsAction,
    },
    /// Run checks (all enabled plugins, or one).
    Check { plugin: Option<String> },
    /// List findings.
    Findings {
        #[arg(long)]
        plugin: Option<String>,
    },
    /// Simulate a change: build a previewable plan from a patch.
    Plan {
        plugin: String,
        /// Setting for the plugin config, e.g. --set template=dropin.
        #[arg(long = "set", value_name = "KEY=VALUE")]
        sets: Vec<String>,
        /// Setting whose value is a file's text, e.g. --set-file profile=lab.conf.
        #[arg(long = "set-file", value_name = "KEY=PATH")]
        set_files: Vec<String>,
    },
    /// Apply a plan.
    Apply {
        plan_id: String,
        /// Confirmation window in seconds for network-risk plans.
        #[arg(long)]
        confirm_timeout: Option<i64>,
    },
    /// Confirm a pending transaction.
    Confirm { transaction_id: String },
    /// Roll back a transaction.
    Rollback { target: String },
    /// Recent transactions.
    History,
    /// Audit chain operations.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Live events.
    Events {
        #[arg(long)]
        follow: bool,
    },
    /// Applications seen by the connection monitor.
    Apps {
        #[command(subcommand)]
        action: AppsAction,
    },
    /// Connect an AI assistant (MCP) to IbexWall.
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Changes an assistant proposed, waiting for a human decision.
    Proposals {
        #[command(subcommand)]
        action: ProposalsAction,
    },
    /// Connections held in Ask mode, waiting for an answer.
    Prompts {
        #[command(subcommand)]
        action: PromptsAction,
    },
    /// The inbound firewall: what is allowed in, and changes to it.
    Firewall {
        #[command(subcommand)]
        action: FirewallCmd,
    },
    /// Interactive terminal UI.
    Tui,
}

#[derive(Subcommand)]
enum FirewallCmd {
    /// What the firewall allows today.
    Status,
    /// Let a port or a service in: `8080/tcp`, `53/udp` or `service:http`.
    Allow {
        target: String,
        /// Apply it now (otherwise only the plan is shown).
        #[arg(long)]
        yes: bool,
    },
    /// Network profiles (home, work, public, travel): with no name, list
    /// them; with a name, switch to it (firewalld only).
    Profile {
        name: Option<String>,
        /// Apply it now (otherwise only the plan is shown).
        #[arg(long)]
        yes: bool,
    },
    /// Stop letting a port or a service in.
    Deny {
        target: String,
        /// Apply it now (otherwise only the plan is shown).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum AppsAction {
    /// Every application seen, most recently active first.
    List,
    /// One application and where it connects (key from `apps list`).
    Info { app: String },
    /// What apps nobody decided about may do: allow, monitor or ask.
    Default {
        #[arg(value_parser = ["allow", "monitor", "ask"])]
        mode: String,
    },
    /// Choose what an application may do on the network.
    Set {
        /// Key from `apps list`.
        app: String,
        #[arg(value_parser = ["allow", "monitor", "ask", "block"])]
        mode: String,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// What to paste to connect a client, and the matching mcp.toml stanza.
    Config {
        client: mcp_config::McpClient,
        /// Show the stanza with change proposals allowed.
        #[arg(long)]
        with_proposals: bool,
        /// Reach `ibexwall-mcp --http` on another machine (https only).
        #[arg(long, value_name = "https://HOST:PORT/mcp")]
        url: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProposalsAction {
    /// The proposals, newest first (pending by default).
    List {
        #[arg(long, value_parser = ["pending", "approved", "rejected", "expired"])]
        status: Option<String>,
    },
    /// What one proposal would do.
    Show { id: String },
    /// Approve: the plan is made again and applied if it is what was shown.
    Approve { id: String },
    /// Reject: nothing is applied.
    Reject { id: String },
}

#[derive(Subcommand)]
enum PromptsAction {
    /// The open questions.
    List,
    /// Answer one: allow or block, for this connection, this destination
    /// or the whole app.
    Answer {
        id: String,
        #[arg(value_parser = ["allow", "block"])]
        decision: String,
        #[arg(long, default_value = "once", value_parser = ["once", "destination", "always"])]
        scope: String,
    },
}

#[derive(Subcommand)]
enum AuditAction {
    /// Validate the audit hash chain.
    Verify,
}

#[derive(Subcommand)]
enum PluginsAction {
    List,
    Info { id: String },
    Enable { id: String },
    Disable { id: String },
}

fn main() {
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let code = runtime.block_on(run(cli));
    std::process::exit(code);
}

async fn run(cli: Cli) -> i32 {
    // Printing a configuration needs no daemon.
    if let Command::Mcp {
        action:
            McpAction::Config {
                client,
                with_proposals,
                url,
            },
    } = &cli.command
    {
        if let Some(address) = url
            && let Err(reason) = mcp_config::check_url(address)
        {
            eprintln!("ibexctl: {reason}");
            return EXIT_ERROR;
        }
        print!(
            "{}",
            mcp_config::render_for(*client, *with_proposals, url.as_deref())
        );
        return 0;
    }
    let socket = names::core_socket();
    let mut client = match ibexwall_varlink::Client::connect(&socket).await {
        Ok(client) => client,
        Err(err) => {
            eprintln!(
                "ibexctl: cannot reach ibexwalld at {}: {err}",
                socket.display()
            );
            return EXIT_ERROR;
        }
    };
    match dispatch(&cli, &mut client).await {
        Ok(Finish::Done) => 0,
        Ok(Finish::AwaitingConfirm(transaction)) => {
            if cli.json {
                println!("{{\"awaiting_confirmation\":true,\"transaction\":\"{transaction}\"}}");
            } else {
                println!("applied; awaiting confirmation for {transaction}");
                println!("run `ibexctl confirm {transaction}` to keep the changes");
            }
            EXIT_AWAITING_CONFIRM
        }
        Ok(Finish::Findings(count)) => {
            if !cli.json {
                println!("{count} finding(s) present");
            }
            EXIT_FINDINGS
        }
        Err(CliError::Varlink(err)) => {
            report_varlink(&err, cli.json);
            match err.name.as_str() {
                "com.ibexwall.Core.PermissionDenied" => EXIT_PERMISSION_DENIED,
                "com.ibexwall.Core.Locked" => EXIT_LOCKED,
                _ => EXIT_ERROR,
            }
        }
        Err(CliError::Other(err)) => {
            eprintln!("ibexctl: {err:#}");
            EXIT_ERROR
        }
    }
}

enum Finish {
    Done,
    AwaitingConfirm(String),
    Findings(usize),
}

enum CliError {
    Varlink(VarlinkError),
    Other(anyhow::Error),
}

impl From<VarlinkError> for CliError {
    fn from(err: VarlinkError) -> Self {
        CliError::Varlink(err)
    }
}

impl From<anyhow::Error> for CliError {
    fn from(err: anyhow::Error) -> Self {
        CliError::Other(err)
    }
}

async fn dispatch(cli: &Cli, client: &mut ibexwall_varlink::Client) -> Result<Finish, CliError> {
    let json = cli.json;
    match &cli.command {
        Command::Status => {
            let value = client
                .call("com.ibexwall.Core.GetInfo", serde_json::json!({}))
                .await?;
            show(&value, json, render_status);
            Ok(Finish::Done)
        }
        Command::Plugins { action } => plugins(client, action, json).await,
        Command::Apps { action } => apps(client, action, json).await,
        Command::Prompts { action } => prompts(client, action, json).await,
        Command::Mcp { .. } => Ok(Finish::Done),
        Command::Proposals { action } => proposals(client, action, json).await,
        Command::Firewall { action } => firewall(client, action, json).await,
        Command::Check { plugin } => {
            let params = serde_json::json!({ "plugin": plugin });
            let value = client.call("com.ibexwall.Core.RunChecks", params).await?;
            let count = value["findings"].as_array().map(Vec::len).unwrap_or(0);
            show(&value, json, render_findings);
            Ok(if count > 0 {
                Finish::Findings(count)
            } else {
                Finish::Done
            })
        }
        Command::Findings { plugin } => {
            let params = serde_json::json!({ "plugin": plugin });
            let value = client
                .call("com.ibexwall.Core.ListFindings", params)
                .await?;
            show(&value, json, render_findings);
            Ok(Finish::Done)
        }
        Command::Plan {
            plugin,
            sets,
            set_files,
        } => {
            let mut config = serde_json::Map::new();
            for set in set_files {
                let (key, path) = set
                    .split_once('=')
                    .with_context(|| format!("--set-file expects KEY=PATH, got `{set}`"))
                    .map_err(CliError::Other)?;
                let text = std::fs::read(path)
                    .ok()
                    .filter(|bytes| bytes.len() <= 64 * 1024)
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                    .with_context(|| format!("cannot read `{path}` as text under 64 KiB"))
                    .map_err(CliError::Other)?;
                config.insert(key.into(), serde_json::Value::String(text));
            }
            for set in sets {
                let (key, value) = set
                    .split_once('=')
                    .with_context(|| format!("--set expects KEY=VALUE, got `{set}`"))
                    .map_err(CliError::Other)?;
                // Numbers and booleans arrive as JSON, everything else as a
                // string: plugins declare real types for their config.
                let parsed = serde_json::from_str::<serde_json::Value>(value)
                    .unwrap_or(serde_json::Value::String(value.to_string()));
                if parsed.is_string() && value.contains('=') {
                    return Err(CliError::Other(anyhow::anyhow!(
                        "--set expects KEY=VALUE, got `{set}`"
                    )));
                }
                config.insert(key.into(), parsed);
            }
            let params = serde_json::json!({ "plugin": plugin, "patch": config });
            let value = client.call("com.ibexwall.Core.PlanChange", params).await?;
            if json {
                emit(value.clone(), json);
            } else {
                let plan = &value["plan"];
                println!(
                    "plan {} for {} ({} op(s))",
                    plan["id"],
                    plan["plugin"],
                    plan["ops"].as_array().map(Vec::len).unwrap_or(0)
                );
                println!("apply with: ibexctl apply {}", plan["id"]);
            }
            Ok(Finish::Done)
        }
        Command::Apply {
            plan_id,
            confirm_timeout,
        } => {
            let params = serde_json::json!({
                "plan_id": plan_id,
                "confirm_timeout_s": confirm_timeout,
            });
            let value = client.call("com.ibexwall.Core.Apply", params).await?;
            let state = value["transaction"]["state"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let id = value["transaction"]["id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            emit(value, json);
            if state == "pending_confirm" {
                Ok(Finish::AwaitingConfirm(id))
            } else {
                Ok(Finish::Done)
            }
        }
        Command::Confirm { transaction_id } => {
            let params = serde_json::json!({ "transaction_id": transaction_id });
            client.call("com.ibexwall.Core.Confirm", params).await?;
            if !json {
                println!("confirmed {transaction_id}");
            }
            Ok(Finish::Done)
        }
        Command::Rollback { target } => {
            let params = serde_json::json!({ "target": target });
            let value = client.call("com.ibexwall.Core.Rollback", params).await?;
            emit(value, json);
            if !json {
                println!("rolled back {target}");
            }
            Ok(Finish::Done)
        }
        Command::History => {
            let value = client
                .call("com.ibexwall.Core.History", serde_json::json!({}))
                .await?;
            show(&value, json, render_history);
            Ok(Finish::Done)
        }
        Command::Audit {
            action: AuditAction::Verify,
        } => {
            let value = client
                .call("com.ibexwall.Core.AuditVerify", serde_json::json!({}))
                .await?;
            let valid = value["valid"].as_bool().unwrap_or(false);
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            } else if valid {
                println!("audit chain valid ({} entries)", value["entries"]);
            } else {
                eprintln!(
                    "audit chain BROKEN: {}",
                    value["reason"].as_str().unwrap_or("unknown")
                );
            }
            if valid {
                Ok(Finish::Done)
            } else {
                Err(CliError::Other(anyhow::anyhow!(
                    "audit chain verification failed"
                )))
            }
        }
        Command::Tui => {
            // The TUI owns the terminal and creates its own runtime; the
            // control connection stays open (a local unix socket).
            let socket = names::core_socket();
            ibexwall_tui::run(&socket).map_err(CliError::Other)?;
            Ok(Finish::Done)
        }
        Command::Events { follow } => {
            if !*follow {
                let value = client
                    .call("com.ibexwall.Core.RecentEvents", serde_json::json!({}))
                    .await?;
                show(&value, json, render_events);
                return Ok(Finish::Done);
            }
            let mut stream = client
                .call_more("com.ibexwall.Core.Subscribe", serde_json::json!({}))
                .await?;
            while let Some(event) = stream.next_reply().await? {
                println!("{}", serde_json::to_string(&event).unwrap_or_default());
            }
            Ok(Finish::Done)
        }
    }
}

#[allow(dead_code)]
fn default_socket() -> PathBuf {
    names::core_socket()
}

#[cfg(test)]
mod tests;
