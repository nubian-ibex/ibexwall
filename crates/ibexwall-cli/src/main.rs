// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ibexctl` — the IbexWall command line (F1 surface: status, plugins,
//! check, findings, plan, apply, confirm, rollback, history, audit
//! verify, events). Exit codes: 0 ok · 1 error · 2 usage · 3 permission
//! denied · 4 locked by org · 5 awaiting confirmation · 10 findings
//! present.

mod mcp_config;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ibexwall_proto::names;
use ibexwall_varlink::VarlinkError;

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
        action: McpAction::Config {
            client,
            with_proposals,
        },
    } = &cli.command
    {
        print!("{}", mcp_config::render(*client, *with_proposals));
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
            emit(value, json);
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
            emit(value, json);
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
            emit(value, json);
            Ok(Finish::Done)
        }
        Command::Plan { plugin, sets } => {
            let mut config = serde_json::Map::new();
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
            emit(value, json);
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
                emit(value, json);
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

async fn plugins(
    client: &mut ibexwall_varlink::Client,
    action: &PluginsAction,
    json: bool,
) -> Result<Finish, CliError> {
    match action {
        PluginsAction::List => {
            let value = client
                .call("com.ibexwall.Core.ListPlugins", serde_json::json!({}))
                .await?;
            emit(value, json);
            Ok(Finish::Done)
        }
        PluginsAction::Info { id } => {
            let value = client
                .call("com.ibexwall.Core.ListPlugins", serde_json::json!({}))
                .await?;
            let plugin = value["plugins"]
                .as_array()
                .and_then(|list| list.iter().find(|p| p["id"] == id.as_str()))
                .cloned()
                .unwrap_or_else(|| serde_json::json!({ "id": id, "error": "not found" }));
            emit(serde_json::json!({ "plugin": plugin }), json);
            Ok(Finish::Done)
        }
        PluginsAction::Enable { id } | PluginsAction::Disable { id } => {
            let enable = matches!(action, PluginsAction::Enable { .. });
            let params = serde_json::json!({ "id": id, "enabled": enable });
            client
                .call("com.ibexwall.Core.SetPluginEnabled", params)
                .await?;
            if !json {
                println!("{} {id}", if enable { "enabled" } else { "disabled" });
            }
            Ok(Finish::Done)
        }
    }
}

/// `8080/tcp` goes to the plugin's port settings, `service:http` to its
/// service settings.
fn firewall_patch(target: &str, allow: bool) -> serde_json::Value {
    let (key, value) = match target.strip_prefix("service:") {
        Some(name) => (
            if allow {
                "allow_service"
            } else {
                "remove_service"
            },
            name,
        ),
        None => (if allow { "allow" } else { "remove" }, target),
    };
    serde_json::json!({ key: value })
}

async fn firewall(
    client: &mut ibexwall_varlink::Client,
    action: &FirewallCmd,
    json: bool,
) -> Result<Finish, CliError> {
    let (target, allow, yes) = match action {
        FirewallCmd::Status => {
            let value = client
                .call("com.ibexwall.Core.GetFirewall", serde_json::json!({}))
                .await?;
            if json {
                emit(value, json);
            } else {
                print!("{}", render_firewall(&value["firewall"]));
            }
            return Ok(Finish::Done);
        }
        FirewallCmd::Profile { name: None, .. } => {
            if json {
                emit(
                    serde_json::json!({ "profiles": ibexwall_firewall::profile::Profile::ALL
                        .map(|p| serde_json::json!({ "profile": p.name(), "zone": p.zone() })) }),
                    json,
                );
            } else {
                for profile in ibexwall_firewall::profile::Profile::ALL {
                    println!("{:<7} firewalld zone: {}", profile.name(), profile.zone());
                }
            }
            return Ok(Finish::Done);
        }
        FirewallCmd::Profile {
            name: Some(name),
            yes,
        } => {
            return plan_firewall(client, serde_json::json!({ "profile": name }), *yes, json).await;
        }
        FirewallCmd::Allow { target, yes } => (target, true, *yes),
        FirewallCmd::Deny { target, yes } => (target, false, *yes),
    };
    plan_firewall(client, firewall_patch(target, allow), yes, json).await
}

/// Plans a change with the firewall plugin; applies it only with `yes`.
async fn plan_firewall(
    client: &mut ibexwall_varlink::Client,
    patch: serde_json::Value,
    yes: bool,
    json: bool,
) -> Result<Finish, CliError> {
    let plan = client
        .call(
            "com.ibexwall.Core.PlanChange",
            serde_json::json!({ "plugin": "net.firewall", "patch": patch }),
        )
        .await?;
    let plan_id = plan["plan"]["id"].as_str().unwrap_or_default().to_string();
    if !yes {
        if json {
            emit(plan, json);
        } else {
            for op in plan["plan"]["ops"].as_array().cloned().unwrap_or_default() {
                println!("{} {}", text(&op["op"]), text(&op["target"]));
            }
            println!("apply with: ibexctl apply {plan_id}  (or repeat with --yes)");
        }
        return Ok(Finish::Done);
    }
    let applied = client
        .call(
            "com.ibexwall.Core.Apply",
            serde_json::json!({ "plan_id": plan_id, "confirm_timeout_s": null }),
        )
        .await?;
    let state = applied["transaction"]["state"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let id = applied["transaction"]["id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    emit(applied, json);
    if state == "pending_confirm" {
        Ok(Finish::AwaitingConfirm(id))
    } else {
        if !json {
            println!("done ({id}); undo with: ibexctl rollback {id}");
        }
        Ok(Finish::Done)
    }
}

fn ports_line(value: &serde_json::Value) -> String {
    let ports: Vec<String> = value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|p| format!("{}/{}", p["port"].as_u64().unwrap_or(0), text(&p["proto"])))
        .collect();
    if ports.is_empty() {
        "none".into()
    } else {
        ports.join(", ")
    }
}

fn render_firewall(state: &serde_json::Value) -> String {
    let manager = text(&state["backend"]);
    let status = match state["active"].as_bool() {
        Some(true) => "active",
        Some(false) => "not active",
        None => "state unknown",
    };
    let mut out = format!("firewall: {manager} ({status})");
    if let Some(zone) = state["zone"].as_str() {
        out.push_str(&format!(", zone {}", clean(zone)));
    }
    out.push('\n');
    out.push_str(&format!(
        "  allowed ports:    {}\n",
        ports_line(&state["ports"])
    ));
    let services: Vec<String> = state["services"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(text)
        .collect();
    out.push_str(&format!(
        "  allowed services: {}\n",
        if services.is_empty() {
            "none".into()
        } else {
            services.join(", ")
        }
    ));
    out.push_str(&format!(
        "  listening on every address: {}\n",
        ports_line(&state["listening"])
    ));
    for line in state["other"].as_array().cloned().unwrap_or_default() {
        out.push_str(&format!("  read-only: {}\n", text(&line)));
    }
    out
}

async fn apps(
    client: &mut ibexwall_varlink::Client,
    action: &AppsAction,
    json: bool,
) -> Result<Finish, CliError> {
    match action {
        AppsAction::List => {
            let value = client
                .call("com.ibexwall.Core.ListApps", serde_json::json!({}))
                .await?;
            if json {
                emit(value, json);
            } else {
                print!("{}", render_apps(&value));
            }
        }
        AppsAction::Default { mode } => {
            client
                .call(
                    "com.ibexwall.Core.SetDefaultMode",
                    serde_json::json!({ "mode": mode }),
                )
                .await?;
            if !json {
                println!("apps nobody decided about: {mode}");
            }
        }
        AppsAction::Set { app, mode } => {
            let value = client
                .call(
                    "com.ibexwall.Core.SetAppMode",
                    serde_json::json!({ "app": app, "mode": mode }),
                )
                .await?;
            if json {
                emit(value, json);
            } else {
                println!("{}: {}", clean(app), mode);
            }
        }
        AppsAction::Info { app } => {
            let listed = client
                .call("com.ibexwall.Core.ListApps", serde_json::json!({}))
                .await?;
            let destinations = client
                .call(
                    "com.ibexwall.Core.GetAppDestinations",
                    serde_json::json!({ "app": app }),
                )
                .await?;
            let entry = listed["apps"]
                .as_array()
                .and_then(|apps| apps.iter().find(|a| a["key"] == app.as_str()))
                .cloned()
                .ok_or_else(|| CliError::Other(anyhow::anyhow!("no such app: {}", clean(app))))?;
            if json {
                emit(
                    serde_json::json!({ "app": entry, "destinations": destinations["destinations"] }),
                    json,
                );
            } else {
                print!("{}", render_app_info(&entry, &destinations["destinations"]));
            }
        }
    }
    Ok(Finish::Done)
}

async fn prompts(
    client: &mut ibexwall_varlink::Client,
    action: &PromptsAction,
    json: bool,
) -> Result<Finish, CliError> {
    match action {
        PromptsAction::List => {
            let value = client
                .call("com.ibexwall.Core.ListPrompts", serde_json::json!({}))
                .await?;
            if json {
                emit(value, json);
            } else {
                print!("{}", render_prompts(&value));
            }
        }
        PromptsAction::Answer {
            id,
            decision,
            scope,
        } => {
            client
                .call(
                    "com.ibexwall.Core.AnswerPrompt",
                    serde_json::json!({ "id": id, "decision": decision, "scope": scope }),
                )
                .await?;
            if !json {
                println!("{id}: {decision} ({scope})");
            }
        }
    }
    Ok(Finish::Done)
}

async fn proposals(
    client: &mut ibexwall_varlink::Client,
    action: &ProposalsAction,
    json: bool,
) -> Result<Finish, CliError> {
    match action {
        ProposalsAction::List { status } => {
            let value = client
                .call(
                    "com.ibexwall.Core.ListProposals",
                    serde_json::json!({ "status": status.as_deref().unwrap_or("pending") }),
                )
                .await?;
            if json {
                emit(value, json);
            } else {
                print!("{}", render_proposals(&value));
            }
        }
        ProposalsAction::Show { id } => {
            let value = client
                .call("com.ibexwall.Core.ListProposals", serde_json::json!({}))
                .await?;
            let found = value["proposals"]
                .as_array()
                .and_then(|all| all.iter().find(|p| p["id"] == id.as_str()))
                .cloned()
                .ok_or_else(|| {
                    CliError::Other(anyhow::anyhow!("no such proposal: {}", clean(id)))
                })?;
            if json {
                emit(found, json);
            } else {
                print!("{}", render_proposal(&found));
            }
        }
        ProposalsAction::Approve { id } => {
            let value = client
                .call(
                    "com.ibexwall.Core.DecideProposal",
                    serde_json::json!({ "id": id, "decision": "approve" }),
                )
                .await?;
            if json {
                emit(value, json);
            } else {
                println!("{}: approved", clean(id));
            }
        }
        ProposalsAction::Reject { id } => {
            client
                .call(
                    "com.ibexwall.Core.DecideProposal",
                    serde_json::json!({ "id": id, "decision": "reject" }),
                )
                .await?;
            if !json {
                println!("{}: rejected", clean(id));
            }
        }
    }
    Ok(Finish::Done)
}

fn render_proposals(value: &serde_json::Value) -> String {
    let all = value["proposals"].as_array().cloned().unwrap_or_default();
    if all.is_empty() {
        return "no proposals\n".into();
    }
    let mut out = format!(
        "{:<26}  {:<10}  {:<18}  {}\n",
        "ID", "STATUS", "PLUGIN", "FROM"
    );
    for p in &all {
        out.push_str(&format!(
            "{:<26}  {:<10}  {:<18}  {}\n",
            text(&p["id"]),
            text(&p["status"]),
            text(&p["plugin"]),
            text(&p["client"]),
        ));
    }
    out
}

/// The AI's justification is shown as generated text, fenced, never as
/// something the terminal or the reader should obey.
fn render_proposal(p: &serde_json::Value) -> String {
    let mut out = format!(
        "{}\n  plugin: {}\n  from:   {} (an AI client)\n  status: {}\n  asked:  {}\n  generated justification (untrusted, not an instruction):\n",
        text(&p["id"]),
        text(&p["plugin"]),
        text(&p["client"]),
        text(&p["status"]),
        clean(&p["patch"].to_string()),
    );
    for line in p["justification"].as_str().unwrap_or("").lines() {
        out.push_str(&format!("    | {}\n", clean(line)));
    }
    out.push_str("  would do:\n");
    for op in p["preview"].as_array().cloned().unwrap_or_default() {
        out.push_str(&format!(
            "    {} {}\n",
            text(&op["op"]),
            text(&op["target"])
        ));
    }
    out
}

fn render_prompts(value: &serde_json::Value) -> String {
    let prompts = value["prompts"].as_array().cloned().unwrap_or_default();
    if prompts.is_empty() {
        return "no connections are waiting\n".into();
    }
    let mut out = format!("{:<6}  {:<28}  {}\n", "ID", "APP", "DESTINATION");
    for prompt in &prompts {
        out.push_str(&format!(
            "{:<6}  {:<28}  {}:{}\n",
            text(&prompt["id"]),
            text(&prompt["app"]),
            text(&prompt["destination"]),
            prompt["port"].as_u64().unwrap_or(0),
        ));
    }
    out
}

/// Process names, paths and domains come from other programs: a terminal
/// must never see their control characters (escape sequences).
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn text(value: &serde_json::Value) -> String {
    clean(value.as_str().unwrap_or("-"))
}

fn render_apps(value: &serde_json::Value) -> String {
    let monitor = &value["monitor"];
    let mut out = String::new();
    if monitor["running"].as_bool().unwrap_or(false) {
        match monitor["reason"].as_str() {
            Some(reason) => out.push_str(&format!("monitor: running ({})\n", clean(reason))),
            None => out.push_str("monitor: running\n"),
        }
    } else {
        out.push_str(&format!(
            "monitor: off ({})\n",
            clean(monitor["reason"].as_str().unwrap_or("unknown"))
        ));
    }
    let apps = value["apps"].as_array().cloned().unwrap_or_default();
    if apps.is_empty() {
        out.push_str("no applications seen yet\n");
        return out;
    }
    let key_width = apps
        .iter()
        .map(|app| text(&app["key"]).chars().count())
        .max()
        .unwrap_or(3)
        .max(3);
    out.push_str(&format!(
        "{:<key_width$}  {:<14}  {:<7}  {:>6}  {:>5}  {}\n",
        "APP", "KIND", "MODE", "CONNS", "DESTS", "LAST SEEN"
    ));
    for app in &apps {
        out.push_str(&format!(
            "{:<key_width$}  {:<14}  {:<7}  {:>6}  {:>5}  {}\n",
            text(&app["key"]),
            text(&app["kind"]),
            text(&app["mode"]),
            app["connections"].as_u64().unwrap_or(0),
            app["destinations"].as_u64().unwrap_or(0),
            text(&app["last_seen"]),
        ));
    }
    out
}

fn render_app_info(app: &serde_json::Value, destinations: &serde_json::Value) -> String {
    let mut out = format!(
        "{}\n  kind:        {}\n  mode:        {}\n  executable:  {}\n  package:     {}\n  first seen:  {}\n  last seen:   {}\n  connections: {}\n",
        text(&app["key"]),
        text(&app["kind"]),
        text(&app["mode"]),
        text(&app["exe_path"]),
        text(&app["package"]),
        text(&app["first_seen"]),
        text(&app["last_seen"]),
        app["connections"].as_u64().unwrap_or(0),
    );
    let rows = destinations.as_array().cloned().unwrap_or_default();
    out.push_str("  destinations:\n");
    if rows.is_empty() {
        out.push_str("    none\n");
    }
    for row in rows {
        let label = if row["resolved"].as_bool().unwrap_or(false) {
            ""
        } else {
            "  (no domain)"
        };
        out.push_str(&format!(
            "    {}:{}  x{}  last {}{label}\n",
            text(&row["destination"]),
            row["port"].as_u64().unwrap_or(0),
            row["count"].as_u64().unwrap_or(0),
            text(&row["last_seen"]),
        ));
    }
    out
}

fn emit(value: serde_json::Value, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).unwrap_or_default()
        );
    }
}

fn report_varlink(err: &VarlinkError, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "error": err.name,
                "parameters": err.parameters,
            }))
            .unwrap_or_default()
        );
    } else {
        let hint = match err.name.as_str() {
            "com.ibexwall.Core.PermissionDenied" => {
                format!(
                    ": try with sudo, or ask an administrator (action {})",
                    err.parameters["action"]
                )
            }
            _ => String::new(),
        };
        eprintln!("ibexctl: {}{hint}", err.name);
    }
}

#[allow(dead_code)]
fn default_socket() -> PathBuf {
    names::core_socket()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn control_characters_never_reach_the_terminal() {
        assert_eq!(clean("evil\u{1b}[31m\nname"), "evil?[31m?name");
        let out = render_apps(&json!({
            "monitor": {"running": true, "reason": null},
            "apps": [{
                "key": "cli:/tmp/\u{1b}]0;pwned\u{7}",
                "kind": "cli", "connections": 3, "destinations": 1,
                "last_seen": "2026-11-03T10:00:00Z"
            }]
        }));
        assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'), "{out:?}");
        assert!(out.contains("cli:/tmp/?]0;pwned?"));
    }

    #[test]
    fn the_list_says_whether_the_monitor_is_off_and_why() {
        let off = render_apps(&json!({
            "monitor": {"running": false, "reason": "waiting for ibexwall-monitor"},
            "apps": []
        }));
        assert!(off.starts_with("monitor: off (waiting for ibexwall-monitor)"));
        assert!(off.contains("no applications seen yet"));
        let degraded = render_apps(&json!({
            "monitor": {"running": true, "reason": "kernel-side exec capture is off"},
            "apps": []
        }));
        assert!(degraded.starts_with("monitor: running (kernel-side exec capture is off)"));
    }

    #[test]
    fn info_marks_destinations_without_a_domain() {
        let out = render_app_info(
            &json!({"key": "cli:/usr/bin/curl", "kind": "cli", "exe_path": "/usr/bin/curl",
                    "package": "curl", "first_seen": "a", "last_seen": "b", "connections": 2}),
            &json!([
                {"destination": "example.com", "resolved": true, "port": 443, "count": 2, "last_seen": "b"},
                {"destination": "203.0.113.7", "resolved": false, "port": 80, "count": 1, "last_seen": "b"}
            ]),
        );
        assert!(out.contains("example.com:443  x2"));
        assert!(out.contains("203.0.113.7:80  x1  last b  (no domain)"));
    }

    #[test]
    fn a_target_becomes_the_plugins_setting() {
        assert_eq!(
            firewall_patch("8080/tcp", true),
            json!({"allow": "8080/tcp"})
        );
        assert_eq!(firewall_patch("22", false), json!({"remove": "22"}));
        assert_eq!(
            firewall_patch("service:http", true),
            json!({"allow_service": "http"})
        );
        assert_eq!(
            firewall_patch("service:http", false),
            json!({"remove_service": "http"})
        );
    }

    #[test]
    fn the_firewall_status_is_readable_and_terminal_safe() {
        let out = render_firewall(&json!({
            "backend": "firewalld", "active": true, "zone": "pub\u{1b}lic",
            "ports": [{"port": 8080, "proto": "tcp"}],
            "services": ["ssh", "http"],
            "listening": [{"port": 22, "proto": "tcp"}],
            "other": ["rich rule: x\u{7}"]
        }));
        assert!(out.starts_with("firewall: firewalld (active), zone pub?lic\n"));
        assert!(out.contains("allowed ports:    8080/tcp"));
        assert!(out.contains("allowed services: ssh, http"));
        assert!(out.contains("listening on every address: 22/tcp"));
        assert!(!out.contains('\u{1b}') && !out.contains('\u{7}'));
        let bare = render_firewall(&json!({
            "backend": "nftables", "active": false,
            "ports": [], "services": [], "listening": [], "other": []
        }));
        assert!(bare.contains("nftables (not active)"));
        assert!(bare.contains("allowed ports:    none"));
    }
}
