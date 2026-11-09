// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The subcommands that do more than one call.

use super::*;

pub(crate) async fn compliance(
    client: &mut ibexwall_varlink::Client,
    action: &ComplianceCmd,
    json: bool,
) -> Result<Finish, CliError> {
    match action {
        ComplianceCmd::List => {
            let value = client
                .call(
                    "com.ibexwall.Core.ListComplianceProfiles",
                    serde_json::json!({}),
                )
                .await?;
            show(&value, json, render_compliance_list);
            Ok(Finish::Done)
        }
        ComplianceCmd::Show { profile } => {
            let value = client
                .call(
                    "com.ibexwall.Core.GetCompliance",
                    serde_json::json!({ "profile": profile }),
                )
                .await?;
            show(&value, json, render_compliance_report);
            Ok(Finish::Done)
        }
        ComplianceCmd::Export { profile, format } => {
            let value = client
                .call(
                    "com.ibexwall.Core.ExportCompliance",
                    serde_json::json!({ "profile": profile, "format": format }),
                )
                .await?;
            match format.as_str() {
                "csv" => println!("{}", value["export"].as_str().unwrap_or_default()),
                _ => emit(value["export"].clone(), json),
            }
            Ok(Finish::Done)
        }
    }
}

pub(crate) async fn plugins(
    client: &mut ibexwall_varlink::Client,
    action: &PluginsAction,
    json: bool,
) -> Result<Finish, CliError> {
    match action {
        PluginsAction::List => {
            let value = client
                .call("com.ibexwall.Core.ListPlugins", serde_json::json!({}))
                .await?;
            show(&value, json, render_plugins);
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
                .call("com.ibexwall.Core.SetPluginEnabled", ask(params))
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
pub(crate) fn firewall_patch(target: &str, allow: bool) -> serde_json::Value {
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

pub(crate) async fn firewall(
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
pub(crate) async fn plan_firewall(
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
            ask(serde_json::json!({ "plan_id": plan_id, "confirm_timeout_s": null })),
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

pub(crate) async fn apps(
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
        AppsAction::Monitor { state } => {
            let enabled = state == "on";
            client
                .call(
                    "com.ibexwall.Core.SetMonitorEnabled",
                    ask(serde_json::json!({ "enabled": enabled })),
                )
                .await?;
            if !json {
                println!("connection monitor: {state}");
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

pub(crate) async fn prompts(
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

pub(crate) async fn proposals(
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
                    ask(serde_json::json!({ "id": id, "decision": "approve" })),
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
                    ask(serde_json::json!({ "id": id, "decision": "reject" })),
                )
                .await?;
            if !json {
                println!("{}: rejected", clean(id));
            }
        }
    }
    Ok(Finish::Done)
}

pub(crate) struct McpToken<'a> {
    pub name: &'a str,
    pub preset: &'a str,
    pub client: Option<String>,
    pub id: Option<String>,
    pub expires: Option<String>,
    pub secret_stdin: bool,
}

/// Makes the token here, shows it once, and plans the change with its hash:
/// the secret never reaches the daemon, a plan or a log.
pub(crate) async fn mcp_token(
    client: &mut ibexwall_varlink::Client,
    request: McpToken<'_>,
    json: bool,
) -> Result<Finish, CliError> {
    use std::io::Read;
    let id = match request.id {
        Some(id) => id,
        None => {
            let bytes = ibexwall_token::random_bytes(4).map_err(|e| CliError::Other(e.into()))?;
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
                .chars()
                .take(8)
                .collect()
        }
    };
    let client_name = request.client.unwrap_or_else(|| format!("remote-{id}"));
    let secret = if request.secret_stdin {
        let mut text = String::new();
        std::io::stdin()
            .take(512)
            .read_to_string(&mut text)
            .map_err(|e| CliError::Other(e.into()))?;
        Some(text.trim().to_string())
    } else {
        None
    };
    let created = ibexwall_token::create(
        &id,
        request.name,
        &client_name,
        request.expires.as_deref(),
        secret.as_deref(),
    )
    .map_err(|e| CliError::Other(anyhow::anyhow!(e)))?;
    let hash = created
        .stanza
        .lines()
        .find_map(|l| l.strip_prefix("hash = \""))
        .and_then(|l| l.strip_suffix('"'))
        .ok_or_else(|| CliError::Other(anyhow::anyhow!("no hash was made")))?
        .to_string();
    let mut config = serde_json::json!({
        "action": "token_add", "id": id, "name": request.name,
        "client": client_name, "preset": request.preset, "hash": hash,
    });
    if let Some(day) = &request.expires {
        config["expires"] = serde_json::json!(day);
    }
    let params = serde_json::json!({ "plugin": "system.assistant", "patch": config });
    let value = client.call("com.ibexwall.Core.PlanChange", params).await?;
    if json {
        emit(
            serde_json::json!({ "token": created.token, "plan": value["plan"] }),
            json,
        );
    } else {
        println!(
            "Token (shown once; copy it now, only its hash is kept):\n\n  {}\n",
            created.token
        );
        println!("plan {} for system.assistant", value["plan"]["id"]);
        println!("apply with: ibexctl apply {}", value["plan"]["id"]);
        println!(
            "Then, on the client, keep the token in IBEXWALL_MCP_TOKEN. For the address and the certificate: ibexctl mcp config <client> --url https://HOST:PORT/mcp"
        );
    }
    Ok(Finish::Done)
}
pub(crate) async fn policy(
    client: &mut ibexwall_varlink::Client,
    action: &PolicyCmd,
    _json: bool,
) -> Result<Finish, CliError> {
    match action {
        PolicyCmd::ApplyBundle { file } => {
            let text =
                std::fs::read_to_string(file).map_err(|e| CliError::Other(anyhow::anyhow!(e)))?;
            let bundle: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| CliError::Other(anyhow::anyhow!(e)))?;
            let value = client
                .call(
                    "com.ibexwall.Policy.ApplyBundle",
                    serde_json::json!({ "bundle": bundle }),
                )
                .await?;
            super::emit(value, true);
            Ok(Finish::Done)
        }
    }
}
