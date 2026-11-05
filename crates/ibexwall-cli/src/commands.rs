// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! The subcommands that do more than one call.

use super::*;

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
