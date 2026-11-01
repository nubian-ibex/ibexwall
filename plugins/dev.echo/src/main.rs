// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `dev.echo` plugin: serves the `com.ibexwall.Plugin` interface with
//! template-driven plans so the engine, supervisor and CLI can be
//! exercised end to end. Development/test only; never packaged.

use std::sync::Arc;

use ibexwall_proto::names;
use ibexwall_proto::{Op, UnitAction};
use ibexwall_varlink::{Call, Handler, Reply, ServiceInfo, futures_handle};
use serde_json::{Value, json};

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(run()) {
        eprintln!("ibexwall-plugin-echo: {err:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let socket = names::plugin_socket("dev.echo");
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A killed predecessor leaves its socket file behind.
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket)?;
    let mut interfaces = std::collections::HashMap::new();
    interfaces.insert(
        names::IFACE_PLUGIN.to_string(),
        include_str!("../../../spec/idl/com.ibexwall.Plugin.varlink").to_string(),
    );
    let info = ServiceInfo {
        vendor: "Nubian Ibex".into(),
        product: "dev.echo".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        url: String::new(),
        interfaces,
    };
    ibexwall_varlink::serve(listener, info, Arc::new(Echo)).await
}

struct Echo;

impl Handler for Echo {
    fn handle(
        &self,
        call: Call,
        out: tokio::sync::mpsc::Sender<Reply>,
    ) -> futures_handle::BoxHandle {
        futures_handle::BoxHandle::new(async move {
            let method = call
                .method
                .strip_prefix("com.ibexwall.Plugin.")
                .unwrap_or(&call.method)
                .to_string();
            let reply = match method.as_str() {
                "Describe" => Reply::result(json!({
                    "manifest": { "id": "dev.echo", "api": 1 },
                    "api": 1,
                })),
                "Check" => Reply::result(json!({
                    "findings": [ {
                        "id": "dev.echo.check",
                        "plugin": "dev.echo",
                        "severity": "low",
                        "title_key": "dev-echo-finding-title",
                        "summary_key": "dev-echo-finding-summary",
                        "status": "open",
                        "detected_at": "1970-01-01T00:00:00Z",
                    } ]
                })),
                "Plan" => {
                    let template = call
                        .parameters
                        .get("config")
                        .and_then(|c| c.get("template"))
                        .and_then(Value::as_str)
                        .unwrap_or("noop");
                    match plan_for(template) {
                        Ok(ops) => Reply::result(json!({
                            "ops": ops,
                            "notes": [format!("template: {template}")],
                            "may_affect_keys": [],
                        })),
                        Err(reason) => Reply::error(
                            "com.ibexwall.Core.InvalidArgument",
                            json!({ "field": "template", "reason": reason }),
                        ),
                    }
                }
                "Verify" => Reply::result(json!({ "ok": true, "details": [] })),
                "Monitor" => {
                    // One event, then the stream closes (F1 minimal).
                    let _ = out
                        .send(Reply::result_continues(json!({
                            "kind": "dev.echo.heartbeat", "data": {}
                        })))
                        .await;
                    Reply::result(json!({ "kind": "dev.echo.done", "data": {} }))
                }
                "Reconcile" => Reply::result(json!({ "applied": true, "details": [] })),
                other => Reply::error(
                    ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
                    json!({ "method": other }),
                ),
            };
            let _ = out.send(reply).await;
        })
    }
}

/// Templates the test suites drive through `PlanChange`.
fn plan_for(template: &str) -> Result<Vec<Op>, String> {
    let ops = match template {
        "noop" => vec![],
        "dropin" => vec![
            Op::FileWrite {
                path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
                content: "kernel.ibexwall_test = 1\n".into(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::SysctlSet {
                key: "kernel.ibexwall_test".into(),
                value: "1".into(),
            },
        ],
        // File-only variant for real systems where the fake sysctl key
        // does not exist in /proc/sys.
        "dropin_file" => vec![Op::FileWrite {
            path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
            content: "# managed by IbexWall (vm test)\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }],
        // Real, harmless sysctl for VM runs.
        "sysctl" => vec![
            Op::FileWrite {
                path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
                content: "vm.swappiness = 10\n".into(),
                mode: "0644".into(),
                owner: "root".into(),
                group: "root".into(),
            },
            Op::SysctlSet {
                key: "vm.swappiness".into(),
                value: "10".into(),
            },
        ],
        "network" => vec![Op::FileWrite {
            path: "/etc/NetworkManager/conf.d/50-ibexwall-test.conf".into(),
            content: "# managed by IbexWall (dev test)\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }],
        "slow" => vec![Op::Exec {
            path: "/usr/bin/sleep".into(),
            args: vec!["10".into()],
        }],
        "unit" => vec![Op::SystemdUnit {
            unit: "ibexwall-test.service".into(),
            action: UnitAction::Restart,
            now: Some(true),
        }],
        // Deliberately outside the manifest: the core must refuse it.
        "out_of_manifest" => vec![Op::FileWrite {
            path: "/etc/ibexwall-refuse-me.conf".into(),
            content: "nope\n".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }],
        other => return Err(format!("unknown template `{other}`")),
    };
    Ok(ops)
}
