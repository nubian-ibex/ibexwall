// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! IbexWall plugin SDK.
//!
//! A plugin implements [`Plugin`] and calls [`serve`]. The SDK owns the
//! wire protocol (`com.ibexwall.Plugin` over varlink), socket creation and
//! stale-socket cleanup, so a plugin only contains its own logic.
//! Plugins **propose** typed operations ([`ibexwall_proto::Op`]); the core
//! validates and executes them.
//!
//! This crate is permissively licensed and must not depend on GPL code.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use ibexwall_proto::{CheckReport, Op, names};
use ibexwall_varlink::{Call, Handler, Reply, ServiceInfo, futures_handle::BoxHandle};
use serde_json::{Value, json};
use tokio::net::UnixListener;
use tokio::sync::mpsc::Sender;

pub use ibexwall_proto as proto;

/// Errors a plugin can report; they are mapped to named varlink errors.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// A caller-supplied value is wrong.
    #[error("invalid {field}: {reason}")]
    Invalid { field: String, reason: String },
    /// The plugin does not implement the method.
    #[error("method `{0}` is not supported by this plugin")]
    Unsupported(&'static str),
    /// Anything else; the message reaches the user, so keep it free of
    /// secrets.
    #[error("{0}")]
    Failed(String),
}

impl PluginError {
    pub fn invalid(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            reason: reason.into(),
        }
    }

    fn into_reply(self) -> Reply {
        match self {
            Self::Invalid { field, reason } => Reply::error(
                "com.ibexwall.Core.InvalidArgument",
                json!({ "field": field, "reason": reason }),
            ),
            Self::Unsupported(method) => Reply::error(
                ibexwall_varlink::service_errors::METHOD_NOT_IMPLEMENTED,
                json!({ "method": method }),
            ),
            Self::Failed(reason) => {
                Reply::error("com.ibexwall.Plugin.Failed", json!({ "reason": reason }))
            }
        }
    }
}

/// The plugin contract. Only `id` and `check` are required.
pub trait Plugin: Send + Sync + 'static {
    /// Plugin id, `<category>.<name>`.
    fn id(&self) -> &'static str;

    /// Evaluates the plugin's checks. Must not change the system.
    fn check(&self, config: Value)
    -> impl Future<Output = Result<CheckReport, PluginError>> + Send;

    /// Proposes the operations for a configuration change.
    fn plan(&self, config: Value) -> impl Future<Output = Result<Vec<Op>, PluginError>> + Send {
        let _ = config;
        async { Err(PluginError::Unsupported("Plan")) }
    }

    /// Verifies the result after the core applied `ops`.
    fn verify(&self, transaction: &str, ops: &[Op]) -> impl Future<Output = bool> + Send {
        let _ = (transaction, ops);
        async { true }
    }
}

/// Binds the plugin socket under `IBEXWALL_ROOT` (removing a stale one
/// left by a killed predecessor) and serves until the process stops.
pub async fn serve<P: Plugin>(plugin: P) -> std::io::Result<()> {
    let socket = names::plugin_socket(plugin.id());
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&socket);
    serve_on(UnixListener::bind(&socket)?, plugin).await
}

/// Serves on an already bound listener (tests, socket activation).
pub async fn serve_on<P: Plugin>(listener: UnixListener, plugin: P) -> std::io::Result<()> {
    let info = ServiceInfo {
        vendor: "Nubian Ibex".into(),
        product: plugin.id().into(),
        version: String::new(),
        url: String::new(),
        interfaces: Default::default(),
    };
    ibexwall_varlink::serve(listener, info, Arc::new(Adapter(Arc::new(plugin))))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

struct Adapter<P>(Arc<P>);

impl<P: Plugin> Handler for Adapter<P> {
    fn handle(&self, call: Call, out: Sender<Reply>) -> BoxHandle {
        let plugin = Arc::clone(&self.0);
        BoxHandle::new(async move {
            let method = call
                .method
                .strip_prefix("com.ibexwall.Plugin.")
                .unwrap_or(&call.method)
                .to_string();
            let reply = dispatch(&*plugin, &method, call.parameters).await;
            let _ = out.send(reply).await;
        })
    }
}

async fn dispatch<P: Plugin>(plugin: &P, method: &str, params: Value) -> Reply {
    match method {
        "Describe" => Reply::result(json!({ "manifest": { "id": plugin.id() }, "api": 1 })),
        "Check" => match plugin
            .check(params.get("config").cloned().unwrap_or(Value::Null))
            .await
        {
            Ok(report) => Reply::result(json!({
                "findings": report.findings,
                "results": report.results,
            })),
            Err(err) => err.into_reply(),
        },
        "Plan" => match plugin
            .plan(params.get("config").cloned().unwrap_or(Value::Null))
            .await
        {
            Ok(ops) => Reply::result(json!({ "ops": ops, "notes": [], "may_affect_keys": [] })),
            Err(err) => err.into_reply(),
        },
        "Verify" => {
            let tx = params
                .get("transaction_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let ops: Vec<Op> = params
                .get("ops")
                .cloned()
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default();
            Reply::result(json!({ "ok": plugin.verify(tx, &ops).await, "details": [] }))
        }
        "Monitor" | "Reconcile" => PluginError::Unsupported("Monitor/Reconcile").into_reply(),
        other => Reply::error(
            ibexwall_varlink::service_errors::METHOD_NOT_FOUND,
            json!({ "method": other }),
        ),
    }
}

/// Convenience for plugins that read files under the sandbox root.
pub fn under_root(path: &str) -> std::path::PathBuf {
    names::path_under(&names::root(), path)
}

/// Reads a file under the sandbox root; `None` when it is missing or
/// unreadable (checks treat that as "cannot tell", not as a pass).
pub fn read_text(path: &str) -> Option<String> {
    std::fs::read_to_string(under_root(path)).ok()
}

/// True when `path` exists under the sandbox root.
pub fn exists(path: &str) -> bool {
    Path::new(&under_root(path)).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ibexwall_proto::{CheckOutcome, CheckResult, Severity};
    use ibexwall_varlink::Client;

    struct Probe;

    impl Plugin for Probe {
        fn id(&self) -> &'static str {
            "dev.probe"
        }

        async fn check(&self, config: Value) -> Result<CheckReport, PluginError> {
            if config.get("boom").is_some() {
                return Err(PluginError::Failed("boom".into()));
            }
            Ok(CheckReport {
                results: vec![CheckResult {
                    id: "probe.one".into(),
                    severity: Severity::Low,
                    outcome: CheckOutcome::Pass,
                }],
                findings: vec![],
            })
        }

        async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
            match config.get("path").and_then(Value::as_str) {
                Some(path) => Ok(vec![Op::FileRemove { path: path.into() }]),
                None => Err(PluginError::invalid("path", "required")),
            }
        }
    }

    async fn client() -> (Client, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("ibx-sdk-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        tokio::spawn(serve_on(listener, Probe));
        (Client::connect(&path).await.unwrap(), path)
    }

    #[tokio::test]
    async fn serves_describe_check_plan_verify() {
        let (mut client, path) = client().await;
        let described = client
            .call("com.ibexwall.Plugin.Describe", json!({}))
            .await
            .unwrap();
        assert_eq!(described["manifest"]["id"], "dev.probe");

        let checked = client
            .call("com.ibexwall.Plugin.Check", json!({ "config": {} }))
            .await
            .unwrap();
        assert_eq!(checked["results"][0]["outcome"], "pass");

        let planned = client
            .call(
                "com.ibexwall.Plugin.Plan",
                json!({ "config": { "path": "/etc/x" } }),
            )
            .await
            .unwrap();
        assert_eq!(planned["ops"][0]["op"], "file.remove");

        let verified = client
            .call(
                "com.ibexwall.Plugin.Verify",
                json!({ "transaction_id": "t", "ops": [] }),
            )
            .await
            .unwrap();
        assert_eq!(verified["ok"], true);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn maps_plugin_errors_to_named_varlink_errors() {
        let (mut client, path) = client().await;
        let err = client
            .call("com.ibexwall.Plugin.Plan", json!({ "config": {} }))
            .await
            .unwrap_err();
        assert_eq!(err.name, "com.ibexwall.Core.InvalidArgument");
        let err = client
            .call(
                "com.ibexwall.Plugin.Check",
                json!({ "config": { "boom": 1 } }),
            )
            .await
            .unwrap_err();
        assert_eq!(err.name, "com.ibexwall.Plugin.Failed");
        let err = client
            .call("com.ibexwall.Plugin.Monitor", json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            err.name,
            ibexwall_varlink::service_errors::METHOD_NOT_IMPLEMENTED
        );
        let err = client
            .call("com.ibexwall.Plugin.Nope", json!({}))
            .await
            .unwrap_err();
        assert_eq!(err.name, ibexwall_varlink::service_errors::METHOD_NOT_FOUND);
        let _ = std::fs::remove_file(path);
    }
}
