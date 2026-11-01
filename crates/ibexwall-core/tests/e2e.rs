// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! End-to-end test: a real daemon + the real dev.echo plugin over
//! varlink under a sandbox root, with a fake polkit. This is the
//! unprivileged rehearsal of the F1 acceptance criteria; the VM suite
//! re-runs them against real systemd/nftables/polkit.
//!
//! Requires `cargo build -p ibexwall-plugin-echo` (any workspace-wide
//! test invocation builds it; the test skips with a notice otherwise).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::Signer;
use serde_json::json;

use ibexwall_core::api::Api;
use ibexwall_core::{Core, TxRow};
use ibexwall_proto::TransactionState;
use ibexwall_sys::{FakePolkit, RealSysctl, Sysctl};
use ibexwall_varlink::Client;

/// Minimal tempdir (no extra dependency).
struct TempDir(PathBuf);

impl TempDir {
    fn new(prefix: &str) -> Self {
        // Short paths: unix socket paths must stay under 108 bytes
        // (SUN_LEN), so no timestamp suffixes.
        let path = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Sandbox {
    root: PathBuf,
    socket: PathBuf,
    _dir: TempDir,
}

fn repo_dir(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn plugin_binary() -> Option<PathBuf> {
    let binary = repo_dir("../../target/debug/ibexwall-plugin-echo");
    binary.is_file().then_some(binary)
}

/// Signs `data` with a fresh key and writes a minisign-format public
/// key + signature (mirrors `xtask devkey`).
fn write_dev_trust(dir: &Path, data: &[u8]) -> PathBuf {
    use blake2::digest::{Update, VariableOutput};
    let mut secret_bytes = [0u8; 32];
    std::io::Read::read_exact(
        &mut std::fs::File::open("/dev/urandom").unwrap(),
        &mut secret_bytes,
    )
    .unwrap();
    let secret = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    use sha2::Digest as _;
    let key_id: [u8; 8] = sha2::Sha256::digest(secret.verifying_key().as_bytes())[..8]
        .try_into()
        .unwrap();

    let mut hasher = blake2::Blake2bVar::new(64).unwrap();
    hasher.update(data);
    let mut prehash = [0u8; 64];
    hasher.finalize_variable(&mut prehash).unwrap();
    let signature = secret.sign(&prehash);
    let comment = "ibexwall dev plugin";
    let mut global_input = Vec::new();
    global_input.extend_from_slice(&signature.to_bytes());
    global_input.extend_from_slice(comment.as_bytes());
    let global = secret.sign(&global_input);

    let mut sig_bytes = Vec::with_capacity(74);
    sig_bytes.extend_from_slice(&[0x45, 0x44]);
    sig_bytes.extend_from_slice(&key_id);
    sig_bytes.extend_from_slice(&signature.to_bytes());
    let mut pub_bytes = Vec::with_capacity(42);
    pub_bytes.extend_from_slice(&[0x45, 0x64]);
    pub_bytes.extend_from_slice(&key_id);
    pub_bytes.extend_from_slice(secret.verifying_key().as_bytes());
    let engine = base64::engine::general_purpose::STANDARD;

    let pub_path = dir.join("dev.pub");
    std::fs::write(
        &pub_path,
        format!(
            "untrusted comment: test key\n{}\n",
            engine.encode(pub_bytes)
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("plugin.toml.sig"),
        format!(
            "untrusted comment: test sig\n{}\ntrusted comment: {comment}\n{}\n",
            engine.encode(sig_bytes),
            engine.encode(global.to_bytes())
        ),
    )
    .unwrap();
    pub_path
}

fn prepare_sandbox() -> Sandbox {
    let dir = TempDir::new("ibx-e2e");
    let root = dir.0.join("root");
    for sub in [
        "etc/ibexwall",
        "var/lib/ibexwall",
        "run/ibexwall",
        "etc/sysctl.d",
        "proc/sys/kernel",
    ] {
        std::fs::create_dir_all(root.join(sub)).unwrap();
    }
    // Prior sysctl state the engine must restore on rollback.
    std::fs::write(root.join("proc/sys/kernel/ibexwall_test"), "0\n").unwrap();
    // Prior drop-in with distinct content and mode (byte-for-byte
    // rollback target).
    std::fs::write(
        root.join("etc/sysctl.d/90-ibexwall-test.conf"),
        "kernel.ibexwall_test = 0\n",
    )
    .unwrap();
    set_mode(&root.join("etc/sysctl.d/90-ibexwall-test.conf"), 0o600);

    let plugin_dir = root.join("usr/lib/ibexwall/plugins/dev.echo");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    let manifest = std::fs::read(repo_dir("../../plugins/dev.echo/plugin.toml")).unwrap();
    std::fs::write(plugin_dir.join("plugin.toml"), &manifest).unwrap();
    let _pub_path = write_dev_trust(&plugin_dir, &manifest);
    if let Some(binary) = plugin_binary() {
        // Symlink, not copy: /tmp is exec-restricted here, and the
        // spawned process resolves to the real file under target/.
        std::os::unix::fs::symlink(binary, plugin_dir.join("ibexwall-plugin-echo")).unwrap();
    }

    let socket = root.join("run/ibexwall/core.sock");
    let _ = std::fs::remove_file(&socket);
    Sandbox {
        root,
        socket,
        _dir: dir,
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn test_service_info() -> ibexwall_varlink::ServiceInfo {
    ibexwall_varlink::ServiceInfo {
        vendor: "test".into(),
        product: "ibexwall".into(),
        version: "1".into(),
        url: String::new(),
        interfaces: Default::default(),
    }
}

async fn spawn_daemon(sandbox: &Sandbox, polkit: FakePolkit) -> (Arc<Core>, Client) {
    let core = Arc::new(
        Core::open(
            sandbox.root.clone(),
            Some(
                sandbox
                    .root
                    .join("usr/lib/ibexwall/plugins/dev.echo/dev.pub"),
            ),
        )
        .await
        .unwrap(),
    );
    let api = Api::with_polkit(Arc::clone(&core), Arc::new(polkit));
    // Fresh socket per daemon (the crash-recovery test runs two).
    static DAEMONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let socket = sandbox.root.join("run/ibexwall").join(format!(
        "core-{}.sock",
        DAEMONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(ibexwall_varlink::serve(
        listener,
        test_service_info(),
        Arc::new(api),
    ));
    let client = Client::connect(&socket).await.unwrap();
    (core, client)
}

fn all_actions_polkit() -> FakePolkit {
    let mut polkit = FakePolkit::new();
    for action in ibexwall_proto::names::polkit_actions() {
        polkit.allow(current_uid(), action);
    }
    polkit
}

fn current_uid() -> u32 {
    // /proc/self/status Uid line, no libc dependency, no unsafe.
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

async fn plan_with(client: &mut Client, template: &str) -> serde_json::Value {
    client
        .call(
            "com.ibexwall.Core.PlanChange",
            json!({ "plugin": "dev.echo", "patch": { "template": template } }),
        )
        .await
        .unwrap()["plan"]
        .clone()
}

#[tokio::test]
async fn full_flow_plan_apply_rollback_confirm_and_gates() {
    if plugin_binary().is_none() {
        eprintln!("skipping e2e: build ibexwall-plugin-echo first (cargo build --workspace)");
        return;
    }
    let sandbox = prepare_sandbox();
    let (core, mut client) = spawn_daemon(&sandbox, all_actions_polkit()).await;

    // Enable the plugin.
    client
        .call(
            "com.ibexwall.Core.SetPluginEnabled",
            json!({ "id": "dev.echo", "enabled": true }),
        )
        .await
        .unwrap();

    // Checks produce a finding.
    let value = client
        .call(
            "com.ibexwall.Core.RunChecks",
            json!({ "plugin": "dev.echo" }),
        )
        .await
        .unwrap();
    assert_eq!(value["findings"].as_array().map(Vec::len), Some(1));

    // Plan + apply (dropin template): overwrite prior content.
    let plan = plan_with(&mut client, "dropin").await;
    assert_eq!(plan["requires_confirm"], false);
    let plan_id = plan["id"].as_str().unwrap().to_string();
    let value = client
        .call("com.ibexwall.Core.Apply", json!({ "plan_id": plan_id }))
        .await
        .unwrap();
    let tx = value["transaction"]["id"].as_str().unwrap().to_string();
    assert_eq!(value["transaction"]["state"], "committed");

    let target = sandbox.root.join("etc/sysctl.d/90-ibexwall-test.conf");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "kernel.ibexwall_test = 1\n"
    );
    let sysctl = RealSysctl::with_root(sandbox.root.clone());
    assert_eq!(sysctl.get("kernel.ibexwall_test").unwrap(), "1");

    // Rollback restores byte-for-byte, including the prior mode.
    client
        .call("com.ibexwall.Core.Rollback", json!({ "target": tx }))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "kernel.ibexwall_test = 0\n"
    );
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(sysctl.get("kernel.ibexwall_test").unwrap(), "0");

    // Network-risk plan: pending confirmation, then confirm.
    let plan = plan_with(&mut client, "network").await;
    assert_eq!(plan["requires_confirm"], true);
    let plan_id = plan["id"].as_str().unwrap().to_string();
    let value = client
        .call(
            "com.ibexwall.Core.Apply",
            json!({ "plan_id": plan_id, "confirm_timeout_s": 3600 }),
        )
        .await
        .unwrap();
    let tx = value["transaction"]["id"].as_str().unwrap().to_string();
    assert_eq!(value["transaction"]["state"], "pending_confirm");
    assert!(
        sandbox
            .root
            .join("etc/NetworkManager/conf.d/50-ibexwall-test.conf")
            .exists()
    );
    client
        .call("com.ibexwall.Core.Confirm", json!({ "transaction_id": tx }))
        .await
        .unwrap();
    assert!(
        sandbox
            .root
            .join("etc/NetworkManager/conf.d/50-ibexwall-test.conf")
            .exists()
    );

    // Out-of-manifest plan is refused at PlanChange (the gate).
    let err = client
        .call(
            "com.ibexwall.Core.PlanChange",
            json!({ "plugin": "dev.echo", "patch": { "template": "out_of_manifest" } }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.name, "com.ibexwall.Core.InvalidArgument");

    // Audit chain is valid after all operations.
    assert!(matches!(
        core.audit_verify(),
        ibexwall_core::audit::Verification::Valid { .. }
    ));
}

#[tokio::test]
async fn confirmation_timeout_rolls_back_automatically() {
    if plugin_binary().is_none() {
        eprintln!("skipping e2e: build ibexwall-plugin-echo first (cargo build --workspace)");
        return;
    }
    let sandbox = prepare_sandbox();
    let (_core, mut client) = spawn_daemon(&sandbox, all_actions_polkit()).await;
    client
        .call(
            "com.ibexwall.Core.SetPluginEnabled",
            json!({ "id": "dev.echo", "enabled": true }),
        )
        .await
        .unwrap();

    let plan = plan_with(&mut client, "network").await;
    let plan_id = plan["id"].as_str().unwrap().to_string();
    let value = client
        .call(
            "com.ibexwall.Core.Apply",
            json!({ "plan_id": plan_id, "confirm_timeout_s": 2 }),
        )
        .await
        .unwrap();
    assert_eq!(value["transaction"]["state"], "pending_confirm");
    let target = sandbox
        .root
        .join("etc/NetworkManager/conf.d/50-ibexwall-test.conf");
    assert!(target.exists());

    // Without Confirm, the watchdog reverts at the deadline.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    assert!(
        !target.exists(),
        "network change must auto-revert without confirmation"
    );
    let value = client
        .call("com.ibexwall.Core.History", json!({}))
        .await
        .unwrap();
    let history = serde_json::to_string(&value).unwrap();
    assert!(
        history.contains("rolled_back"),
        "history must record the auto-rollback: {history}"
    );
}

#[tokio::test]
async fn crash_recovery_rolls_back_interrupted_transactions() {
    if plugin_binary().is_none() {
        eprintln!("skipping e2e: build ibexwall-plugin-echo first (cargo build --workspace)");
        return;
    }
    let sandbox = prepare_sandbox();
    let (core, mut client) = spawn_daemon(&sandbox, all_actions_polkit()).await;
    client
        .call(
            "com.ibexwall.Core.SetPluginEnabled",
            json!({ "id": "dev.echo", "enabled": true }),
        )
        .await
        .unwrap();
    let plan = plan_with(&mut client, "dropin").await;
    let plan_id = plan["id"].as_str().unwrap().to_string();
    let persisted = core.state.load_plan(&plan_id).unwrap().unwrap();
    let ops: Vec<ibexwall_proto::Op> = serde_json::from_str(&persisted.ops_json).unwrap();

    // Simulate a crash mid-apply: snapshot taken, ops partially run, the
    // transaction row says `applying`.
    core.engine.snapshot(&core.state, "tx-crash", &ops).unwrap();
    core.engine.execute(&ops).unwrap();
    core.state
        .insert_transaction(
            &TxRow {
                id: "tx-crash".into(),
                plan_id,
                plugin: "dev.echo".into(),
                state: TransactionState::Applying,
                restore_point: "snapshots/tx-crash".into(),
            },
            "2026-11-01T12:00:00Z",
        )
        .unwrap();
    drop(client);
    let target = sandbox.root.join("etc/sysctl.d/90-ibexwall-test.conf");
    assert!(target.exists());

    // Daemon B: recovery must roll the transaction back.
    let (_core2, mut client2) = spawn_daemon(&sandbox, all_actions_polkit()).await;
    let value = client2
        .call("com.ibexwall.Core.History", json!({}))
        .await
        .unwrap();
    let history = serde_json::to_string(&value).unwrap();
    assert!(
        history.contains("rolled_back"),
        "recovery must mark the transaction rolled back: {history}"
    );
}

#[tokio::test]
async fn unauthorized_callers_get_permission_denied() {
    if plugin_binary().is_none() {
        eprintln!("skipping e2e: build ibexwall-plugin-echo first (cargo build --workspace)");
        return;
    }
    let sandbox = prepare_sandbox();
    // A polkit that allows nothing.
    let (_core, mut client) = spawn_daemon(&sandbox, FakePolkit::new()).await;
    let err = client
        .call(
            "com.ibexwall.Core.SetPluginEnabled",
            json!({ "id": "dev.echo", "enabled": true }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.name, "com.ibexwall.Core.PermissionDenied");
    assert_eq!(err.parameters["action"], "com.ibexwall.plugins.manage");
}

#[tokio::test]
async fn unsigned_plugins_are_refused_on_use() {
    if plugin_binary().is_none() {
        eprintln!("skipping e2e: build ibexwall-plugin-echo first (cargo build --workspace)");
        return;
    }
    let sandbox = prepare_sandbox();
    // Corrupt the signature.
    let sig = sandbox
        .root
        .join("usr/lib/ibexwall/plugins/dev.echo/plugin.toml.sig");
    std::fs::write(
        &sig,
        "untrusted comment: bad\nAAAA\ntrusted comment: x\nAAAA\n",
    )
    .unwrap();
    let core = Core::open(
        sandbox.root.clone(),
        Some(
            sandbox
                .root
                .join("usr/lib/ibexwall/plugins/dev.echo/dev.pub"),
        ),
    )
    .await
    .unwrap();
    let err = core.plugins.verify_signature("dev.echo").unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("signature"),
        "expected a signature failure, got: {message}"
    );
}
