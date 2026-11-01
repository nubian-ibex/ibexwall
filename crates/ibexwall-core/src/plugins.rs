// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Plugin supervisor (F1 scope): discovery, manifest validation,
//! dev-key signature verification, direct process launching (dev/tests
//! and the F1 VM), and varlink calls into plugin processes
//! (Describe/Check/Plan/Verify/Monitor). systemd socket-activated units
//! land with packaging; unit generation text lives here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use minisign_verify::{PublicKey, Signature};

use ibexwall_proto::names;
use ibexwall_proto::{Manifest, Op, PluginOrigin};

pub struct PluginEntry {
    pub manifest: Manifest,
    pub binary: PathBuf,
    pub socket: PathBuf,
}

pub struct Supervisor {
    plugins: BTreeMap<String, PluginEntry>,
    processes: Mutex<BTreeMap<String, Child>>,
    dev_key: Option<PathBuf>,
    /// Root the sandbox was discovered under; passed to plugin
    /// processes so they bind their sockets in the same tree.
    root: PathBuf,
}

impl Supervisor {
    /// Discovers plugins under the install and local directories.
    /// Official/community plugins must carry a minisign signature
    /// (`plugin.toml.sig`) verified against the embedded key or the
    /// `--dev-key` anchor; local plugins require the dev key anchor to
    /// be present (explicit admin trust in dev).
    pub async fn discover(root: &Path, dev_key: Option<PathBuf>) -> Result<Self> {
        let mut plugins = BTreeMap::new();
        for dir in [
            names::path_under(root, names::PLUGIN_INSTALL_DIR),
            names::path_under(root, names::LOCAL_PLUGIN_DIR),
        ] {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path().join("plugin.toml");
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let manifest: Manifest =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                manifest
                    .validate()
                    .with_context(|| format!("validating {}", path.display()))?;
                if !plugins.contains_key(&manifest.id) {
                    let socket = names::path_under(root, names::RUNTIME_DIR)
                        .join("plugins")
                        .join(format!("{}.sock", manifest.id));
                    plugins.insert(
                        manifest.id.clone(),
                        PluginEntry {
                            manifest,
                            binary: entry.path().join("binary"),
                            socket,
                        },
                    );
                }
            }
        }
        Ok(Self {
            plugins,
            processes: Mutex::new(BTreeMap::new()),
            dev_key,
            root: root.to_path_buf(),
        })
    }

    pub fn plugins(&self) -> impl Iterator<Item = &PluginEntry> {
        self.plugins.values()
    }

    pub fn manifest(&self, id: &str) -> Result<&Manifest> {
        self.plugins
            .get(id)
            .map(|entry| &entry.manifest)
            .ok_or_else(|| anyhow::anyhow!("plugin `{id}` not found"))
    }

    /// Verifies the plugin signature against the trust anchor.
    pub fn verify_signature(&self, id: &str) -> Result<()> {
        let entry = self
            .plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("plugin `{id}` not found"))?;
        let dir = entry
            .binary
            .parent()
            .ok_or_else(|| anyhow::anyhow!("plugin dir"))?;
        let manifest_path = dir.join("plugin.toml");
        let sig_path = dir.join("plugin.toml.sig");

        let anchor = match (&self.dev_key, entry.manifest.origin) {
            // Dev builds accept every origin against the dev key.
            (Some(path), _) => std::fs::read_to_string(path)
                .with_context(|| format!("reading dev key {}", path.display()))?,
            (None, PluginOrigin::Local) => {
                bail!("local plugin `{id}` requires explicit trust: start ibexwalld with --dev-key")
            }
            (None, PluginOrigin::Official | PluginOrigin::Community) => {
                // The official release key is embedded with packaging
                // (F10); until then non-dev builds refuse everything.
                bail!("no embedded release key yet; use --dev-key in dev builds")
            }
        };
        let public_key =
            PublicKey::decode(&anchor).map_err(|e| anyhow::anyhow!("bad public key: {e:?}"))?;
        let signature_text = std::fs::read_to_string(&sig_path)
            .with_context(|| format!("reading {}", sig_path.display()))?;
        let signature = Signature::decode(&signature_text)
            .map_err(|e| anyhow::anyhow!("bad signature for {id}: {e:?}"))?;
        let manifest_bytes = std::fs::read(&manifest_path)?;
        match public_key.verify(&manifest_bytes, &signature, false) {
            Ok(_) => Ok(()),
            Err(e) => bail!("signature verification failed for `{id}`: {e:?}"),
        }
    }

    /// Ensures the plugin process is listening, spawning it directly
    /// (dev/F1-VM mode; systemd activation arrives with packaging).
    pub async fn ensure_running(&self, id: &str) -> Result<()> {
        // Every use verifies the manifest signature (spec 5.1).
        self.verify_signature(id)?;
        if let Some(entry) = self.plugins.get(id)
            && ibexwall_varlink::Client::connect(&entry.socket)
                .await
                .is_ok()
        {
            return Ok(());
        }
        let entry = self
            .plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("plugin `{id}` not found"))?;
        let bin = resolve_binary(&entry.binary, &entry.manifest)?;
        let child = Command::new(&bin)
            .env(names::ENV_ROOT, &self.root)
            .stdin(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {}", bin.display()))?;
        self.processes.lock().unwrap().insert(id.into(), child);

        // Wait for the socket to accept connections.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(entry) = self.plugins.get(id)
                && ibexwall_varlink::Client::connect(&entry.socket)
                    .await
                    .is_ok()
            {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                bail!("plugin `{id}` did not come up within 10s");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Calls `com.ibexwall.Plugin.Plan` with the caller's patch.
    pub async fn plan(&self, id: &str, patch: serde_json::Value) -> Result<Vec<Op>> {
        self.ensure_running(id).await?;
        let entry = self
            .plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("plugin `{id}` not found"))?;
        let reply = ibexwall_varlink::call(
            &entry.socket,
            "com.ibexwall.Plugin.Plan",
            serde_json::json!({ "config": patch, "previous": null }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("plugin Plan call failed: {e}"))?;
        let ops = reply.get("ops").cloned().unwrap_or_default();
        Ok(serde_json::from_value(ops)?)
    }

    /// Calls `com.ibexwall.Plugin.Check`.
    pub async fn check(
        &self,
        id: &str,
        config: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        self.ensure_running(id).await?;
        let entry = self
            .plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("plugin `{id}` not found"))?;
        let reply = ibexwall_varlink::call(
            &entry.socket,
            "com.ibexwall.Plugin.Check",
            serde_json::json!({ "config": config }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("plugin Check call failed: {e}"))?;
        Ok(reply
            .get("findings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Calls `com.ibexwall.Plugin.Verify` after applying a transaction.
    pub async fn verify(&self, id: &str, transaction_id: &str, ops: &[Op]) -> Result<bool> {
        self.ensure_running(id).await?;
        let entry = self
            .plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("plugin `{id}` not found"))?;
        let reply = ibexwall_varlink::call(
            &entry.socket,
            "com.ibexwall.Plugin.Verify",
            serde_json::json!({ "transaction_id": transaction_id, "ops": ops }),
        )
        .await
        .map_err(|e| anyhow::anyhow!("plugin Verify call failed: {e}"))?;
        Ok(reply.get("ok").and_then(|v| v.as_bool()).unwrap_or(false))
    }
}

fn resolve_binary(_marker: &Path, manifest: &Manifest) -> Result<PathBuf> {
    // The binary marker file names the directory; the real binary sits
    // next to plugin.toml under its canonical name.
    let dir = _marker
        .parent()
        .ok_or_else(|| anyhow::anyhow!("plugin dir"))?;
    let binary = dir.join(format!(
        "{}{}",
        names::PLUGIN_BIN_PREFIX,
        manifest.id.rsplit('.').next().unwrap_or_default()
    ));
    if binary.is_file() {
        return Ok(binary);
    }
    // Dev layout: workspace target/debug on PATH-less hosts.
    let dev = std::env::var("IBEXWALL_DEV_BIN_DIR").ok();
    if let Some(dir) = dev {
        let candidate = PathBuf::from(dir).join(
            binary
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("binary name"))?,
        );
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Ok(binary)
}

/// Generates the plugin unit text from the manifest (§4.2 sandbox
/// rules). Written under the plugin directory by packaging; tested as
/// text in F1.
pub fn generate_unit(manifest: &Manifest) -> String {
    let caps = manifest.sandbox.capabilities.join(" ");
    let read_only = manifest
        .sandbox
        .read_paths
        .iter()
        .map(|p| format!("ReadOnlyPaths={p}"))
        .collect::<Vec<_>>()
        .join("\n");
    let bin = format!(
        "{}{}",
        names::PLUGIN_BIN_PREFIX,
        manifest.id.rsplit('.').next().unwrap_or_default()
    );
    let dynamic = if matches!(manifest.sandbox.user, ibexwall_proto::SandboxUser::Dynamic) {
        "yes"
    } else {
        "no"
    };
    let mut unit = String::new();
    unit.push_str("# Generated by ibexwalld from plugin.toml; do not edit.\n");
    unit.push_str("[Unit]\n");
    unit.push_str(&format!("Description=IbexWall plugin {}\n", manifest.id));
    unit.push_str("\n[Service]\n");
    unit.push_str("Type=notify\n");
    unit.push_str(&format!("ExecStart={bin}\n"));
    unit.push_str(&format!("DynamicUser={dynamic}\n"));
    unit.push_str("NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n");
    if !caps.is_empty() {
        unit.push_str(&format!("CapabilityBoundingSet={caps}\n"));
    }
    if !read_only.is_empty() {
        unit.push_str(&read_only);
        unit.push('\n');
    }
    unit.push_str("RestrictAddressFamilies=AF_UNIX\n");
    unit.push_str("SystemCallFilter=@system-service\n");
    unit
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        for child in self.processes.get_mut().unwrap().values_mut() {
            let _ = child.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;

    #[test]
    fn generated_units_hardening_matches_the_spec() {
        let manifest: Manifest = toml::from_str(
            r#"
id = "dev.echo"
version = "1.0.0"
api = 1
category = "dev"
kinds = ["check", "control"]
origin = "local"
license = "GPL-3.0-or-later"
binary = "ibexwall-plugin-echo"
default_enabled = true

[name]
en = "Echo"

[privileges]
write_paths = ["/etc/sysctl.d"]

[sandbox]
user = "dynamic"
capabilities = []
read_paths = ["/etc/chrony"]
network = false

[risk]
reversible = "immediate"
"#,
        )
        .unwrap();
        let unit = generate_unit(&manifest);
        assert!(unit.contains("DynamicUser=yes"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ReadOnlyPaths=/etc/chrony"));
        assert!(unit.contains("ExecStart=ibexwall-plugin-echo"));
    }

    #[test]
    fn engine_preview_targets_carry_paths() {
        let ops = vec![Op::FileWrite {
            path: "/etc/sysctl.d/90-ibexwall-test.conf".into(),
            content: "x=1".into(),
            mode: "0644".into(),
            owner: "root".into(),
            group: "root".into(),
        }];
        let preview = Engine::new().preview(&ops);
        assert_eq!(preview[0].op, "file.write");
        assert_eq!(preview[0].target, "/etc/sysctl.d/90-ibexwall-test.conf");
        assert_eq!(preview[0].diff.as_deref(), Some("+x=1"));
    }
}
