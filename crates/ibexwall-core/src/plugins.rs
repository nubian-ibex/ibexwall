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

/// The public key packages sign official and community manifests with,
/// embedded by `build.rs`; empty in a development build.
const EMBEDDED_RELEASE_KEY: &str = include_str!(concat!(env!("OUT_DIR"), "/release.pub"));

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

        let anchor = trust_anchor(
            self.dev_key.as_deref(),
            entry.manifest.origin,
            EMBEDDED_RELEASE_KEY,
            id,
        )?;
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
        // Installed with its units, a plugin is started by systemd on the
        // first connection. If the socket is not there, the unit is not
        // active: say so rather than run the plugin outside its sandbox.
        if self.root == Path::new("/") && units_installed(&entry.manifest) {
            bail!(
                "plugin `{id}` is installed with its systemd units but its socket does not answer; \
                 is ibexwall-plugin-{}.socket active?",
                id.rsplit('.').next().unwrap_or_default()
            );
        }
        let bin = resolve_binary(&entry.binary, &entry.manifest)?;
        let child = Command::new(&bin)
            .env(names::ENV_ROOT, &self.root)
            .stdin(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {}", bin.display()))?;
        self.processes
            .lock()
            .expect("lock poisoned")
            .insert(id.into(), child);

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
    ) -> Result<ibexwall_proto::CheckReport> {
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
        let mut report: ibexwall_proto::CheckReport = serde_json::from_value(reply)
            .context("plugin Check reply does not match CheckReport")?;
        // A plugin may only report on itself.
        // Plugins have no trusted clock; the core stamps detection time
        // (a plugin sends the epoch as "unknown").
        let now = ibexwall_sys::Clock::rfc3339_now(&ibexwall_sys::RealClock);
        for finding in &mut report.findings {
            finding.plugin = id.to_string();
            if finding.detected_at.starts_with("1970-") {
                finding.detected_at = now.clone();
            }
        }
        Ok(report)
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

/// The systemd units of one plugin: a socket unit that listens on the
/// plugin's socket and a service unit that runs it in its own sandbox. The
/// socket unit starts the service when the core first connects, so the core
/// needs no right over systemd (a compromised core cannot start a unit of
/// its own choosing and leave its sandbox).
pub struct PluginUnits {
    /// `ibexwall-plugin-<name>`, without the `.service` or `.socket` suffix.
    pub name: String,
    pub service: String,
    pub socket: String,
}

/// True when packaging installed this plugin's socket unit.
fn units_installed(manifest: &Manifest) -> bool {
    let name = generate_units(manifest).name;
    [
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/etc/systemd/system",
    ]
    .iter()
    .any(|dir| Path::new(dir).join(format!("{name}.socket")).exists())
}

/// The public key a plugin's manifest signature is checked against: the dev
/// key when one was given (development), the key embedded by the package
/// build for official and community plugins, and nothing for a local plugin
/// unless the person trusts it explicitly with `--dev-key`.
fn trust_anchor(
    dev_key: Option<&Path>,
    origin: PluginOrigin,
    embedded: &str,
    id: &str,
) -> Result<String> {
    match (dev_key, origin) {
        // Dev builds accept every origin against the dev key.
        (Some(path), _) => std::fs::read_to_string(path)
            .with_context(|| format!("reading dev key {}", path.display())),
        (None, PluginOrigin::Local) => {
            bail!("local plugin `{id}` requires explicit trust: start ibexwalld with --dev-key")
        }
        (None, PluginOrigin::Official | PluginOrigin::Community) => {
            if embedded.trim().is_empty() {
                bail!("this build has no release key; start with --dev-key in development")
            }
            Ok(embedded.to_string())
        }
    }
}

/// Generates both units from the manifest (spec 4.2 sandbox rules).
/// Packaging writes them under `/usr/lib/systemd/system`.
pub fn generate_units(manifest: &Manifest) -> PluginUnits {
    let name = format!(
        "{}{}",
        names::PLUGIN_BIN_PREFIX,
        manifest.id.rsplit('.').next().unwrap_or_default()
    );
    let id = &manifest.id;
    let caps = manifest.sandbox.capabilities.join(" ");
    let dynamic = matches!(manifest.sandbox.user, ibexwall_proto::SandboxUser::Dynamic);
    // The home folders are read by the plugins that watch them (persistence,
    // integrity, antivirus); everything else does not see them at all.
    let reads_home = manifest
        .sandbox
        .read_paths
        .iter()
        .any(|p| p.starts_with("/home") || p.starts_with("/root"));
    let mut service = String::new();
    service.push_str("# Generated from plugin.toml by `cargo xtask plugin-units`; do not edit.\n");
    service.push_str(&format!(
        "[Unit]\nDescription=IbexWall plugin {id}\nRequires={name}.socket\nAfter={name}.socket\n"
    ));
    service.push_str("\n[Service]\nType=simple\n");
    service.push_str(&format!(
        "ExecStart={}/{id}/{name}\n",
        names::PLUGIN_INSTALL_DIR
    ));
    service.push_str(&format!(
        "DynamicUser={}\n",
        if dynamic { "yes" } else { "no" }
    ));
    // The profile of the plugins where the machine has loaded it; the dash
    // ignores a machine that does not use AppArmor.
    service
        .push_str("NoNewPrivileges=yes\nAppArmorProfile=-ibexwall-plugins\nProtectSystem=strict\n");
    service.push_str(if reads_home {
        "ProtectHome=read-only\n"
    } else {
        "ProtectHome=yes\n"
    });
    service.push_str(
        "PrivateTmp=yes\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelLogs=yes\nProtectControlGroups=yes\nProtectClock=yes\nProtectHostname=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nRestrictSUIDSGID=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nSystemCallArchitectures=native\nUMask=0077\n",
    );
    // An empty set drops every capability; a dynamic user keeps the ones the
    // manifest asks for only through the ambient set.
    service.push_str(&format!("CapabilityBoundingSet={caps}\n"));
    if !caps.is_empty() {
        service.push_str(&format!("AmbientCapabilities={caps}\n"));
    }
    // /proc and /sys are read-only already (and a bind mount over a /proc
    // path cannot be set up for an unprivileged user).
    for path in manifest
        .sandbox
        .read_paths
        .iter()
        .filter(|p| !p.starts_with("/proc") && !p.starts_with("/sys"))
    {
        // A leading `-` lets a path that this machine lacks be skipped.
        service.push_str(&format!("ReadOnlyPaths=-{path}\n"));
    }
    for path in &manifest.sandbox.state_paths {
        service.push_str(&format!("ReadWritePaths=-{path}\n"));
    }
    service.push_str(if manifest.sandbox.network {
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n"
    } else {
        "RestrictAddressFamilies=AF_UNIX\n"
    });
    service.push_str("SystemCallFilter=@system-service\n");

    let socket = format!(
        "# Generated from plugin.toml by `cargo xtask plugin-units`; do not edit.\n[Unit]\nDescription=IbexWall plugin {id} socket\n\n[Socket]\nListenStream=/run/ibexwall/plugins/{id}.sock\nSocketMode=0600\nDirectoryMode=0755\n\n[Install]\nWantedBy=sockets.target\n"
    );
    PluginUnits {
        name,
        service,
        socket,
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        for child in self
            .processes
            .get_mut()
            .expect("lock poisoned")
            .values_mut()
        {
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
        let units = generate_units(&manifest);
        let unit = &units.service;
        assert_eq!(units.name, "ibexwall-plugin-echo");
        assert!(unit.contains("DynamicUser=yes"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("ProtectHome=yes"));
        assert!(unit.contains("CapabilityBoundingSet=\n"));
        assert!(!unit.contains("AmbientCapabilities"));
        assert!(unit.contains("ReadOnlyPaths=-/etc/chrony"));
        assert!(unit.contains("RestrictAddressFamilies=AF_UNIX\n"));
        assert!(unit.contains("ExecStart=/usr/lib/ibexwall/plugins/dev.echo/ibexwall-plugin-echo"));
        assert!(unit.contains("Requires=ibexwall-plugin-echo.socket"));
        assert!(
            units
                .socket
                .contains("ListenStream=/run/ibexwall/plugins/dev.echo.sock")
        );
        assert!(units.socket.contains("SocketMode=0600"));
    }

    #[test]
    fn the_trust_anchor_is_the_dev_key_the_embedded_release_key_or_nothing() {
        let dir = std::env::temp_dir().join(format!("ibx-anchor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dev = dir.join("dev.pub");
        std::fs::write(&dev, "DEV KEY").unwrap();
        // A dev key wins for every origin.
        for origin in [
            PluginOrigin::Official,
            PluginOrigin::Community,
            PluginOrigin::Local,
        ] {
            assert_eq!(
                trust_anchor(Some(&dev), origin, "RELEASE", "x").unwrap(),
                "DEV KEY"
            );
        }
        // Without one, a package build's embedded key covers official and community plugins.
        assert_eq!(
            trust_anchor(None, PluginOrigin::Official, "RELEASE", "x").unwrap(),
            "RELEASE"
        );
        assert_eq!(
            trust_anchor(None, PluginOrigin::Community, "RELEASE\n", "x").unwrap(),
            "RELEASE\n"
        );
        // A local plugin is never trusted by the release key.
        assert!(trust_anchor(None, PluginOrigin::Local, "RELEASE", "x").is_err());
        // A build with no key trusts nothing by itself.
        for origin in [PluginOrigin::Official, PluginOrigin::Community] {
            let error = trust_anchor(None, origin, " \n", "x")
                .unwrap_err()
                .to_string();
            assert!(error.contains("no release key"), "{error}");
        }
        std::fs::remove_dir_all(dir).unwrap();
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
