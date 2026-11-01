// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Operation executors. Implemented in F1: file.write/remove,
//! systemd.unit, sysctl.set, exec (allowlisted argv, no shell) and
//! nft.fragment via the nftables JSON API (`nft -j`), with `nft -c`
//! prechecks. Adapter ops validate but execute as `NotImplemented`
//! until their phases (F3-F5).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use ibexwall_proto::Op;

use super::SysBundle;
use super::ops::OpError;

pub fn execute(op: &Op, sys: &SysBundle) -> Result<()> {
    match op {
        Op::FileWrite {
            path,
            content,
            mode,
            owner,
            group,
        } => {
            let mode = parse_mode(mode).ok_or_else(|| OpError::Invalid {
                field: "mode",
                reason: format!("`{mode}` is not octal"),
            })?;
            let uid = resolve_user(owner)?;
            let gid = resolve_group(group)?;
            sys.fs
                .write_atomic(Path::new(path), content.as_bytes(), mode, Some((uid, gid)))
                .map_err(anyhow::Error::from)
                .with_context(|| format!("writing {path}"))?;
            Ok(())
        }
        Op::FileRemove { path } => {
            sys.fs
                .remove(Path::new(path))
                .map_err(anyhow::Error::from)?;
            Ok(())
        }
        Op::SystemdUnit { unit, action, now } => {
            let now = now.unwrap_or(true);
            sys.systemd.apply(unit, *action, now)?;
            Ok(())
        }
        Op::SysctlSet { key, value } => {
            sys.sysctl.set(key, value)?;
            Ok(())
        }
        Op::Exec { path, args } => {
            if !sys.allow_system_executors {
                return Err(OpError::SandboxBlocked.into());
            }
            let status = Command::new(path)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .status()
                .with_context(|| format!("spawning {path}"))?;
            if !status.success() {
                bail!("exec {path} failed with {status}");
            }
            Ok(())
        }
        Op::NftFragment { fragment } => {
            if !sys.allow_system_executors {
                return Err(OpError::SandboxBlocked.into());
            }
            apply_nft_fragment(fragment)
        }
        Op::FirewallAdapter { .. } => {
            Err(not_implemented("firewall.adapter", "adapter lands in F5"))
        }
        Op::DnsBackend { .. } => Err(not_implemented("dns.backend", "adapter lands in F3")),
        Op::FlatpakOverride { .. } => Err(not_implemented("flatpak.override", "lands in F4")),
        Op::SnapInterface { .. } => Err(not_implemented("snap.interface", "lands in F4")),
        Op::BrowserPolicy { .. } => Err(not_implemented("browser.policy", "lands in F3")),
        Op::NmSetting { .. } => Err(not_implemented("nm.setting", "lands in F3")),
        Op::PackageInstall { .. } => Err(not_implemented(
            "package.install",
            "PackageKit flow lands in F7",
        )),
    }
}

fn not_implemented(op: &'static str, detail: &'static str) -> anyhow::Error {
    OpError::NotImplemented { op, detail }.into()
}

fn parse_mode(mode: &str) -> Option<u32> {
    u32::from_str_radix(mode, 8).ok().filter(|m| *m <= 0o7777)
}

fn resolve_user(owner: &str) -> Result<u32> {
    match owner {
        "root" => Ok(0),
        numeric => Ok(numeric.parse::<u32>().map_err(|_| OpError::Invalid {
            field: "owner",
            reason: format!("`{owner}`: only `root` or a numeric uid in F1"),
        })?),
    }
}

fn resolve_group(group: &str) -> Result<u32> {
    match group {
        "root" => Ok(0),
        numeric => Ok(numeric.parse::<u32>().map_err(|_| OpError::Invalid {
            field: "group",
            reason: format!("`{group}`: only `root` or a numeric gid in F1"),
        })?),
    }
}

/// Applies a fragment to `table inet ibexwall` atomically through the
/// nftables JSON API: `nft -c -j` precheck, then `nft -j -f -`.
fn apply_nft_fragment(fragment: &serde_json::Value) -> Result<()> {
    let batch = serde_json::json!({
        "nftables": [
            { "table": { "family": "inet", "name": ibexwall_proto::names::NFT_TABLE } },
            fragment.clone(),
        ]
    });
    let payload = serde_json::to_vec(&batch)?;

    for check in [true, false] {
        let mut command = Command::new("nft");
        command.arg("-j");
        if check {
            command.arg("-c");
        }
        command.arg("-f").arg("-");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().context("spawning nft")?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&payload)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "nft {} failed: {}",
                if check { "check" } else { "apply" },
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
    }
    Ok(())
}
