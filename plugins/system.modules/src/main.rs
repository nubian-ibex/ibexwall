// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.modules`: groups of kernel modules that almost nobody needs and
//! that an unprivileged program can still make the kernel load (a network
//! protocol opened on a socket, a file system mounted from a stick). The
//! plan writes one owned drop-in in `/etc/modprobe.d` that tells `modprobe`
//! to run a command that fails instead of loading them. Modules already
//! loaded stay until the next boot, and the plan says so.
//!
//! The groups are fixed here: the plugin never takes a module name from
//! the caller.

use std::collections::BTreeSet;

use ibexwall_proto::{CheckReport, Op};
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde::Deserialize;
use serde_json::Value;

pub const DROP_IN: &str = "/etc/modprobe.d/70-ibexwall-modules.conf";

pub struct Group {
    pub id: &'static str,
    pub modules: &'static [&'static str],
    /// What `modprobe` runs instead of loading the module.
    pub command: &'static str,
}

/// The module lists follow the Linux Hardening Guide, section 2.5.2
/// (<https://madaidans-insecurities.github.io/guides/linux-hardening.html>).
pub const GROUPS: &[Group] = &[
    Group {
        id: "net-protocols",
        modules: &[
            "dccp",
            "sctp",
            "rds",
            "tipc",
            "n-hdlc",
            "ax25",
            "netrom",
            "x25",
            "rose",
            "decnet",
            "econet",
            "af_802154",
            "ipx",
            "appletalk",
            "psnap",
            "p8023",
            "p8022",
            "can",
            "atm",
        ],
        command: "/bin/false",
    },
    Group {
        id: "rare-filesystems",
        modules: &["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"],
        command: "/bin/false",
    },
    Group {
        id: "network-filesystems",
        modules: &["cifs", "nfs", "nfsv3", "nfsv4", "ksmbd", "gfs2"],
        command: "/bin/true",
    },
    Group {
        id: "bluetooth",
        modules: &["bluetooth", "btusb"],
        command: "/bin/false",
    },
    Group {
        id: "vivid",
        modules: &["vivid"],
        command: "/bin/false",
    },
];

fn group(id: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.id == id)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Groups to keep from loading.
    pub block: Vec<String>,
    /// Groups to allow again.
    pub unblock: Vec<String>,
}

struct Modules;

pub fn run() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Modules)) {
        eprintln!("ibexwall-plugin-modules: {err}");
        std::process::exit(1);
    }
}

impl Plugin for Modules {
    fn id(&self) -> &'static str {
        "system.modules"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        // What is blocked is judged by the hardening catalog; nothing here
        // is a failure.
        Ok(CheckReport::default())
    }

    async fn plan(&self, config: Value) -> Result<Vec<Op>, PluginError> {
        let config: Config = serde_json::from_value(config)
            .map_err(|e| PluginError::invalid("config", e.to_string()))?;
        plan(&Sandbox::system(), &config)
    }
}

/// The groups this plugin's own drop-in already blocks.
pub fn blocked_groups(sandbox: &Sandbox) -> BTreeSet<String> {
    sandbox
        .read(DROP_IN)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("# group: "))
        .map(str::trim)
        .filter(|id| group(id).is_some())
        .map(str::to_string)
        .collect()
}

pub fn plan(sandbox: &Sandbox, config: &Config) -> Result<Vec<Op>, PluginError> {
    for id in config.block.iter().chain(&config.unblock) {
        if group(id).is_none() {
            let known: Vec<&str> = GROUPS.iter().map(|g| g.id).collect();
            return Err(PluginError::invalid(
                "block",
                format!("`{id}` is not a group; the groups are {}", known.join(", ")),
            ));
        }
    }
    if config.block.is_empty() && config.unblock.is_empty() {
        return Err(PluginError::invalid(
            "block",
            "name the groups to block or unblock",
        ));
    }
    let mut now = blocked_groups(sandbox);
    for id in &config.block {
        now.insert(id.clone());
    }
    for id in &config.unblock {
        now.remove(id);
    }
    if now.is_empty() {
        // Nothing left to keep out: the drop-in goes away.
        if !sandbox.exists(DROP_IN) {
            return Err(PluginError::invalid("unblock", "nothing is blocked"));
        }
        return Ok(vec![Op::FileRemove {
            path: DROP_IN.into(),
        }]);
    }
    let mut text = String::from("# Managed by IbexWall (system.modules); edit it from IbexWall.\n");
    for g in GROUPS.iter().filter(|g| now.contains(g.id)) {
        text.push_str(&format!("# group: {}\n", g.id));
        for module in g.modules {
            text.push_str(&format!("install {module} {}\n", g.command));
        }
    }
    Ok(vec![Op::FileWrite {
        path: DROP_IN.into(),
        content: text,
        mode: "0644".into(),
        owner: "root".into(),
        group: "root".into(),
    }])
}

#[cfg(test)]
mod tests;
