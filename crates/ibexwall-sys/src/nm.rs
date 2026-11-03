// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! What NetworkManager says about the networks this computer is on, read
//! over D-Bus (read-only). Names come from the network and are untrusted.

use std::collections::HashMap;

use anyhow::Result;
use zbus::{OwnedObjectPath, OwnedVariant};

const NM: &str = "org.freedesktop.NetworkManager";

/// One active connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveNetwork {
    /// The connection's name (for Wi-Fi, usually the network name).
    pub name: String,
    /// NetworkManager's connection type (`802-3-ethernet`,
    /// `802-11-wireless`, `vpn`, ...).
    pub nm_type: String,
    /// Whether it carries wireless security settings (a password or an
    /// enterprise login).
    pub has_security: bool,
}

/// The active connections, or an empty list when NetworkManager is not
/// running or does not answer in time: no manager is not an error.
pub async fn active_networks() -> Vec<ActiveNetwork> {
    match tokio::time::timeout(std::time::Duration::from_secs(3), read()).await {
        Ok(Ok(networks)) => networks,
        _ => Vec::new(),
    }
}

async fn read() -> Result<Vec<ActiveNetwork>> {
    let connection = zbus::Connection::system().await?;
    let manager = zbus::Proxy::new(
        &connection,
        NM,
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await?;
    let active: Vec<OwnedObjectPath> = manager.get_property("ActiveConnections").await?;
    let mut networks = Vec::new();
    for path in active {
        let connection_proxy = zbus::Proxy::new(
            &connection,
            NM,
            path.as_str(),
            "org.freedesktop.NetworkManager.Connection.Active",
        )
        .await?;
        let name: String = connection_proxy.get_property("Id").await?;
        let nm_type: String = connection_proxy.get_property("Type").await?;
        let settings_path: OwnedObjectPath = connection_proxy.get_property("Connection").await?;
        let settings = zbus::Proxy::new(
            &connection,
            NM,
            settings_path.as_str(),
            "org.freedesktop.NetworkManager.Settings.Connection",
        )
        .await?;
        let all: HashMap<String, HashMap<String, OwnedVariant>> =
            settings.call("GetSettings", &()).await?;
        networks.push(ActiveNetwork {
            name,
            nm_type,
            has_security: all.contains_key("802-11-wireless-security"),
        });
    }
    Ok(networks)
}
