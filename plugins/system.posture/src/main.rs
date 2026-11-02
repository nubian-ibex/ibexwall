// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `system.posture`: read-only checks of how well the computer is
//! protected. Everything comes from `/sys`, `/proc` and `/etc`; the plugin
//! runs no commands. Checks that need PackageKit or fwupd are reported as
//! "not assessed" until `system.updates` and `system.firmware` ship (F7).

use ibexwall_proto::CheckReport;
use ibexwall_sdk::{Plugin, PluginError, Sandbox};
use serde_json::Value;

mod blockdev;
mod checks;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(ibexwall_sdk::serve(Posture)) {
        eprintln!("ibexwall-plugin-posture: {err}");
        std::process::exit(1);
    }
}

struct Posture;

impl Plugin for Posture {
    fn id(&self) -> &'static str {
        "system.posture"
    }

    async fn check(&self, _config: Value) -> Result<CheckReport, PluginError> {
        Ok(checks::evaluate(&Sandbox::system(), "1970-01-01T00:00:00Z"))
    }
}
