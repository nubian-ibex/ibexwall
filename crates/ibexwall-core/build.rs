// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Embeds the release public key, when the build is given one.
//!
//! `IBEXWALL_RELEASE_PUBKEY` is the path of a minisign public key file. A
//! package build sets it so the daemon can verify the manifests of official
//! and community plugins without `--dev-key`; a development build leaves it
//! unset and embeds nothing, so such a build trusts no plugin by itself.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=IBEXWALL_RELEASE_PUBKEY");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("release.pub");
    let key = match std::env::var("IBEXWALL_RELEASE_PUBKEY") {
        Ok(path) if !path.is_empty() => {
            println!("cargo:rerun-if-changed={path}");
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("IBEXWALL_RELEASE_PUBKEY={path}: {e}"))
        }
        _ => String::new(),
    };
    std::fs::write(out, key).expect("writing release.pub");
}
