// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! WebKitGTK's DMABUF renderer draws nothing on the virtual graphics adapter
//! of VMware and VirtualBox guests in an X11 session: the window stays white
//! (<https://v2.tauri.app/develop/debug/linux-graphics/> describes the symptom).
//! Only there is it turned off; anyone else affected can set the variable.

use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

const VARIABLE: &str = "WEBKIT_DISABLE_DMABUF_RENDERER";

fn needed(drm: &Path, wayland: bool, already_set: bool) -> bool {
    !already_set
        && !wayland
        && std::fs::read_dir(drm)
            .into_iter()
            .flatten()
            .flatten()
            .any(|card| {
                std::fs::read_link(card.path().join("device/driver"))
                    .is_ok_and(|driver| driver.file_name().is_some_and(|name| name == "vmwgfx"))
            })
}

/// Starts the app again with the variable set, before any window exists.
/// Setting it in this process would need `unsafe`.
pub(crate) fn restart_if_needed() {
    if !needed(
        Path::new("/sys/class/drm"),
        std::env::var_os("WAYLAND_DISPLAY").is_some(),
        std::env::var_os(VARIABLE).is_some(),
    ) {
        return;
    }
    // `exec` returns only when it failed; the app then runs as it is.
    let error = match std::env::current_exe() {
        Ok(app) => Command::new(app)
            .args(std::env::args_os().skip(1))
            .env(VARIABLE, "1")
            .exec(),
        Err(error) => error,
    };
    eprintln!("ibexwall-desktop: cannot restart without the DMABUF renderer: {error}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_virtual_adapter_under_x11_needs_it() {
        let root = std::env::temp_dir().join(format!("ibexwall-drm-{}", std::process::id()));
        let card = |drm: &str, driver: &str| {
            let dir = root.join(drm).join("card0/device");
            std::fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink(
                format!("/sys/bus/pci/drivers/{driver}"),
                dir.join("driver"),
            )
            .unwrap();
            root.join(drm)
        };
        let virtual_adapter = card("vm", "vmwgfx");
        let other = card("metal", "amdgpu");
        assert!(needed(&virtual_adapter, false, false));
        assert!(!needed(&virtual_adapter, true, false), "Wayland draws");
        assert!(
            !needed(&virtual_adapter, false, true),
            "the person decided, no loop"
        );
        assert!(!needed(&other, false, false));
        assert!(!needed(&root.join("missing"), false, false));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
