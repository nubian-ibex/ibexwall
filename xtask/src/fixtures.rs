// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `vm-test --phase fixtures`: copies the files the read-only check
//! plugins look at from a real distro VM into `tests/fixtures/<distro>/`,
//! so plugin tests run against what each distro really exposes.
//!
//! The VM is ours and short-lived, but its output is still treated as
//! untrusted: it travels as one base64 tarball and is extracted locally by
//! GNU tar, which refuses absolute and `..` paths by default.

use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine as _;

use super::vm::{Vm, run_capture};

/// Runs inside the VM as root and prints a base64 tarball of the files.
const COLLECT: &str = r#"
set -u
D=$(mktemp -d)
cp_file() { [ -e "$1" ] && mkdir -p "$D$(dirname "$1")" && cat "$1" > "$D$1" 2>/dev/null; return 0; }
for f in /proc/self/mounts /proc/swaps /proc/sys/fs/suid_dumpable \
         /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 \
         /sys/kernel/security/lockdown /sys/fs/selinux/enforce \
         /sys/module/apparmor/parameters/enabled /etc/sudoers /etc/os-release \
         /etc/ufw/ufw.conf; do
  cp_file "$f"
done
for f in /etc/sudoers.d/*; do cp_file "$f"; done
if [ -d /sys/firmware/efi ]; then
  mkdir -p "$D/sys/firmware/efi"
  for f in /sys/firmware/efi/efivars/SecureBoot-*; do cp_file "$f"; done
fi
[ -e /sys/class/tpm/tpm0 ] && mkdir -p "$D/sys/class/tpm/tpm0"
mkdir -p "$D/run/systemd/units"
for f in /run/systemd/units/invocation:*; do
  [ -e "$f" ] || [ -L "$f" ] && : > "$D/run/systemd/units/$(basename "$f")"
done
for dm in /sys/block/dm-*; do
  [ -d "$dm" ] || continue
  n=$(basename "$dm")
  cp_file "$dm/dm/name"; cp_file "$dm/dm/uuid"
  mkdir -p "$D/sys/block/$n/slaves"
  for s in "$dm"/slaves/*; do [ -e "$s" ] && : > "$D/sys/block/$n/slaves/$(basename "$s")"; done
done
tar -C "$D" -czf - . | base64 -w0
rm -rf "$D"
"#;

pub fn run(vm: &Vm, workspace: &Path, distro: &str) -> Result<()> {
    let encoded = vm
        .ssh_stdin(COLLECT)
        .context("collecting fixtures inside the VM")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("decoding the fixture tarball")?;

    let dir = workspace.join("tests/fixtures").join(distro);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let tarball = dir.join("collected.tgz");
    std::fs::write(&tarball, &bytes)?;
    run_capture(
        "tar",
        [
            "-xzf",
            &tarball.to_string_lossy(),
            "--no-same-owner",
            "--no-same-permissions",
            "-C",
            &dir.to_string_lossy(),
        ],
        None,
        "extracting fixtures",
    )?;
    std::fs::remove_file(&tarball)?;

    if !dir.join("proc/self/mounts").is_file() {
        bail!("fixture collection produced no /proc/self/mounts");
    }
    println!("PASS: fixtures for {distro} written to {}", dir.display());
    Ok(())
}
