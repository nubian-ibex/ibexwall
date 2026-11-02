// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Is a block device backed by LUKS? Walks device-mapper (`/sys/block/dm-*`)
//! and its `slaves/` so LVM on LUKS is recognized.

use ibexwall_sdk::Sandbox;

/// Answer for "is this device encrypted?". `Unknown` means we could not
/// map the device; the caller must not treat it as a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    Encrypted,
    Plain,
    Unknown,
}

/// Maps a `/dev/...` source (as shown in `/proc/mounts` or `/proc/swaps`).
pub fn device_encryption(sandbox: &Sandbox, source: &str) -> Encryption {
    let Some(name) = source.strip_prefix("/dev/") else {
        return Encryption::Unknown;
    };
    if name == "root" {
        // The kernel's alias for "whatever the bootloader gave us".
        return Encryption::Unknown;
    }
    if let Some(mapper) = name.strip_prefix("mapper/") {
        return match dm_for_name(sandbox, mapper) {
            Some(dm) => dm_encryption(sandbox, &dm, 0),
            None => Encryption::Unknown,
        };
    }
    if name.starts_with("dm-") {
        return dm_encryption(sandbox, name, 0);
    }
    Encryption::Plain
}

fn dm_for_name(sandbox: &Sandbox, mapper_name: &str) -> Option<String> {
    sandbox
        .list("/sys/block")
        .into_iter()
        .filter(|entry| entry.starts_with("dm-"))
        .find(|dm| {
            sandbox
                .read(&format!("/sys/block/{dm}/dm/name"))
                .is_some_and(|n| n.trim() == mapper_name)
        })
}

fn dm_encryption(sandbox: &Sandbox, dm: &str, depth: u8) -> Encryption {
    if depth > 5 {
        return Encryption::Unknown;
    }
    let Some(uuid) = sandbox.read(&format!("/sys/block/{dm}/dm/uuid")) else {
        return Encryption::Unknown;
    };
    if uuid.trim().starts_with("CRYPT-") {
        return Encryption::Encrypted;
    }
    // LVM and friends sit on top of the real device.
    let slaves = sandbox.list(&format!("/sys/block/{dm}/slaves"));
    let mut saw_unknown = false;
    for slave in slaves {
        if slave.starts_with("dm-") {
            match dm_encryption(sandbox, &slave, depth + 1) {
                Encryption::Encrypted => return Encryption::Encrypted,
                Encryption::Unknown => saw_unknown = true,
                Encryption::Plain => {}
            }
        }
    }
    if saw_unknown {
        Encryption::Unknown
    } else {
        Encryption::Plain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)], name: &str) -> (std::path::PathBuf, Sandbox) {
        let root = std::env::temp_dir().join(format!("ibx-blk-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, content) in files {
            let full = root.join(path.trim_start_matches('/'));
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        let sandbox = Sandbox::at(&root);
        (root, sandbox)
    }

    #[test]
    fn luks_mapper_device_is_encrypted() {
        let (root, sb) = tree(
            &[
                ("/sys/block/dm-0/dm/name", "luks-1234\n"),
                ("/sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-abc-luks-1234\n"),
            ],
            "luks",
        );
        assert_eq!(
            device_encryption(&sb, "/dev/mapper/luks-1234"),
            Encryption::Encrypted
        );
        assert_eq!(device_encryption(&sb, "/dev/dm-0"), Encryption::Encrypted);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lvm_on_luks_is_encrypted_through_slaves() {
        let (root, sb) = tree(
            &[
                ("/sys/block/dm-0/dm/name", "luks-1\n"),
                ("/sys/block/dm-0/dm/uuid", "CRYPT-LUKS2-x\n"),
                ("/sys/block/dm-1/dm/name", "vg-root\n"),
                ("/sys/block/dm-1/dm/uuid", "LVM-abc\n"),
                ("/sys/block/dm-1/slaves/dm-0/.keep", ""),
            ],
            "lvm",
        );
        assert_eq!(
            device_encryption(&sb, "/dev/mapper/vg-root"),
            Encryption::Encrypted
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn plain_lvm_and_plain_partitions_are_not_encrypted() {
        let (root, sb) = tree(
            &[
                ("/sys/block/dm-1/dm/name", "vg-root\n"),
                ("/sys/block/dm-1/dm/uuid", "LVM-abc\n"),
            ],
            "plain",
        );
        assert_eq!(
            device_encryption(&sb, "/dev/mapper/vg-root"),
            Encryption::Plain
        );
        assert_eq!(device_encryption(&sb, "/dev/vda1"), Encryption::Plain);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn unmappable_sources_are_unknown_never_plain() {
        let (root, sb) = tree(&[("/sys/block/dm-0/dm/name", "other\n")], "unk");
        assert_eq!(
            device_encryption(&sb, "/dev/mapper/missing"),
            Encryption::Unknown
        );
        assert_eq!(device_encryption(&sb, "/dev/root"), Encryption::Unknown);
        assert_eq!(device_encryption(&sb, "overlay"), Encryption::Unknown);
        let _ = std::fs::remove_dir_all(root);
    }
}
