// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask stage`: lays IbexWall out as it is installed, under one
//! directory (a DESTDIR), and records which package each file belongs to.
//! The RPM, DEB and Arch packages are thin wrappers over this tree, so what
//! is installed is decided in one place.
//!
//! The plugin manifests in the tree are signed with the key in `--key-dir`
//! (`dev.pub`/`dev.key`, the development key, unless the maintainer's
//! release key directory is given) and the daemon is built with that public
//! key embedded, so an installed package trusts exactly the plugins it
//! shipped with and needs no `--dev-key`.

use std::collections::BTreeMap;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::devkey;

const MULTICALL: &str = "/usr/libexec/ibexwall/ibexwall-plugins";

pub struct Options {
    pub destdir: PathBuf,
    pub key_dir: PathBuf,
    pub build: bool,
    pub desktop: bool,
    /// Where cargo builds (`CARGO_TARGET_DIR`); the workspace's `target/` when None.
    pub target_dir: Option<PathBuf>,
    /// Extra environment for the build (a reproducible build sets
    /// `SOURCE_DATE_EPOCH` and `RUSTFLAGS`).
    pub build_env: Vec<(String, String)>,
}

/// Which package a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Package {
    Core,
    Desktop,
    Mcp,
    /// AppArmor profiles, for Debian and Ubuntu.
    AppArmor,
}

impl Package {
    pub fn name(self) -> &'static str {
        match self {
            Package::Core => "ibexwall",
            Package::Desktop => "ibexwall-desktop",
            Package::Mcp => "ibexwall-mcp",
            Package::AppArmor => "ibexwall-apparmor",
        }
    }
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn run(program: &str, args: &[&str], env: &[(String, String)], what: &str) -> Result<()> {
    let mut command = Command::new(program);
    command.args(args).current_dir(workspace());
    for (key, value) in env {
        command.env(key, value);
    }
    let status = command
        .status()
        .with_context(|| format!("{what}: {program}"))?;
    if !status.success() {
        bail!("{what} failed ({status})");
    }
    Ok(())
}

/// Copies one file into the tree and records which package owns it.
fn put(
    dest: &Path,
    files: &mut BTreeMap<String, Package>,
    rel: &str,
    source: &Path,
    mode: u32,
    package: Package,
) -> Result<()> {
    let target = dest.join(rel.trim_start_matches('/'));
    std::fs::create_dir_all(target.parent().expect("a parent"))?;
    std::fs::copy(source, &target)
        .with_context(|| format!("{} -> {}", source.display(), target.display()))?;
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode))?;
    files.insert(rel.to_string(), package);
    Ok(())
}

pub fn run_stage(options: &Options) -> Result<()> {
    let root = workspace().canonicalize()?;
    let key_dir = if options.key_dir.is_absolute() {
        options.key_dir.clone()
    } else {
        root.join(&options.key_dir)
    };
    let public = key_dir.join("dev.pub");
    let secret = key_dir.join("dev.key");
    let pair = devkey::ensure_keypair(&public, &secret)?;

    if options.build {
        let mut args = vec![
            "build",
            "--release",
            "-p",
            "ibexwall-core",
            "-p",
            "ibexwall-cli",
            "-p",
            "ibexwall-exec",
            "-p",
            "ibexwall-dns",
            "-p",
            "ibexwall-mcp",
            "-p",
            "ibexwall-agent",
            "-p",
            "ibexwall-ebpf-loader",
            "-p",
            "ibexwall-plugins",
        ];
        if options.desktop {
            args.extend(["-p", "ibexwall-desktop", "--features", "custom-protocol"]);
        }
        // The release public key goes into the daemon at build time.
        let mut env = options.build_env.clone();
        env.push((
            "IBEXWALL_RELEASE_PUBKEY".into(),
            public.to_string_lossy().into_owned(),
        ));
        if let Some(target) = &options.target_dir {
            env.push((
                "CARGO_TARGET_DIR".into(),
                target.to_string_lossy().into_owned(),
            ));
        }
        run("cargo", &args, &env, "building")?;
    }
    let object = root.join("target/bpf/ibexwall-ebpf.o");
    if !object.is_file() {
        crate::ebpf::run().context("the eBPF object is needed (cargo xtask ebpf)")?;
    }

    let dest = &options.destdir;
    if dest.exists() {
        std::fs::remove_dir_all(dest)?;
    }
    let mut files: BTreeMap<String, Package> = BTreeMap::new();
    let release = options
        .target_dir
        .clone()
        .unwrap_or_else(|| root.join("target"))
        .join("release");
    for (name, package) in [
        ("ibexwalld", Package::Core),
        ("ibexctl", Package::Core),
        ("ibexwall-exec", Package::Core),
        ("ibexwall-dns", Package::Core),
        ("ibexwall-ebpf-loader", Package::Core),
        ("ibexwall-mcp", Package::Mcp),
        ("ibexwall-agent", Package::Desktop),
    ] {
        put(
            dest,
            &mut files,
            &format!("/usr/bin/{name}"),
            &release.join(name),
            0o755,
            package,
        )?;
    }
    if options.desktop {
        put(
            dest,
            &mut files,
            "/usr/bin/ibexwall-desktop",
            &release.join("ibexwall-desktop"),
            0o755,
            Package::Desktop,
        )?;
    }
    put(
        dest,
        &mut files,
        MULTICALL,
        &release.join("ibexwall-plugins"),
        0o755,
        Package::Core,
    )?;
    put(
        dest,
        &mut files,
        "/usr/lib/ibexwall/ebpf/ibexwall-ebpf.o",
        &object,
        0o644,
        Package::Core,
    )?;

    // The plugins: manifest, its signature, and the name the binary is
    // started under (a link to the multicall binary).
    let units = crate::plugin_units::all(&root)?;
    let mut sockets = vec!["ibexwalld.socket".to_string()];
    for (id, unit) in &units {
        if id == "dev.echo" {
            continue;
        }
        let dir = format!("/usr/lib/ibexwall/plugins/{id}");
        let manifest = root.join("plugins").join(id).join("plugin.toml");
        put(
            dest,
            &mut files,
            &format!("{dir}/plugin.toml"),
            &manifest,
            0o644,
            Package::Core,
        )?;
        let signature = devkey::sign(&pair, &std::fs::read(&manifest)?, "ibexwall plugin");
        let sig_path = dest.join(format!("{}/plugin.toml.sig", dir.trim_start_matches('/')));
        std::fs::write(&sig_path, signature)?;
        files.insert(format!("{dir}/plugin.toml.sig"), Package::Core);
        let link = dest.join(format!("{}/{}", dir.trim_start_matches('/'), unit.name));
        symlink(relative_to(&dir, MULTICALL), &link)?;
        files.insert(format!("{dir}/{}", unit.name), Package::Core);
        for (suffix, text) in [("service", &unit.service), ("socket", &unit.socket)] {
            let rel = format!("/usr/lib/systemd/system/{}.{suffix}", unit.name);
            let path = dest.join(rel.trim_start_matches('/'));
            std::fs::create_dir_all(path.parent().expect("a parent"))?;
            std::fs::write(&path, text)?;
            files.insert(rel, Package::Core);
        }
        sockets.push(format!("{}.socket", unit.name));
    }

    // Static files from packaging/.
    let pk = root.join("packaging");
    for (rel, source, package) in [
        (
            "/usr/lib/systemd/system/ibexwalld.service",
            "systemd/ibexwalld.service",
            Package::Core,
        ),
        (
            "/usr/lib/systemd/system/ibexwalld.socket",
            "systemd/ibexwalld.socket",
            Package::Core,
        ),
        (
            "/usr/lib/systemd/system/ibexwall-dns.service",
            "systemd/ibexwall-dns.service",
            Package::Core,
        ),
        (
            "/usr/lib/systemd/system/ibexwall-dns-failsafe.service",
            "systemd/ibexwall-dns-failsafe.service",
            Package::Core,
        ),
        (
            "/usr/lib/systemd/system/ibexwall-monitor.service",
            "systemd/ibexwall-monitor.service",
            Package::Core,
        ),
        (
            "/usr/lib/systemd/system/ibexwall-mcp.service",
            "systemd/ibexwall-mcp.service",
            Package::Mcp,
        ),
        (
            "/usr/lib/systemd/system/ibexwall-mcp.path",
            "systemd/ibexwall-mcp.path",
            Package::Mcp,
        ),
        (
            "/usr/lib/systemd/system/ibexwall-mcp-reload.service",
            "systemd/ibexwall-mcp-reload.service",
            Package::Mcp,
        ),
        (
            "/usr/lib/systemd/user/ibexwall-agent.service",
            "systemd/ibexwall-agent.service",
            Package::Desktop,
        ),
        (
            "/usr/lib/sysusers.d/ibexwall.conf",
            "sysusers.d/ibexwall.conf",
            Package::Core,
        ),
        (
            "/usr/lib/sysusers.d/ibexwall-dns.conf",
            "sysusers.d/ibexwall-dns.conf",
            Package::Core,
        ),
        (
            "/usr/lib/tmpfiles.d/ibexwall.conf",
            "tmpfiles.d/ibexwall.conf",
            Package::Core,
        ),
        (
            "/usr/share/polkit-1/actions/com.ibexwall.policy",
            "polkit/com.ibexwall.policy",
            Package::Core,
        ),
        (
            "/usr/share/polkit-1/rules.d/49-ibexwall-assistants.rules",
            "polkit/49-ibexwall-assistants.rules",
            Package::Core,
        ),
        (
            "/usr/share/polkit-1/rules.d/49-ibexwall-admins.rules",
            "polkit/49-ibexwall-admins.rules",
            Package::Core,
        ),
    ] {
        put(dest, &mut files, rel, &pk.join(source), 0o644, package)?;
    }
    if options.desktop {
        put(
            dest,
            &mut files,
            "/usr/share/applications/com.ibexwall.IbexWall.desktop",
            &pk.join("desktop/com.ibexwall.IbexWall.desktop"),
            0o644,
            Package::Desktop,
        )?;
        for size in ["32x32", "64x64", "128x128", "256x256", "512x512"] {
            put(
                dest,
                &mut files,
                &format!("/usr/share/icons/hicolor/{size}/apps/com.ibexwall.IbexWall.png"),
                &pk.join(format!(
                    "icons/hicolor/{size}/apps/com.ibexwall.IbexWall.png"
                )),
                0o644,
                Package::Desktop,
            )?;
        }
    }
    put(
        dest,
        &mut files,
        "/usr/share/doc/ibexwall/LICENSE",
        &root.join("LICENSES/GPL-3.0-or-later.txt"),
        0o644,
        Package::Core,
    )?;

    // The shipped compliance profiles (F11a): the default first-release
    // set, evaluated against what the plugins measure. The source of truth
    // is the `ibexwall-profiles` repository; this is a snapshot so the
    // package works out of the box. Operators shadow them with files in
    // /etc/ibexwall/profiles.
    let profile_src = root.join("profiles/compliance");
    for entry in std::fs::read_dir(&profile_src)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        put(
            dest,
            &mut files,
            &format!("{}/{name}", ibexwall_proto::names::PROFILE_INSTALL_DIR),
            &path,
            0o644,
            Package::Core,
        )?;
    }

    // AppArmor: the profiles, and the include the manifests generate.
    let apparmor = pk.join("apparmor");
    let mut profiles: Vec<_> = std::fs::read_dir(&apparmor)?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("usr."))
        .collect();
    profiles.sort();
    for name in &profiles {
        put(
            dest,
            &mut files,
            &format!("/usr/share/ibexwall/apparmor/{name}"),
            &apparmor.join(name),
            0o644,
            Package::AppArmor,
        )?;
    }
    let include = "/usr/share/ibexwall/apparmor/ibexwall/plugin-paths";
    let target = dest.join(include.trim_start_matches('/'));
    std::fs::create_dir_all(target.parent().expect("a parent"))?;
    std::fs::write(
        &target,
        crate::mac::apparmor_plugin_paths(&crate::mac::manifests(&root)?),
    )?;
    files.insert(include.to_string(), Package::AppArmor);

    // The steps every package format runs on install, upgrade and removal;
    // installed so a scriptlet can source them on the target machine.
    put(
        dest,
        &mut files,
        "/usr/lib/ibexwall/package-scripts.sh",
        &pk.join("scripts.sh"),
        0o644,
        Package::Core,
    )?;

    // What is switched on at install: the control socket and every plugin's
    // socket (they start nothing until the core connects). The monitor, the
    // resolver, the MCP server and the session agent stay off until used.
    let preset = format!(
        "# IbexWall: the sockets cost nothing until something connects.\n{}",
        sockets
            .iter()
            .map(|s| format!("enable {s}\n"))
            .collect::<String>()
    );
    let preset_path = "/usr/lib/systemd/system-preset/85-ibexwall.preset";
    let target = dest.join(preset_path.trim_start_matches('/'));
    std::fs::create_dir_all(target.parent().expect("a parent"))?;
    std::fs::write(&target, preset)?;
    files.insert(preset_path.to_string(), Package::Core);
    let enable_list = "/usr/lib/ibexwall/sockets.list";
    let target = dest.join(enable_list.trim_start_matches('/'));
    std::fs::create_dir_all(target.parent().expect("a parent"))?;
    std::fs::write(&target, sockets.join("\n") + "\n")?;
    files.insert(enable_list.to_string(), Package::Core);

    // One list per package, for the packaging tools.
    let lists = dest.join("../stage-lists");
    std::fs::create_dir_all(&lists)?;
    for package in [
        Package::Core,
        Package::Desktop,
        Package::Mcp,
        Package::AppArmor,
    ] {
        let text: String = files
            .iter()
            .filter(|(_, p)| **p == package)
            .map(|(path, _)| format!("{path}\n"))
            .collect();
        std::fs::write(lists.join(format!("{}.list", package.name())), text)?;
        // The directories only IbexWall uses, so a removal leaves none behind.
        let dirs: String = owned_directories(
            files
                .iter()
                .filter(|(_, p)| **p == package)
                .map(|(path, _)| path.as_str()),
        )
        .into_iter()
        .map(|d| format!("{d}\n"))
        .collect();
        std::fs::write(lists.join(format!("{}.dirs", package.name())), dirs)?;
    }
    println!(
        "staged {} files into {} ({} plugins, key {})",
        files.len(),
        dest.display(),
        units.len() - 1,
        public.display()
    );
    Ok(())
}

/// The directories under IbexWall's own roots that hold these files,
/// parents first.
fn owned_directories<'a>(paths: impl Iterator<Item = &'a str>) -> Vec<String> {
    const ROOTS: [&str; 4] = [
        "/usr/share/ibexwall",
        "/usr/lib/ibexwall",
        "/usr/libexec/ibexwall",
        "/usr/share/doc/ibexwall",
    ];
    let mut dirs = std::collections::BTreeSet::new();
    for path in paths {
        let mut current = Path::new(path).parent();
        while let Some(dir) = current {
            let text = dir.to_string_lossy();
            if !ROOTS.iter().any(|root| text.starts_with(root)) {
                break;
            }
            dirs.insert(text.into_owned());
            current = dir.parent();
        }
    }
    dirs.into_iter().collect()
}

/// The path from the directory `from` to the file `to`, both absolute.
fn relative_to(from: &str, to: &str) -> PathBuf {
    let from: Vec<&str> = from.trim_matches('/').split('/').collect();
    let to_parts: Vec<&str> = to.trim_matches('/').split('/').collect();
    let common = from
        .iter()
        .zip(&to_parts)
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in common..from.len() {
        out.push("..");
    }
    for part in &to_parts[common..] {
        out.push(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_ibexwalls_own_directories_are_owned_by_the_packages() {
        let dirs = owned_directories(
            [
                "/usr/bin/ibexwalld",
                "/usr/lib/ibexwall/plugins/net.vpn/plugin.toml",
                "/usr/lib/ibexwall/ebpf/ibexwall-ebpf.o",
                "/usr/lib/systemd/system/ibexwalld.service",
                "/usr/libexec/ibexwall/ibexwall-plugins",
            ]
            .into_iter(),
        );
        assert_eq!(
            dirs,
            [
                "/usr/lib/ibexwall",
                "/usr/lib/ibexwall/ebpf",
                "/usr/lib/ibexwall/plugins",
                "/usr/lib/ibexwall/plugins/net.vpn",
                "/usr/libexec/ibexwall",
            ]
        );
    }

    #[test]
    fn the_plugin_link_reaches_the_multicall_binary_from_its_directory() {
        assert_eq!(
            relative_to("/usr/lib/ibexwall/plugins/net.vpn", MULTICALL),
            PathBuf::from("../../../../libexec/ibexwall/ibexwall-plugins")
        );
        assert_eq!(relative_to("/a/b", "/a/c/d"), PathBuf::from("../c/d"));
    }
}
