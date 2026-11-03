// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Application identity (spec section 4.9). Everything here treats its
//! inputs (cgroup paths, unit names, file paths, command output) as
//! untrusted data: they are parsed, never interpolated into a command.
//!
//! Identity is best effort and labelled: [`AppKind::Unknown`] is a valid
//! answer, and an interpreter is identified by the interpreter's own exe
//! (the script behind it is a documented limitation).

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The kind of thing that made a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppKind {
    Flatpak,
    Snap,
    /// A graphical app started by the desktop (`app-*.service|scope`).
    DesktopApp,
    /// A unit under `system.slice`.
    SystemService,
    Container,
    /// A program started from a terminal or script: identified by exe.
    Cli,
    Unknown,
}

/// What the cgroup says about a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity {
    pub kind: AppKind,
    /// Application id, snap name, unit name or `container:<id>`; empty for
    /// [`AppKind::Cli`] and [`AppKind::Unknown`] (the exe path identifies
    /// those).
    pub id: String,
}

impl Identity {
    fn new(kind: AppKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }
}

/// Classifies a `/proc/<pid>/cgroup` line (`0::/user.slice/...`) or a bare
/// cgroup path. Deeper components win over shallower ones, so an app
/// scope inside a user session is the app, not the session.
pub fn classify_cgroup(line: &str) -> Identity {
    let path = line.rsplit("::").next().unwrap_or(line).trim();
    let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();

    for component in components.iter().rev() {
        if let Some(identity) = classify_component(component) {
            return identity;
        }
    }
    let in_system_slice = components.first() == Some(&"system.slice");
    if in_system_slice && let Some(unit) = components.iter().find(|c| c.ends_with(".service")) {
        return Identity::new(AppKind::SystemService, *unit);
    }
    if components
        .iter()
        .any(|c| c.starts_with("session-") && c.ends_with(".scope"))
    {
        return Identity::new(AppKind::Cli, "");
    }
    Identity::new(AppKind::Unknown, "")
}

fn classify_component(component: &str) -> Option<Identity> {
    if let Some(identity) = classify_app_unit(component) {
        return Some(identity);
    }
    if let Some(identity) = classify_snap(component) {
        return Some(identity);
    }
    classify_container(component)
}

/// `app[-<launcher>]-<ApplicationID>[@<rand>].service` or
/// `app[-<launcher>]-<ApplicationID>-<rand>.scope`. systemd escapes a `-`
/// inside the id as `\x2d`, so splitting on `-` is exact.
fn classify_app_unit(component: &str) -> Option<Identity> {
    let (stem, is_scope) = if let Some(stem) = component.strip_suffix(".scope") {
        (stem, true)
    } else {
        (component.strip_suffix(".service")?, false)
    };
    let stem = stem.strip_prefix("app-")?;
    let stem = stem.split('@').next().unwrap_or(stem);
    let stem = if is_scope {
        strip_numeric_tail(stem)
    } else {
        stem
    };

    let parts: Vec<&str> = stem.split('-').collect();
    let (launcher, id) = match parts.as_slice() {
        [id] => (None, *id),
        [launcher, id] => (Some(*launcher), *id),
        // More dashes than the convention allows: keep the last token as
        // the id and call the rest the launcher.
        [.., launcher, id] => (Some(*launcher), *id),
        [] => return None,
    };
    let id = unescape_unit(id);
    if id.is_empty() {
        return None;
    }
    let kind = if launcher == Some("flatpak") {
        AppKind::Flatpak
    } else {
        AppKind::DesktopApp
    };
    Some(Identity::new(kind, id))
}

/// Removes a trailing `-<digits>` (the pid or random suffix of a scope).
fn strip_numeric_tail(stem: &str) -> &str {
    match stem.rsplit_once('-') {
        Some((head, tail)) if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => stem,
    }
}

/// Decodes the `\xNN` escapes systemd uses in unit names.
fn unescape_unit(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && bytes.get(i + 1) == Some(&b'x')
            && let Some(hex) = text.get(i + 2..i + 4)
            && let Ok(value) = u8::from_str_radix(hex, 16)
        {
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `snap.<name>.<app>-<uuid>.scope`: the id is `snap.<name>.<app>`.
fn classify_snap(component: &str) -> Option<Identity> {
    let stem = component.strip_suffix(".scope")?;
    if !stem.starts_with("snap.") {
        return None;
    }
    let id = match stem.len().checked_sub(37) {
        Some(at) if stem.as_bytes()[at] == b'-' && is_uuid(&stem[at + 1..]) => &stem[..at],
        _ => stem,
    };
    Some(Identity::new(AppKind::Snap, id))
}

fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    groups.len() == 5
        && groups
            .iter()
            .zip(lens)
            .all(|(g, n)| g.len() == n && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Container runtimes put each container in `<runtime>-<id>.scope`.
fn classify_container(component: &str) -> Option<Identity> {
    let stem = component.strip_suffix(".scope")?;
    for prefix in [
        "docker-",
        "libpod-",
        "crio-",
        "cri-containerd-",
        "containerd-",
    ] {
        if let Some(id) = stem.strip_prefix(prefix)
            && id.len() >= 12
            && id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some(Identity::new(
                AppKind::Container,
                format!("container:{}", &id[..12]),
            ));
        }
    }
    None
}

/// SHA-256 of a file, streamed, as lowercase hex. The caller treats a
/// failure (permissions, vanished file) as "no hash", not as an error.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// A package manager that can say which package owns a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Rpm,
    Dpkg,
    Pacman,
}

impl PackageManager {
    /// The fixed allowlist: absolute binary and argv for an owner query.
    /// The queried path is passed as its own argument after `--`-style
    /// separation where the tool supports it, never through a shell.
    pub fn query(self, path: &Path) -> (&'static str, Vec<String>) {
        let path = path.to_string_lossy().into_owned();
        match self {
            Self::Rpm => (
                "/usr/bin/rpm",
                vec!["-qf".into(), "--qf".into(), "%{NAME}\\n".into(), path],
            ),
            Self::Dpkg => ("/usr/bin/dpkg", vec!["-S".into(), path]),
            Self::Pacman => ("/usr/bin/pacman", vec!["-Qo".into(), path]),
        }
    }

    /// Parses the tool's stdout into a package name.
    pub fn parse_owner(self, stdout: &str) -> Option<String> {
        let line = stdout.lines().next()?.trim();
        let name = match self {
            Self::Rpm => line,
            // "curl: /usr/bin/curl" or "libc6:amd64, libc6-dev: /path"
            Self::Dpkg => {
                // The owner list is followed by ": <absolute path>"; error
                // lines ("dpkg-query: no path found ...") are not.
                let (owners, path) = line.rsplit_once(": ")?;
                if !path.starts_with('/') {
                    return None;
                }
                owners.split(',').next()?.split(':').next()?.trim()
            }
            // "/usr/bin/curl is owned by curl 8.1.2-1"
            Self::Pacman => line
                .split(" is owned by ")
                .nth(1)?
                .split_whitespace()
                .next()?,
        };
        let name = name.trim();
        let valid = !name.is_empty()
            && !name.contains(' ')
            && !name.starts_with("file ")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-._:".contains(&b));
        valid.then(|| name.to_string())
    }

    /// Which manager this system uses, judged by the allowlisted binaries.
    pub fn detect(root: &Path) -> Option<Self> {
        [Self::Rpm, Self::Dpkg, Self::Pacman]
            .into_iter()
            .find(|manager| {
                let (binary, _) = manager.query(Path::new("/"));
                root.join(binary.trim_start_matches('/')).exists()
            })
    }
}

/// Asks the package manager who owns `path`, through `run`, which executes
/// an argv and returns stdout on success. Relative paths are refused so a
/// value can never be read as an option.
pub fn package_owner(
    manager: PackageManager,
    path: &Path,
    run: &dyn Fn(&str, &[String]) -> Option<String>,
) -> Option<String> {
    if !path.is_absolute() {
        return None;
    }
    let (binary, args) = manager.query(path);
    manager.parse_owner(&run(binary, &args)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(line: &str) -> (AppKind, String) {
        let identity = classify_cgroup(line);
        (identity.kind, identity.id)
    }

    #[test]
    fn flatpak_scope_gives_the_app_id() {
        let line = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-3141.scope";
        assert_eq!(id(line), (AppKind::Flatpak, "org.mozilla.firefox".into()));
    }

    #[test]
    fn desktop_launcher_conventions() {
        let gnome = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Terminal-2718.scope";
        assert_eq!(
            id(gnome),
            (AppKind::DesktopApp, "org.gnome.Terminal".into())
        );
        let kde = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.dolphin@a1b2c3.service";
        assert_eq!(id(kde), (AppKind::DesktopApp, "org.kde.dolphin".into()));
        let plain =
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox-99.scope";
        assert_eq!(id(plain), (AppKind::DesktopApp, "firefox".into()));
    }

    #[test]
    fn escaped_dashes_in_an_application_id_are_decoded() {
        let line = "0::/user.slice/user@1000.service/app.slice/app-com.github.foo\\x2dbar-7.scope";
        assert_eq!(id(line), (AppKind::DesktopApp, "com.github.foo-bar".into()));
    }

    #[test]
    fn snap_scope_drops_the_uuid() {
        let line = "0::/user.slice/user@1000.service/app.slice/snap.firefox.firefox-0a1b2c3d-1111-2222-3333-444455556666.scope";
        assert_eq!(id(line), (AppKind::Snap, "snap.firefox.firefox".into()));
        let hyphen =
            "0::/x/snap.snap-store.ubuntu-software-0a1b2c3d-1111-2222-3333-444455556666.scope";
        assert_eq!(
            id(hyphen),
            (AppKind::Snap, "snap.snap-store.ubuntu-software".into())
        );
    }

    #[test]
    fn system_services_use_the_unit_name() {
        assert_eq!(
            id("0::/system.slice/sshd.service"),
            (AppKind::SystemService, "sshd.service".into())
        );
        assert_eq!(
            id("0::/system.slice/NetworkManager.service/sub"),
            (AppKind::SystemService, "NetworkManager.service".into())
        );
    }

    #[test]
    fn containers_are_named_by_a_short_id() {
        let docker = "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope";
        assert_eq!(
            id(docker),
            (AppKind::Container, "container:0123456789ab".into())
        );
        let podman =
            "0::/user.slice/user@1000.service/user.slice/libpod-fedcba9876543210fedcba98.scope";
        assert_eq!(
            id(podman),
            (AppKind::Container, "container:fedcba987654".into())
        );
    }

    #[test]
    fn a_terminal_session_is_a_cli_and_junk_is_unknown() {
        assert_eq!(
            id("0::/user.slice/user-1000.slice/session-6.scope"),
            (AppKind::Cli, String::new())
        );
        assert_eq!(id("0::/"), (AppKind::Unknown, String::new()));
        assert_eq!(id(""), (AppKind::Unknown, String::new()));
        assert_eq!(id("garbage"), (AppKind::Unknown, String::new()));
    }

    #[test]
    fn an_app_scope_inside_a_session_beats_the_session() {
        let line = "0::/user.slice/user-1000.slice/session-2.scope/app-firefox-1.scope";
        assert_eq!(id(line), (AppKind::DesktopApp, "firefox".into()));
    }

    #[test]
    fn hashes_a_file() {
        let dir = std::env::temp_dir().join(format!("ibexwall-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("abc");
        std::fs::write(&file, b"abc").unwrap();
        assert_eq!(
            hash_file(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(hash_file(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn owner_output_is_parsed_per_manager() {
        assert_eq!(
            PackageManager::Rpm.parse_owner("curl\n"),
            Some("curl".into())
        );
        assert_eq!(
            PackageManager::Rpm.parse_owner("file /x is not owned by any package\n"),
            None
        );
        assert_eq!(
            PackageManager::Dpkg.parse_owner("curl: /usr/bin/curl\n"),
            Some("curl".into())
        );
        assert_eq!(
            PackageManager::Dpkg.parse_owner("libc6:amd64, libc6-dev:amd64: /usr/lib/x\n"),
            Some("libc6".into())
        );
        assert_eq!(
            PackageManager::Dpkg.parse_owner("dpkg-query: no path found matching pattern /x\n"),
            None
        );
        assert_eq!(
            PackageManager::Pacman.parse_owner("/usr/bin/curl is owned by curl 8.1.2-1\n"),
            Some("curl".into())
        );
        assert_eq!(
            PackageManager::Pacman.parse_owner("error: No package owns /x\n"),
            None
        );
        assert_eq!(PackageManager::Rpm.parse_owner(""), None);
    }

    #[test]
    fn owner_lookup_refuses_relative_paths_and_uses_the_allowlist() {
        let run = |binary: &str, args: &[String]| {
            assert_eq!(binary, "/usr/bin/rpm");
            assert_eq!(args.last().unwrap(), "/usr/bin/curl");
            Some("curl\n".to_string())
        };
        assert_eq!(
            package_owner(PackageManager::Rpm, Path::new("/usr/bin/curl"), &run),
            Some("curl".into())
        );
        // Looks like an option: refused before anything runs.
        let never = |_: &str, _: &[String]| -> Option<String> { panic!("must not run") };
        assert_eq!(
            package_owner(PackageManager::Rpm, Path::new("-rf"), &never),
            None
        );
    }
}
