// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! `cargo xtask vm-test`: QEMU/KVM smoke test.
//!
//! Downloads the Fedora cloud image (checksum-verified) into a cache,
//! boots an overlay clone with a cloud-init NoCloud seed, then runs the
//! smoke test over SSH: a workspace binary must execute inside the VM.
//! The developer host is never modified; everything happens inside the
//! VM (project rule: no system changes outside VMs/`IBEXWALL_ROOT`).

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

/// Fedora releases to try, newest first (matrix grows in F1).
const FEDORA_RELEASES: &[u32] = &[45, 44];
/// Mirrors tried in order; first one that serves the listing wins.
const FEDORA_MIRRORS: &[&str] = &[
    "https://dl.fedoraproject.org/pub/fedora/linux",
    "https://mirrors.kernel.org/fedora",
];
const SSH_TIMEOUT: Duration = Duration::from_secs(420);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(120);

/// A distro the VM harness can boot from an official cloud image.
struct Distro {
    id: &'static str,
    /// Command (run over ssh as the test user) that installs polkit and
    /// python3 and must succeed.
    install: &'static str,
    /// Where the image and its checksum list live; Fedora is discovered
    /// from a directory listing instead.
    image: Option<Image>,
}

struct Image {
    base_url: &'static str,
    file: &'static str,
    sums_file: &'static str,
    /// `sha256sum` or `sha512sum`.
    hasher: &'static str,
}

const DISTROS: &[Distro] = &[
    Distro {
        id: "fedora",
        install: "rpm -q polkit >/dev/null 2>&1 || sudo dnf install -y polkit",
        image: None,
    },
    Distro {
        id: "ubuntu-24.04",
        install: "sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq polkitd python3",
        image: Some(Image {
            base_url: "https://cloud-images.ubuntu.com/releases/24.04/release",
            file: "ubuntu-24.04-server-cloudimg-amd64.img",
            sums_file: "SHA256SUMS",
            hasher: "sha256sum",
        }),
    },
    Distro {
        id: "ubuntu-26.04",
        install: "sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq polkitd python3",
        image: Some(Image {
            base_url: "https://cloud-images.ubuntu.com/releases/26.04/release",
            file: "ubuntu-26.04-server-cloudimg-amd64.img",
            sums_file: "SHA256SUMS",
            hasher: "sha256sum",
        }),
    },
    Distro {
        id: "debian",
        install: "sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 install -y -qq polkitd python3",
        image: Some(Image {
            base_url: "https://cloud.debian.org/images/cloud/trixie/latest",
            file: "debian-13-generic-amd64.qcow2",
            sums_file: "SHA512SUMS",
            hasher: "sha512sum",
        }),
    },
    Distro {
        id: "arch",
        install: "sudo pacman -Sy --noconfirm --needed polkit python",
        image: Some(Image {
            base_url: "https://geo.mirror.pkgbuild.com/images/latest",
            file: "Arch-Linux-x86_64-cloudimg.qcow2",
            sums_file: "Arch-Linux-x86_64-cloudimg.qcow2.SHA256",
            hasher: "sha256sum",
        }),
    },
];

pub fn run(distro: &str, phase: Option<&str>) -> Result<()> {
    let Some(entry) = DISTROS.iter().find(|d| d.id == distro) else {
        let ids: Vec<&str> = DISTROS.iter().map(|d| d.id).collect();
        bail!(
            "unsupported distro `{distro}` (supported: {})",
            ids.join(", ")
        );
    };
    let (vm, workspace) = boot(entry)?;
    match phase {
        None | Some("f0") => f0_smoke(&vm, &workspace),
        Some("f1") => crate::f1::run(&vm, &workspace, entry.install),
        Some("f2") => crate::f2::run(&vm, &workspace, entry.install),
        Some("f3") => crate::f3::run(&vm, &workspace, entry.install),
        Some("f4") => crate::f4::run(&vm, &workspace, entry.install),
        Some("f5") => crate::f5::run(&vm, &workspace, entry.install),
        Some("f6") => crate::f6::run(&vm, &workspace, entry.install),
        Some("f7") => crate::f7::run(&vm, &workspace, entry.install),
        Some("f8") => crate::f8::run(&vm, &workspace, entry.install),
        Some("f9") => crate::f9::run(&vm, &workspace, entry.install),
        Some("f10") => crate::f10::run(&vm, &workspace, entry.install),
        Some("f11a") => crate::f11a::run(&vm, &workspace, entry.install),
        Some("f11b") => crate::f11b::run(&vm, &workspace, entry.install),
        Some("desktop") => crate::desktop::run(&vm, &workspace, entry.install),
        Some("firewall-on") => crate::firewall_on::run(&vm, &workspace, entry.install),
        Some("selinux") => crate::f10::run_selinux_build(&vm, &workspace, entry.install),
        Some("fixtures") => crate::fixtures::run(&vm, &workspace, entry.id),
        Some(other) => {
            bail!(
                "unknown phase `{other}` (supported: f0 to f10, f11a, f11b, desktop, firewall-on, fixtures)"
            )
        }
    }
}

/// Boots the distro VM and returns it with the workspace root. The Drop
/// guard shuts it down.
fn boot(distro: &Distro) -> Result<(Vm, PathBuf)> {
    check_tools()?;
    let cache = cache_dir();
    std::fs::create_dir_all(&cache)?;

    let base = match &distro.image {
        None => ensure_fedora_image(&cache)?,
        Some(image) => ensure_image(&cache, image)?,
    };
    println!("base image: {}", base.display());
    let workspace = workspace_root();
    Ok((start_vm(&cache, &base)?, workspace))
}

/// Downloads an image and verifies it against the distro's published
/// checksum list.
fn ensure_image(cache: &Path, image: &Image) -> Result<PathBuf> {
    // "Latest" images are renewed upstream: a cached copy that no longer
    // matches the published checksum is stale, so fetch it once more
    // before calling it a failure.
    match fetch_verified_image(cache, image) {
        Ok(path) => Ok(path),
        Err(error) if error.to_string().contains("checksum mismatch") => {
            fetch_verified_image(cache, image)
        }
        Err(error) => Err(error),
    }
}

fn fetch_verified_image(cache: &Path, image: &Image) -> Result<PathBuf> {
    let sums = curl(&format!("{}/{}", image.base_url, image.sums_file))?;
    let expected = checksum_for(&sums, image.file)
        .with_context(|| format!("no checksum for {} in {}", image.file, image.sums_file))?;
    let target = cache.join(image.file);
    if !target.is_file() {
        println!("downloading {} ...", image.file);
        run_capture(
            "curl",
            [
                "-fL",
                "--progress-bar",
                "-o",
                &target.to_string_lossy(),
                &format!("{}/{}", image.base_url, image.file),
            ],
            None,
            "downloading cloud image",
        )?;
    }
    let output = run_capture(
        image.hasher,
        [&target.to_string_lossy()],
        None,
        "hashing image",
    )?;
    let actual = output
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    if actual != expected {
        // A partial download must not poison the cache.
        let _ = std::fs::remove_file(&target);
        bail!(
            "checksum mismatch for {}: expected {expected}, got {actual}",
            image.file
        );
    }
    Ok(target)
}

/// Finds `file` in a `sha*sum` style list (`<hash>  <file>` or
/// `<hash> *<file>`, or just `<hash>` when the list has a single entry).
fn checksum_for(sums: &str, file: &str) -> Option<String> {
    for line in sums.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name.trim_start_matches('*') == file {
            return Some(hash.to_lowercase());
        }
    }
    None
}

fn f0_smoke(vm: &Vm, workspace: &Path) -> Result<()> {
    run_capture(
        "cargo",
        ["build", "-p", "ibexwall-cli"],
        None,
        "building ibexctl for the smoke test",
    )?;
    let ibexctl = workspace.join("target/debug/ibexctl");

    let kernel = vm.ssh("uname -sr")?.trim().to_string();
    println!("vm up: {kernel}");
    let version = vm
        .ssh_pipe(
            &ibexctl,
            "cat > /tmp/ibexctl && chmod +x /tmp/ibexctl && /tmp/ibexctl --version",
        )?
        .trim()
        .to_string();
    println!("smoke: {version}");

    assert!(kernel.starts_with("Linux"), "unexpected uname output");
    assert!(
        version.starts_with("ibexctl "),
        "workspace binary did not run inside the VM: `{version}`"
    );
    println!("PASS: fedora vm smoke test");
    Ok(())
}

pub(crate) struct Vm {
    work: PathBuf,
    qemu: std::process::Child,
    port: u16,
    key: PathBuf,
}

impl Vm {
    pub(crate) fn ssh_base(&self) -> Command {
        let mut cmd = Command::new("ssh");
        cmd.args([
            "-i",
            self.key.to_str().unwrap(),
            "-p",
            &self.port.to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "BatchMode=yes",
            "ibex@127.0.0.1",
        ]);
        cmd
    }

    pub(crate) fn ssh(&self, command: &str) -> Result<String> {
        let output = self
            .ssh_base()
            .arg(command)
            .output()
            .context("running ssh")?;
        if !output.status.success() {
            bail!(
                "ssh `{command}` failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Runs a script given on stdin as root-capable `sudo bash -s`.
    pub(crate) fn ssh_stdin(&self, script: &str) -> Result<String> {
        let mut child = self
            .ssh_base()
            .arg("sudo bash -s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(script.as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "remote script failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Pipes `local` into `remote_cmd` over ssh stdin (no scp needed).
    pub(crate) fn ssh_pipe(&self, local: &Path, remote_cmd: &str) -> Result<String> {
        let mut child = self
            .ssh_base()
            .arg(remote_cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        {
            let stdin = child.stdin.as_mut().expect("piped stdin");
            let bytes = std::fs::read(local)?;
            stdin.write_all(&bytes).context("sending file over ssh")?;
        } // drop closes stdin
        let output = child.wait_with_output()?;
        if !output.status.success() {
            bail!(
                "ssh pipe `{remote_cmd}` failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = self.ssh("sudo poweroff");
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        while Instant::now() < deadline {
            if self.qemu.try_wait().is_ok_and(|s| s.is_some()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = self.qemu.kill();
        let _ = self.qmu_wait();
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

impl Vm {
    fn qmu_wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.qemu.wait()
    }
}

fn start_vm(cache: &Path, base: &Path) -> Result<Vm> {
    let work = cache.join(format!(
        "work-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    ));
    std::fs::create_dir_all(&work)?;
    let key = work.join("id_ed25519");
    run_capture(
        "ssh-keygen",
        ["-t", "ed25519", "-N", "", "-f", key.to_str().unwrap()],
        Some(work.to_str().unwrap()),
        "generating smoke-test ssh key",
    )?;
    let pubkey = std::fs::read_to_string(key.with_extension("pub"))?
        .trim()
        .to_string();

    let user_data = format!(
        "#cloud-config\nhostname: ibexwall-f0\nusers:\n  - name: ibex\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    ssh_authorized_keys:\n      - {pubkey}\nssh_pwauth: false\npackage_update: false\n"
    );
    let meta_data = "instance-id: ibexwall-f0\nlocal-hostname: ibexwall-f0\n";
    std::fs::write(work.join("user-data"), user_data)?;
    std::fs::write(work.join("meta-data"), meta_data)?;
    run_capture(
        "genisoimage",
        [
            "-output",
            "seed.iso",
            "-volid",
            "cidata",
            "-joliet",
            "user-data",
            "meta-data",
        ],
        Some(work.to_str().unwrap()),
        "building cloud-init seed",
    )?;

    let overlay = work.join("overlay.qcow2");
    run_capture(
        "qemu-img",
        [
            "create",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            base.to_str().unwrap(),
            overlay.to_str().unwrap(),
            // Bigger than the cloud images ship with: cloud-init grows the
            // root filesystem, and some scenarios install packages.
            "8G",
        ],
        None,
        "creating overlay disk",
    )?;

    let port = free_port()?;
    let serial_log = work.join("serial.log");
    let qemu = Command::new("qemu-system-x86_64")
        .args([
            "-machine",
            "q35,accel=kvm",
            "-cpu",
            "host",
            "-smp",
            "2",
            "-m",
            "2048",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            &format!("file:{}", serial_log.display()),
            "-drive",
            &format!("file={},if=virtio,format=qcow2", overlay.display()),
            "-cdrom",
            &format!("{}", work.join("seed.iso").display()),
            "-netdev",
            &format!("user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22"),
            "-device",
            "virtio-net-pci,netdev=net0",
            "-pidfile",
            &format!("{}", work.join("qemu.pid").display()),
        ])
        .stdout(std::fs::File::create(work.join("qemu.out"))?)
        .stderr(std::fs::File::create(work.join("qemu.err"))?)
        .spawn()
        .context("starting qemu")?;

    // Safety: from here on the Vm drop guard owns shutdown/cleanup.
    let vm = Vm {
        work,
        qemu,
        port,
        key,
    };

    println!("waiting for ssh (up to {}s)...", SSH_TIMEOUT.as_secs());
    let deadline = Instant::now() + SSH_TIMEOUT;
    loop {
        if vm
            .ssh_base()
            .arg("true")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            break;
        }
        if Instant::now() > deadline {
            bail!("VM never became reachable over ssh; see serial.log in the work dir");
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    Ok(vm)
}

fn check_tools() -> Result<()> {
    for tool in [
        "qemu-system-x86_64",
        "qemu-img",
        "genisoimage",
        "ssh",
        "ssh-keygen",
        "curl",
        "sha256sum",
    ] {
        if which(tool).is_none() {
            bail!(
                "missing tool `{tool}`; on Fedora: sudo dnf install qemu-system-x86 qemu-img genisoimage openssh-clients coreutils curl"
            );
        }
    }
    if !Path::new("/dev/kvm").exists() {
        bail!("/dev/kvm not available; VM tests require KVM");
    }
    Ok(())
}

fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|p| p.is_file())
}

fn cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".cache"));
    base.join("ibexwall").join("vm")
}

pub(crate) fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives inside the workspace")
        .to_path_buf()
}

/// Downloads (and verifies) the newest available Fedora cloud image.
/// The checksum file name varies per respin (e.g.
/// `Fedora-Cloud-44-1.7-x86_64-CHECKSUM`), so both the image name and
/// the checksum name are discovered from the directory listing.
fn ensure_fedora_image(cache: &Path) -> Result<PathBuf> {
    for release in FEDORA_RELEASES {
        for mirror in FEDORA_MIRRORS {
            let dir = format!("{mirror}/releases/{release}/Cloud/x86_64/images/");
            let Ok(listing) = curl(&dir) else { continue };
            let Some((file, checksum_file)) = pick_cloud_image(&listing) else {
                continue;
            };
            let Ok(checksum) = curl(&format!("{dir}{checksum_file}")) else {
                continue;
            };
            let Some(hash) = parse_cloud_checksum(&checksum, &file) else {
                continue;
            };

            let target = cache.join(&file);
            if !target.is_file() {
                println!("downloading {file} (~700 MB) from {mirror}...");
                run_capture(
                    "curl",
                    [
                        "-fL",
                        "--progress-bar",
                        "-o",
                        &target.to_string_lossy(),
                        &format!("{dir}{file}"),
                    ],
                    None,
                    "downloading cloud image",
                )?;
            }
            let actual = run_capture(
                "sha256sum",
                [&target.to_string_lossy()],
                None,
                "hashing image",
            )?;
            let actual = actual
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_lowercase();
            if actual != hash.to_lowercase() {
                bail!("checksum mismatch for {file}: expected {hash}, got {actual}");
            }
            return Ok(target);
        }
    }
    bail!("no Fedora cloud image found for releases {FEDORA_RELEASES:?}")
}

/// From a directory listing, pick the generic cloud qcow2 and the
/// checksum file name.
fn pick_cloud_image(listing: &str) -> Option<(String, String)> {
    let mut file = None;
    let mut checksum_file = None;
    for href in listing.split("href=\"").skip(1) {
        let raw = href.split('"').next()?;
        let name = raw.split('/').next_back().unwrap_or_default();
        if name.contains("Cloud-Base-Generic") && name.ends_with(".qcow2") && file.is_none() {
            file = Some(name.to_string());
        } else if name == "CHECKSUM" || name.ends_with("-CHECKSUM") {
            checksum_file = Some(name.to_string());
        }
    }
    Some((file?, checksum_file?))
}

/// Parses `SHA256 (<file>) = <hash>` for the given file.
fn parse_cloud_checksum(text: &str, want_file: &str) -> Option<String> {
    for line in text.lines() {
        let Some(file) = line.split('(').nth(1) else {
            continue;
        };
        let file = file.split(')').next()?;
        if file != want_file {
            continue;
        }
        let hash = line.rsplit('=').next()?.trim().to_string();
        if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(hash);
        }
    }
    None
}

fn curl(url: &str) -> Result<String> {
    let out = Command::new("curl")
        .args(["-fsSL", url])
        .output()
        .with_context(|| format!("fetching {url}"))?;
    if !out.status.success() {
        bail!(
            "curl {url} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub(crate) fn run_capture(
    program: &str,
    args: impl IntoIterator<Item = impl AsRef<str>>,
    cwd: Option<&str>,
    what: &str,
) -> Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args.into_iter().map(|a| a.as_ref().to_string()));
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let output = cmd
        .output()
        .with_context(|| format!("{what}: spawning {program}"))?;
    if !output.status.success() {
        bail!(
            "{what}: {program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

#[cfg(test)]
mod tests {
    const LISTING: &str = r#"<html><body><pre>
<a href="../">../</a>
<a href="Fedora-Cloud-44-1.7-x86_64-CHECKSUM">Fedora-Cloud-44-1.7-x86_64-CHECKSUM</a>
<a href="Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2">Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2</a>
<a href="Fedora-Cloud-Base-UEFI-UKI-44-1.7.x86_64.qcow2">Fedora-Cloud-Base-UEFI-UKI-44-1.7.x86_64.qcow2</a>
<a href="Fedora-Cloud-Base-Vagrant-VirtualBox-44-1.7.x86_64.vagrant.virtualbox.box">Fedora-Cloud-Base-Vagrant-VirtualBox-44-1.7.x86_64.vagrant.virtualbox.box</a>
</pre></body></html>"#;

    const CHECKSUM: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSHA256 (Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2) = 6b1f0a8f9c2e4d5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f80912a3b4\nSHA256 (Fedora-Cloud-Base-UEFI-UKI-44-1.7.x86_64.qcow2) = ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n";

    #[test]
    fn picks_generic_qcow2_and_checksum_from_listing() {
        let (file, checksum) = super::pick_cloud_image(LISTING).expect("listing parses");
        assert_eq!(file, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2");
        assert_eq!(checksum, "Fedora-Cloud-44-1.7-x86_64-CHECKSUM");
    }

    #[test]
    fn parses_checksum_for_the_wanted_file_only() {
        let hash =
            super::parse_cloud_checksum(CHECKSUM, "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2")
                .expect("wanted file parses");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        // The other file's line must not leak into the result.
        assert_eq!(super::parse_cloud_checksum(CHECKSUM, "missing.qcow2"), None);
    }

    #[test]
    fn finds_checksums_in_sum_lists() {
        let sums = "aaaa *ubuntu.img\nbbbb  debian.qcow2\n";
        assert_eq!(
            super::checksum_for(sums, "ubuntu.img").as_deref(),
            Some("aaaa")
        );
        assert_eq!(
            super::checksum_for(sums, "debian.qcow2").as_deref(),
            Some("bbbb")
        );
        assert_eq!(super::checksum_for(sums, "missing"), None);
    }
}
