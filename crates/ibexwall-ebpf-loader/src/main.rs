// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Loads the connect monitor and prints what it sees. Spike form: a
//! standalone binary; the M2 milestones turn this into the monitor service
//! with rollups. Requires `CAP_BPF`/`CAP_PERFMON` (or root) and cgroup v2.

use std::path::{Path, PathBuf};

use std::os::fd::AsFd as _;

use anyhow::{Context, Result, bail};
use aya::EbpfLoader;
use aya::maps::RingBuf;
use aya::programs::{CgroupSockAddr, TracePoint};
use ibexwall_identity::{Identity, PackageManager, classify_cgroup, hash_file, package_owner};
use ibexwall_net_common::{ConnectEvent, EVENTS_MAP};

/// Where the built program lives, in order (env override, install dir,
/// workspace build output).
pub fn elf_candidates() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(path) = std::env::var("IBEXWALL_EBPF") {
        paths.push(path.into());
    }
    paths.push("/usr/lib/ibexwall/ebpf/ibexwall-ebpf.o".into());
    paths.push("target/bpf/ibexwall-ebpf.o".into());
    paths
}

/// Loads and attaches both programs to the cgroup v2 root; returns the
/// loaded `Ebpf` with the programs pinned by link.
/// Returns the loaded programs and, when the exec tracepoint could not be
/// attached, why: the monitor still works, only without the kernel's copy
/// of the exec path (short-lived processes then rely on `/proc`).
pub fn load_and_attach(elf: &Path, cgroup_root: &Path) -> Result<(aya::Ebpf, Option<String>)> {
    let mut ebpf = EbpfLoader::new()
        .load_file(elf)
        .with_context(|| format!("loading {}", elf.display()))?;
    // Attach through a directory fd, at the cgroup v2 root: every
    // process's connect() passes through it.
    let cgroup_dir = std::fs::File::open(cgroup_root)
        .with_context(|| format!("opening {}", cgroup_root.display()))?;
    let exec: &mut TracePoint = ebpf
        .program_mut("ibexwall_exec")
        .context("ibexwall_exec not found in the ELF")?
        .try_into()
        .context("ibexwall_exec has the wrong type")?;
    exec.load().context("loading ibexwall_exec")?;
    // Some kernels (Debian's perf_event_paranoid=3) only allow
    // perf_event_open with CAP_SYS_ADMIN, which the unit deliberately
    // does not hold. Degrade instead of failing: connections are still
    // seen and attributed, only exits-before-/proc lose their path.
    let degraded = exec
        .attach("sched", "sched_process_exec")
        .err()
        .map(|error| format!("kernel-side exec capture is off ({error})"));
    for program in ["ibexwall_connect4", "ibexwall_connect6"] {
        let attached: &mut CgroupSockAddr = ebpf
            .program_mut(program)
            .with_context(|| format!("{program} not found in the ELF"))?
            .try_into()
            .context("program has the wrong type")?;
        attached
            .load()
            .with_context(|| format!("loading {program}"))?;
        attached
            .attach(&cgroup_dir, aya::programs::CgroupAttachMode::Single)
            .with_context(|| format!("attaching {program} to {}", cgroup_root.display()))?;
    }
    Ok((ebpf, degraded))
}

/// One resolved event: what the kernel saw plus who was responsible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    pub event: ConnectEvent,
    /// `/proc/<pid>/exe`, best effort (the process may already be gone).
    pub exe: Option<String>,
    /// `/proc/<pid>/cgroup`, best effort.
    pub cgroup: Option<String>,
}

/// Resolves the process behind an event. Best effort by design: the
/// monitor observes, it never keeps processes alive.
pub fn resolve(event: ConnectEvent) -> Sighting {
    let base = Path::new("/proc").join(event.pid.to_string());
    // /proc is authoritative while the process lives (it resolves symlinks
    // and relative exec paths); the kernel's copy covers the ones that
    // exited before we looked.
    let exe = std::fs::read_link(base.join("exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .or_else(|| event.exe_str().map(str::to_owned));
    let cgroup = std::fs::read_to_string(base.join("cgroup"))
        .ok()
        .map(|text| text.trim().to_string());
    Sighting { event, exe, cgroup }
}

/// Maps a cgroup id (the inode of its directory in cgroupfs) back to its
/// path, for processes that exited before `/proc/<pid>/cgroup` was read.
/// Rebuilt by walking the tree on a miss, at most once per `MIN_RESCAN`.
pub struct CgroupIndex {
    root: PathBuf,
    paths: std::collections::HashMap<u64, String>,
    scanned: Option<std::time::Instant>,
}

/// A miss rescans, but never more often than this.
const MIN_RESCAN: std::time::Duration = std::time::Duration::from_secs(1);
/// Bounds the walk on machines with an unusual number of cgroups.
const MAX_CGROUPS: usize = 100_000;

impl CgroupIndex {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            paths: std::collections::HashMap::new(),
            scanned: None,
        }
    }

    /// `0::/path`, the form `/proc/<pid>/cgroup` uses for cgroup v2.
    pub fn lookup(&mut self, id: u64) -> Option<String> {
        if !self.paths.contains_key(&id) {
            let due = self.scanned.is_none_or(|at| at.elapsed() >= MIN_RESCAN);
            if due {
                self.rescan();
            }
        }
        self.paths.get(&id).map(|path| format!("0::{path}"))
    }

    fn rescan(&mut self) {
        use std::os::unix::fs::MetadataExt as _;
        self.scanned = Some(std::time::Instant::now());
        self.paths.clear();
        let mut stack = vec![(self.root.clone(), String::new())];
        while let Some((dir, relative)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                if !meta.is_dir() || self.paths.len() >= MAX_CGROUPS {
                    continue;
                }
                let child = format!("{relative}/{}", entry.file_name().to_string_lossy());
                self.paths.insert(meta.ino(), child.clone());
                stack.push((entry.path(), child));
            }
        }
        // The root itself is the cgroup whose path is "/".
        if let Ok(meta) = std::fs::metadata(&self.root) {
            self.paths.insert(meta.ino(), "/".into());
        }
    }
}

/// Who and what is behind an exe: hash and owning package, cached per path
/// because package-manager queries are slow and a program connects often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeFacts {
    pub hash: Option<String>,
    pub package: Option<String>,
}

#[derive(Default)]
pub struct Enricher {
    manager: Option<PackageManager>,
    detected: bool,
    cache: std::collections::HashMap<String, ExeFacts>,
}

impl Enricher {
    pub fn identity(sighting: &Sighting) -> Identity {
        classify_cgroup(sighting.cgroup.as_deref().unwrap_or(""))
    }

    pub fn facts(&mut self, exe: &str) -> ExeFacts {
        if !self.detected {
            self.manager = PackageManager::detect(Path::new("/"));
            self.detected = true;
        }
        if let Some(known) = self.cache.get(exe) {
            return known.clone();
        }
        let path = Path::new(exe);
        let facts = ExeFacts {
            hash: hash_file(path).ok(),
            package: self
                .manager
                .and_then(|manager| package_owner(manager, path, &run_argv)),
        };
        // Bounded: a runaway of distinct paths must not grow without end.
        if self.cache.len() >= 4096 {
            self.cache.clear();
        }
        self.cache.insert(exe.to_string(), facts.clone());
        facts
    }
}

/// Runs an allowlisted binary with an argv (never a shell) and returns
/// stdout when it exits successfully.
fn run_argv(binary: &str, args: &[String]) -> Option<String> {
    let output = std::process::Command::new(binary)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Runs until `stop`, printing one JSON object per event on stdout.
pub fn run(mut ebpf: aya::Ebpf, on_event: &mut dyn FnMut(Sighting)) -> Result<()> {
    let map = ebpf
        .take_map(EVENTS_MAP)
        .with_context(|| format!("map {EVENTS_MAP} not found"))?;
    let mut ring = RingBuf::try_from(map).context("opening the ring buffer")?;
    let mut dropped = 0u64;
    loop {
        // Drain first, then sleep on the map's fd: an event wakes the
        // thread at once, so short-lived processes are still resolvable
        // from /proc when their identity is looked up.
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            match ConnectEvent::parse(bytes) {
                Some(event) => on_event(resolve(event)),
                None => dropped += 1,
            }
        }
        if dropped > 0 {
            eprintln!("ibexwall-ebpf-loader: {dropped} malformed records skipped");
            dropped = 0;
        }
        let fd = ring.as_fd();
        let mut poller = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 500_000_000,
        };
        let _ = rustix::event::poll(&mut poller, Some(&timeout));
    }
}

fn main() {
    if let Err(error) = amain() {
        eprintln!("ibexwall-ebpf-loader: {error:#}");
        std::process::exit(1);
    }
}

fn amain() -> Result<()> {
    let candidates = elf_candidates();
    let elf = candidates
        .iter()
        .find(|path| path.exists())
        .with_context(|| {
            format!(
                "no eBPF program found (looked in {}); build it with `cargo xtask ebpf` or set IBEXWALL_EBPF",
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        bail!("cgroup v2 is required (no controllers file at /sys/fs/cgroup)");
    }
    let (ebpf, degraded) = load_and_attach(elf, Path::new("/sys/fs/cgroup"))?;
    if let Some(reason) = &degraded {
        eprintln!("ibexwall-ebpf-loader: degraded: {reason}");
    }
    eprintln!(
        "ibexwall-ebpf-loader: monitoring connect() (elf: {})",
        elf.display()
    );
    let mut enricher = Enricher::default();
    let mut cgroups = CgroupIndex::new(PathBuf::from("/sys/fs/cgroup"));
    // With --socket the lines go to the core; without it, to stdout (the
    // VM spike and manual runs).
    let mut sink = Sink::open(std::env::args().skip(1).collect())?;
    if let Some(reason) = degraded {
        sink.send(&serde_json::json!({ "meta": "degraded", "reason": reason }).to_string());
    }
    run(ebpf, &mut |mut sighting| {
        if sighting.cgroup.is_none() {
            sighting.cgroup = cgroups.lookup(sighting.event.cgroup_id);
        }
        let identity = Enricher::identity(&sighting);
        let facts = sighting.exe.as_deref().map(|exe| enricher.facts(exe));
        let Sighting { event, exe, cgroup } = &sighting;
        let dst = if event.family == 4 {
            std::net::Ipv4Addr::from(event.ip4).to_string()
        } else {
            std::net::Ipv6Addr::from(event.ip6).to_string()
        };
        sink.send(
            &serde_json::json!({
                "pid": event.pid,
                "comm": event.comm_str(),
                "exe": exe,
                "exe_kernel": event.exe_str(),
                "kind": identity.kind,
                "id": identity.id,
                "exe_hash": facts.as_ref().and_then(|f| f.hash.as_deref()),
                "package": facts.as_ref().and_then(|f| f.package.as_deref()),
                "cgroup": cgroup,
                "dst": dst,
                "port": event.port,
                "family": event.family,
            })
            .to_string(),
        );
    })
}

/// Where the JSON lines go: stdout, or the core's monitor socket.
enum Sink {
    Stdout,
    Socket(std::os::unix::net::UnixStream),
}

impl Sink {
    fn open(args: Vec<String>) -> Result<Self> {
        match args.as_slice() {
            [] => Ok(Self::Stdout),
            [flag, path] if flag == "--socket" => {
                // The core may still be starting: wait for it, a while.
                let mut last = None;
                for _ in 0..60 {
                    match std::os::unix::net::UnixStream::connect(path) {
                        Ok(stream) => {
                            // A core that stops reading must not wedge us:
                            // the write fails, we exit, systemd restarts us.
                            stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
                            return Ok(Self::Socket(stream));
                        }
                        Err(error) => last = Some(error),
                    }
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                bail!(
                    "cannot reach the core at {path}: {}",
                    last.map(|e| e.to_string()).unwrap_or_default()
                )
            }
            _ => bail!("usage: ibexwall-ebpf-loader [--socket PATH]"),
        }
    }

    fn send(&mut self, line: &str) {
        match self {
            Self::Stdout => println!("{line}"),
            Self::Socket(stream) => {
                use std::io::Write as _;
                let mut bytes = Vec::with_capacity(line.len() + 1);
                bytes.extend_from_slice(line.as_bytes());
                bytes.push(b'\n');
                if let Err(error) = stream.write_all(&bytes) {
                    eprintln!("ibexwall-ebpf-loader: lost the core: {error}");
                    std::process::exit(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(pid: u32, comm: &str, family: u8) -> ConnectEvent {
        let mut name = [0u8; 16];
        name[..comm.len()].copy_from_slice(comm.as_bytes());
        ConnectEvent {
            pid,
            cgroup_id: 7,
            comm: name,
            family,
            port: 443,
            ip4: [9, 9, 9, 9],
            ip6: [0; 16],
            exe: [0; ibexwall_net_common::EXE_LEN],
        }
    }

    #[test]
    fn the_cgroup_index_finds_a_path_by_directory_inode() {
        use std::os::unix::fs::MetadataExt as _;
        let root = std::env::temp_dir().join(format!("ibexwall-cg-{}", std::process::id()));
        let leaf = root.join("user.slice/session-6.scope");
        std::fs::create_dir_all(&leaf).unwrap();
        let id = std::fs::metadata(&leaf).unwrap().ino();

        let mut index = CgroupIndex::new(root.clone());
        assert_eq!(
            index.lookup(id).as_deref(),
            Some("0::/user.slice/session-6.scope")
        );
        // Unknown ids stay unknown.
        assert_eq!(index.lookup(u64::MAX), None);
        let root_id = std::fs::metadata(&root).unwrap().ino();
        assert_eq!(index.lookup(root_id).as_deref(), Some("0::/"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn resolve_survives_a_missing_process() {
        // Pid 0xdeadbeef does not exist; nothing may panic.
        let sighting = resolve(event(0xdead_beef, "gone", 4));
        assert_eq!(sighting.exe, None);
        assert_eq!(sighting.cgroup, None);
        assert_eq!(sighting.event.comm_str(), "gone");
    }

    #[test]
    fn resolve_reads_the_current_process() {
        let sighting = resolve(event(std::process::id(), "self", 4));
        // The test binary name uses underscores, the installed one dashes.
        let exe = sighting.exe.unwrap_or_default().replace('-', "_");
        assert!(exe.contains("ibexwall_ebpf_loader"), "{exe}");
        assert!(sighting.cgroup.is_some());
    }
}
