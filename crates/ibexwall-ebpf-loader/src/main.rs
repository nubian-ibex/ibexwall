// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Loads the connect monitor and prints what it sees. Spike form: a
//! standalone binary; the M2 milestones turn this into the monitor service
//! with rollups. Requires `CAP_BPF`/`CAP_PERFMON` (or root) and cgroup v2.

mod ask;

use std::path::{Path, PathBuf};

use std::os::fd::AsFd as _;

use anyhow::{Context, Result, bail};
use aya::EbpfLoader;
use aya::maps::RingBuf;
use aya::programs::{CgroupSockAddr, TracePoint};
use ibexwall_identity::{Identity, PackageManager, classify_cgroup, hash_file, package_owner};
use ibexwall_net_common::{ASK_FLOWS_MAP, CGROUP_POLICY_MAP, DEFAULTS_MAP, EXE_RULES_MAP};
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
    for program in [
        "ibexwall_connect4",
        "ibexwall_connect6",
        "ibexwall_sendmsg4",
        "ibexwall_sendmsg6",
    ] {
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
pub fn resolve(event: ConnectEvent, cgroups: &mut CgroupIndex) -> Sighting {
    let base = Path::new("/proc").join(event.pid.to_string());
    // /proc is authoritative while the process lives (it resolves symlinks
    // and relative exec paths); the kernel's copy covers the ones that
    // exited before we looked.
    let exe = std::fs::read_link(base.join("exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
        .or_else(|| event.exe_str().map(str::to_owned));
    // The index answers from memory; /proc costs a syscall per event, so
    // it is only the fallback for a cgroup the index has not seen yet.
    let cgroup = cgroups.lookup(event.cgroup_id).or_else(|| {
        std::fs::read_to_string(base.join("cgroup"))
            .ok()
            .map(|text| text.trim().to_string())
    });
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

    /// Every (cgroup id, path) known to the index, rescanned first.
    pub fn cgroup_ids(&mut self) -> Vec<(u64, String)> {
        self.rescan();
        self.paths
            .iter()
            .map(|(id, path)| (*id, format!("/{path}")))
            .collect()
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

/// One rule: what to match and what to do. A cgroup rule covers Flatpak
/// scopes, containers and services (by prefix, or by a text the path
/// contains); an exe rule covers programs and is matched by the hook
/// itself against the exec path. A rule with no matcher sets the default.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Rule {
    /// Matches the `0::`-stripped cgroup path of the connecting process.
    pub cgroup_prefix: Option<String>,
    /// Matches any cgroup whose path contains this text.
    pub cgroup_contains: Option<String>,
    /// The executable path, whole.
    pub exe_exact: Option<String>,
    /// A prefix of the executable path.
    pub exe_prefix: Option<String>,
    /// `allow`, `block` or `ask`.
    pub verdict: String,
}

/// What the core pushes: the rules, then the default for everyone else.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Policy {
    pub rules: Vec<Rule>,
    pub default: String,
    /// How long an Ask flow waits for the user (default 30).
    #[serde(default)]
    pub ask_timeout_secs: Option<u64>,
    /// What an unanswered Ask flow gets: `allow` (default) or `block`.
    #[serde(default)]
    pub ask_fallback: Option<String>,
}

fn verdict_of(text: &str) -> Option<u8> {
    match text {
        "allow" => Some(ibexwall_net_common::verdict::ALLOW),
        "block" => Some(ibexwall_net_common::verdict::BLOCK),
        "ask" => Some(ibexwall_net_common::verdict::ASK),
        _ => None,
    }
}

impl Policy {
    /// A rules file (the spike's form): a list, a rule without a matcher
    /// being the default.
    pub fn load(path: &Path) -> Result<Self> {
        let rules: Vec<Rule> = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        let mut default = "allow".to_string();
        let mut kept = Vec::new();
        for rule in rules {
            if rule.cgroup_prefix.is_none()
                && rule.cgroup_contains.is_none()
                && rule.exe_exact.is_none()
                && rule.exe_prefix.is_none()
            {
                default = rule.verdict;
            } else {
                kept.push(rule);
            }
        }
        let policy = Self {
            rules: kept,
            default,
            ask_timeout_secs: None,
            ask_fallback: None,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Nothing reaches the kernel unless this passes.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            verdict_of(&self.default).is_some(),
            "unknown default `{}`",
            self.default
        );
        let mut exe = 0;
        for rule in &self.rules {
            anyhow::ensure!(
                verdict_of(&rule.verdict).is_some(),
                "unknown verdict `{}` (allow, block or ask)",
                rule.verdict
            );
            if let Some(text) = rule.exe_exact.as_ref().or(rule.exe_prefix.as_ref()) {
                exe += 1;
                anyhow::ensure!(
                    text.len() <= ibexwall_net_common::EXE_RULE_PREFIX_LEN,
                    "exe rule `{text}` is longer than {} bytes",
                    ibexwall_net_common::EXE_RULE_PREFIX_LEN
                );
            }
        }
        anyhow::ensure!(
            exe <= ibexwall_net_common::EXE_RULES_MAX,
            "at most {} exe rules are supported",
            ibexwall_net_common::EXE_RULES_MAX
        );
        if let Some(fallback) = &self.ask_fallback {
            anyhow::ensure!(
                ask::Decision::parse(fallback).is_some(),
                "unknown ask fallback `{fallback}`"
            );
        }
        Ok(())
    }
}

type Slots = aya::maps::Array<aya::maps::MapData, [u8; ibexwall_net_common::EXE_RULE_LEN]>;

/// Owns the verdict maps and keeps them equal to the current policy. The
/// cgroup half is by id, so it is reapplied as cgroups appear; a scope
/// created after the policy has at most one rescan interval of grace
/// (documented in the F6 plan).
pub struct Enforcer {
    cgroups: aya::maps::HashMap<aya::maps::MapData, u64, u8>,
    exe: Slots,
    defaults: aya::maps::Array<aya::maps::MapData, u8>,
    index: CgroupIndex,
    inserted: std::collections::HashMap<u64, u8>,
    policy: Option<Policy>,
}

impl Enforcer {
    pub fn take(ebpf: &mut aya::Ebpf) -> Result<Self> {
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .with_context(|| format!("map {name} not found"))
        };
        Ok(Self {
            cgroups: aya::maps::HashMap::try_from(take(CGROUP_POLICY_MAP)?)?,
            exe: aya::maps::Array::try_from(take(EXE_RULES_MAP)?)?,
            defaults: aya::maps::Array::try_from(take(DEFAULTS_MAP)?)?,
            index: CgroupIndex::new(PathBuf::from("/sys/fs/cgroup")),
            inserted: std::collections::HashMap::new(),
            policy: None,
        })
    }

    /// Replaces the policy. An invalid one is refused and the previous
    /// stays in force.
    pub fn set(&mut self, policy: Policy) -> Result<()> {
        policy.validate()?;
        self.policy = Some(policy);
        self.sync()
    }

    /// Brings the maps in line with the policy and the cgroups that exist.
    pub fn sync(&mut self) -> Result<()> {
        let Some(policy) = self.policy.clone() else {
            return Ok(());
        };
        let ids = self.index.cgroup_ids();
        let mut wanted: std::collections::HashMap<u64, u8> = std::collections::HashMap::new();
        let mut exe_rules: Vec<ibexwall_net_common::ExeRule> = Vec::new();
        for rule in &policy.rules {
            let verdict = verdict_of(&rule.verdict).expect("validated");
            if rule.cgroup_prefix.is_some() || rule.cgroup_contains.is_some() {
                for (id, path) in &ids {
                    let hit = rule
                        .cgroup_prefix
                        .as_ref()
                        .is_some_and(|p| path.starts_with(p.as_str()))
                        || rule
                            .cgroup_contains
                            .as_ref()
                            .is_some_and(|c| path.contains(c.as_str()));
                    if hit {
                        wanted.entry(*id).or_insert(verdict);
                    }
                }
            } else if let Some(text) = rule.exe_exact.as_ref().or(rule.exe_prefix.as_ref()) {
                let mut bytes = [0u8; ibexwall_net_common::EXE_RULE_PREFIX_LEN];
                bytes[..text.len()].copy_from_slice(text.as_bytes());
                let flag = if rule.exe_exact.is_some() {
                    ibexwall_net_common::EXE_RULE_EXACT
                } else {
                    0
                };
                exe_rules.push(ibexwall_net_common::ExeRule {
                    verdict: verdict | flag,
                    len: text.len() as u8,
                    prefix: bytes,
                });
            }
        }
        for (id, verdict) in &wanted {
            if self.inserted.get(id) != Some(verdict) {
                self.cgroups.insert(id, verdict, 0)?;
            }
        }
        let stale: Vec<u64> = self
            .inserted
            .keys()
            .filter(|id| !wanted.contains_key(id))
            .copied()
            .collect();
        for id in stale {
            let _ = self.cgroups.remove(&id);
        }
        self.inserted = wanted;
        // Every slot is written: a rule removed from the policy must not
        // linger, so unused slots are zeroed (length 0 means free).
        for slot in 0..ibexwall_net_common::EXE_RULES_MAX {
            let mut bytes = [0u8; ibexwall_net_common::EXE_RULE_LEN];
            if let Some(rule) = exe_rules.get(slot) {
                rule.write_to(&mut bytes);
            }
            self.exe.set(slot as u32, &bytes, 0)?;
        }
        let default = verdict_of(&policy.default).expect("validated");
        self.defaults.set(0, &default, 0)?;
        Ok(())
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
pub fn run(
    mut ebpf: aya::Ebpf,
    cgroups: &mut CgroupIndex,
    on_event: &mut dyn FnMut(Sighting),
) -> Result<()> {
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
                Some(event) => on_event(resolve(event, cgroups)),
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
    let (mut ebpf, degraded) = load_and_attach(elf, Path::new("/sys/fs/cgroup"))?;
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut enforcer = Enforcer::take(&mut ebpf)?;
    if let Some(at) = args.iter().position(|a| a == "--rules") {
        enforcer.set(Policy::load(Path::new(&args[at + 1]))?)?;
    }
    let value_of = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|at| args.get(at + 1))
            .cloned()
    };
    // The spike's local answer: every Ask flow gets one decision after a
    // delay, with no core involved (the VM scenario for the queue).
    let local_answer = value_of("--ask-default").map(|decision| {
        let delay = value_of("--ask-delay-ms")
            .and_then(|ms| ms.parse().ok())
            .unwrap_or(0);
        (
            ask::Decision::parse(&decision).unwrap_or(ask::Decision::Allow),
            std::time::Duration::from_millis(delay),
        )
    });
    let disable_ask = args.iter().any(|a| a == "--ask-disabled");
    let sink = std::sync::Arc::new(std::sync::Mutex::new(Sink::open(args)?));
    // The handle the answers come back through; set once the queue is up.
    let ask_handle: std::sync::Arc<std::sync::OnceLock<std::sync::Arc<ask::Ask>>> =
        std::sync::Arc::default();
    if !disable_ask {
        let map = ebpf
            .take_map(ASK_FLOWS_MAP)
            .with_context(|| format!("map {ASK_FLOWS_MAP} not found"))?;
        let flows = aya::maps::HashMap::try_from(map)?;
        let to_core = std::sync::Arc::clone(&sink);
        let handle = std::sync::Arc::clone(&ask_handle);
        let describer = std::sync::Mutex::new((
            Enricher::default(),
            CgroupIndex::new(PathBuf::from("/sys/fs/cgroup")),
        ));
        let started = ask::start(flows, move |id, flow, destination| {
            if let Some((decision, delay)) = local_answer {
                let handle = std::sync::Arc::clone(&handle);
                std::thread::spawn(move || {
                    std::thread::sleep(delay);
                    if let Some(ask) = handle.get() {
                        ask.answer(id, decision);
                        eprintln!(
                            "{}",
                            serde_json::json!({ "ask": {
                                "flow": id,
                                "decision": format!("{decision:?}").to_lowercase(),
                                "held_ms": delay.as_millis() as u64,
                            }})
                        );
                    }
                });
                return;
            }
            let Some(destination) = destination else {
                return;
            };
            let (family, ip4, ip6) = match destination.address {
                std::net::IpAddr::V4(ip) => (4, ip.octets(), [0; 16]),
                std::net::IpAddr::V6(ip) => (6, [0; 4], ip.octets()),
            };
            let event = ConnectEvent {
                pid: flow.pid,
                cgroup_id: flow.cgroup_id,
                comm: [0; 16],
                family,
                port: destination.port,
                ip4,
                ip6,
                exe: [0; ibexwall_net_common::EXE_LEN],
            };
            let mut guard = describer.lock().unwrap();
            let (enricher, cgroups) = &mut *guard;
            let sighting = resolve(event, cgroups);
            let mut line = describe(&sighting, enricher);
            line["ask_id"] = id.into();
            let message = serde_json::json!({ "ask": line }).to_string();
            to_core.lock().unwrap().send(&message);
        });
        match started {
            Ok(ask) => {
                let _ = ask_handle.set(ask);
            }
            // Without the queue Ask cannot hold anything: the nft rule's
            // bypass accepts, and the network stays open.
            Err(error) => eprintln!("ibexwall-ebpf-loader: Ask unavailable: {error:#}"),
        }
    }
    // The enforcer runs on its own thread: it applies each policy the core
    // pushes and, every couple of seconds, covers cgroups created since.
    let (policies, incoming) = std::sync::mpsc::channel::<Policy>();
    std::thread::spawn(move || {
        loop {
            match incoming.recv_timeout(std::time::Duration::from_secs(2)) {
                Ok(policy) => {
                    if let Err(error) = enforcer.set(policy) {
                        eprintln!("ibexwall-ebpf-loader: policy refused: {error:#}");
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Err(error) = enforcer.sync() {
                        eprintln!("ibexwall-ebpf-loader: policy sync failed: {error:#}");
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
    let reader = sink.lock().unwrap().reader();
    if let Some(reader) = reader {
        let handle = std::sync::Arc::clone(&ask_handle);
        std::thread::spawn(move || read_core(reader, policies, handle));
    }
    if let Some(reason) = degraded {
        sink.lock()
            .unwrap()
            .send(&serde_json::json!({ "meta": "degraded", "reason": reason }).to_string());
    }
    run(ebpf, &mut cgroups, &mut |sighting| {
        let line = describe(&sighting, &mut enricher).to_string();
        sink.lock().unwrap().send(&line);
    })
}

/// The JSON the core reads for a connection (and for an Ask request).
fn describe(sighting: &Sighting, enricher: &mut Enricher) -> serde_json::Value {
    let identity = Enricher::identity(sighting);
    let facts = sighting.exe.as_deref().map(|exe| enricher.facts(exe));
    let Sighting { event, exe, cgroup } = sighting;
    let dst = if event.family == 4 {
        std::net::Ipv4Addr::from(event.ip4).to_string()
    } else {
        std::net::Ipv6Addr::from(event.ip6).to_string()
    };
    serde_json::json!({
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
}

/// Reads what the core pushes: `{"policy": {...}}` and
/// `{"answer": {"id": N, "decision": "allow"|"block"}}`. A line that does
/// not parse is ignored; the previous policy stays in force.
fn read_core(
    stream: std::os::unix::net::UnixStream,
    policies: std::sync::mpsc::Sender<Policy>,
    ask_handle: std::sync::Arc<std::sync::OnceLock<std::sync::Arc<ask::Ask>>>,
) {
    use std::io::BufRead as _;
    #[derive(serde::Deserialize)]
    struct Answer {
        id: u16,
        decision: String,
    }
    #[derive(serde::Deserialize)]
    struct Message {
        policy: Option<Policy>,
        answer: Option<Answer>,
    }
    for line in std::io::BufReader::new(stream).lines() {
        let Ok(line) = line else { break };
        let message = match serde_json::from_str::<Message>(&line) {
            Ok(message) => message,
            Err(error) => {
                eprintln!("ibexwall-ebpf-loader: unreadable message: {error}");
                continue;
            }
        };
        if let Some(policy) = message.policy {
            if let Some(ask) = ask_handle.get() {
                let fallback = policy
                    .ask_fallback
                    .as_deref()
                    .and_then(ask::Decision::parse)
                    .unwrap_or(ask::Decision::Allow);
                let timeout = policy.ask_timeout_secs.unwrap_or(30).clamp(1, 600);
                ask.configure(std::time::Duration::from_secs(timeout), fallback);
            }
            if policies.send(policy).is_err() {
                break;
            }
        }
        if let (Some(answer), Some(ask)) = (message.answer, ask_handle.get())
            && let Some(decision) = ask::Decision::parse(&answer.decision)
        {
            ask.answer(answer.id, decision);
        }
    }
    // The core is gone. Exiting detaches the programs and closes the queue,
    // so the network opens now instead of when the next write fails; systemd
    // brings the unit back and the core's policy returns with it.
    eprintln!("ibexwall-ebpf-loader: lost the core: connection closed");
    std::process::exit(1);
}

/// Where the JSON lines go: stdout, or the core's monitor socket.
enum Sink {
    Stdout,
    Socket(std::os::unix::net::UnixStream),
}

impl Sink {
    fn open(args: Vec<String>) -> Result<Self> {
        // Options in any order: --socket PATH and --rules FILE (the rules
        // themselves are consumed by main; only --socket matters here).
        let mut socket: Option<&String> = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--socket" => {
                    socket = args.get(index + 1);
                    index += 2;
                }
                "--rules" | "--ask-default" | "--ask-delay-ms" => index += 2,
                "--ask-disabled" => index += 1,
                other => {
                    bail!("unknown argument `{other}` (usage: --socket PATH, --rules FILE)")
                }
            }
        }
        let Some(path) = socket else {
            return Ok(Self::Stdout);
        };
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

    /// A second handle on the core's socket, to read what it pushes.
    fn reader(&self) -> Option<std::os::unix::net::UnixStream> {
        match self {
            Self::Stdout => None,
            Self::Socket(stream) => stream.try_clone().ok(),
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
        let mut cgroups = CgroupIndex::new(PathBuf::from("/nonexistent"));
        let sighting = resolve(event(0xdead_beef, "gone", 4), &mut cgroups);
        assert_eq!(sighting.exe, None);
        assert_eq!(sighting.cgroup, None);
        assert_eq!(sighting.event.comm_str(), "gone");
    }

    #[test]
    fn resolve_reads_the_current_process() {
        let mut cgroups = CgroupIndex::new(PathBuf::from("/nonexistent"));
        let sighting = resolve(event(std::process::id(), "self", 4), &mut cgroups);
        // The test binary name uses underscores, the installed one dashes.
        let exe = sighting.exe.unwrap_or_default().replace('-', "_");
        assert!(exe.contains("ibexwall_ebpf_loader"), "{exe}");
        assert!(sighting.cgroup.is_some());
    }
}
