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

/// What the Ask queue does with a held packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

/// The spike policy: one answer for every held flow after a delay (the
/// real answer comes from the user through the core).
#[derive(Debug, Clone, Copy)]
pub struct AskPolicy {
    pub decision: Decision,
    pub delay: std::time::Duration,
}

/// The queue mark of a flow that was refused: nftables rejects it.
fn refused_mark(mark: u32) -> u32 {
    (mark & 0xff00_0000) | ibexwall_net_common::REFUSED_MARK_VALUE | (mark & 0xffff)
}

/// Listens on the Ask queue: each packet waits `policy.delay` in its own
/// thread (so many flows wait at once), then is accepted, or accepted with
/// the refused mark. A packet whose flow id is unknown is accepted at
/// once: when in doubt, the network stays open.
pub fn run_ask(
    flows: aya::maps::HashMap<aya::maps::MapData, u32, [u8; ibexwall_net_common::ASK_FLOW_LEN]>,
    policy: AskPolicy,
) -> Result<()> {
    let queue = std::sync::Arc::new(
        ibexwall_nfq::Queue::open(ibexwall_net_common::ASK_QUEUE)
            .context("binding the Ask queue (needs CAP_NET_ADMIN)")?,
    );
    eprintln!(
        "ibexwall-ebpf-loader: Ask queue {} bound",
        ibexwall_net_common::ASK_QUEUE
    );
    loop {
        for packet in queue.recv(std::time::Duration::from_millis(500))? {
            let id = packet.mark & 0xffff;
            let known = flows.get(&id, 0).ok();
            let destination = packet.destination();
            let queue = std::sync::Arc::clone(&queue);
            std::thread::spawn(move || {
                let Some(flow) = known else {
                    let _ = queue.verdict(packet.id, ibexwall_nfq::Verdict::Accept, None);
                    return;
                };
                let pid = u32::from_le_bytes(flow[..4].try_into().expect("four bytes"));
                std::thread::sleep(policy.delay);
                let mark = (policy.decision == Decision::Block).then(|| refused_mark(packet.mark));
                let _ = queue.verdict(packet.id, ibexwall_nfq::Verdict::Accept, mark);
                eprintln!(
                    "{}",
                    serde_json::json!({ "ask": {
                        "pid": pid,
                        "dst": destination.as_ref().map(|d| d.address.to_string()),
                        "port": destination.as_ref().map(|d| d.port),
                        "decision": if policy.decision == Decision::Allow { "allow" } else { "block" },
                        "held_ms": policy.delay.as_millis() as u64,
                    }})
                );
            });
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
    // The Ask queue: a thread of its own, unless disabled (the queue then
    // has no listener and the kernel accepts: fail open).
    if !args.iter().any(|a| a == "--ask-disabled") && args.iter().any(|a| a == "--ask-default") {
        let value = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|at| args.get(at + 1))
                .cloned()
        };
        let decision = match value("--ask-default").as_deref() {
            Some("block") => Decision::Block,
            _ => Decision::Allow,
        };
        let delay = value("--ask-delay-ms")
            .and_then(|ms| ms.parse().ok())
            .unwrap_or(0);
        let policy = AskPolicy {
            decision,
            delay: std::time::Duration::from_millis(delay),
        };
        let map = ebpf
            .take_map(ASK_FLOWS_MAP)
            .with_context(|| format!("map {ASK_FLOWS_MAP} not found"))?;
        let flows = aya::maps::HashMap::try_from(map)?;
        std::thread::spawn(move || {
            if let Err(error) = run_ask(flows, policy) {
                eprintln!("ibexwall-ebpf-loader: ask queue stopped: {error:#}");
            }
        });
    }
    let mut sink = Sink::open(args)?;
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
    if let Some(reader) = sink.reader() {
        std::thread::spawn(move || read_policies(reader, policies));
    }
    if let Some(reason) = degraded {
        sink.send(&serde_json::json!({ "meta": "degraded", "reason": reason }).to_string());
    }
    run(ebpf, &mut cgroups, &mut |sighting| {
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

/// Reads `{"policy": {...}}` lines from the core. A line that does not
/// parse is ignored; the previous policy stays in force.
fn read_policies(stream: std::os::unix::net::UnixStream, out: std::sync::mpsc::Sender<Policy>) {
    use std::io::BufRead as _;
    #[derive(serde::Deserialize)]
    struct Message {
        policy: Policy,
    }
    for line in std::io::BufReader::new(stream).lines() {
        let Ok(line) = line else { return };
        match serde_json::from_str::<Message>(&line) {
            Ok(message) => {
                if out.send(message.policy).is_err() {
                    return;
                }
            }
            Err(error) => eprintln!("ibexwall-ebpf-loader: unreadable message: {error}"),
        }
    }
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
