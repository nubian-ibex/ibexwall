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
pub fn load_and_attach(elf: &Path, cgroup_root: &Path) -> Result<aya::Ebpf> {
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
    exec.attach("sched", "sched_process_exec")
        .context("attaching ibexwall_exec")?;
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
    Ok(ebpf)
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
    let ebpf = load_and_attach(elf, Path::new("/sys/fs/cgroup"))?;
    eprintln!(
        "ibexwall-ebpf-loader: monitoring connect() (elf: {})",
        elf.display()
    );
    run(ebpf, &mut |sighting| {
        let Sighting { event, exe, cgroup } = &sighting;
        let dst = if event.family == 4 {
            std::net::Ipv4Addr::from(event.ip4).to_string()
        } else {
            std::net::Ipv6Addr::from(event.ip6).to_string()
        };
        println!(
            "{}",
            serde_json::json!({
                "pid": event.pid,
                "comm": event.comm_str(),
                "exe": exe,
                "exe_kernel": event.exe_str(),
                "cgroup": cgroup,
                "dst": dst,
                "port": event.port,
                "family": event.family,
            })
        );
    })
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
