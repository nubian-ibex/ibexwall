// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! The connect monitor: one eBPF program per address family at the
//! cgroup/connect hooks. Monitor only: it records and always allows.

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext as _,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{cgroup_sock_addr, map, tracepoint},
    maps::{LruHashMap, RingBuf},
    programs::{SockAddrContext, TracePointContext},
};
use ibexwall_net_common::{ConnectEvent, EVENT_LEN, EXE_LEN, verdict};

// The map name is "IBEXWALL_CONNECTS" in the macro below (it needs a
// literal) and EVENTS_MAP on the loader side; keep them in sync.

#[map(name = "IBEXWALL_CONNECTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 14, 0);

/// pid to the path it was executed with. LRU, so exited processes age out
/// without an exit hook; a pid reused by a new exec is simply overwritten.
#[map(name = "IBEXWALL_EXES")]
static mut EXES: LruHashMap<u32, [u8; EXE_LEN]> = LruHashMap::with_max_entries(8192, 0);

/// Exe rules as a fixed array: the hook walks it (no map iteration in
/// eBPF) and compares the path the exec tracepoint recorded for this pid.
/// This closes the first-connect race a pid-keyed map would have.
#[map(name = "IBEXWALL_EXE_RULES")]
static mut EXE_RULES: aya_ebpf::maps::Array<[u8; ibexwall_net_common::EXE_RULE_LEN]> =
    aya_ebpf::maps::Array::with_max_entries(EXE_RULES_MAX_U32, 0);

/// The array bound, as the hook's loop needs it.
const EXE_RULES_MAX_U32: u32 = ibexwall_net_common::EXE_RULES_MAX as u32;

/// The exe rules as plain bytes, read once per call.
fn exe_rule_at(slot: u32) -> Option<ibexwall_net_common::ExeRule> {
    // SAFETY: static map access; the reference lives for the program.
    let rules = unsafe { &*core::ptr::addr_of!(EXE_RULES) };
    let bytes = rules.get(slot)?;
    ibexwall_net_common::ExeRule::parse(bytes.as_slice())
}

/// The verdict for this call: the cgroup's rule, else the first exe rule
/// whose prefix matches the path the exec tracepoint recorded for this
/// pid, else the default. An absent entry is allow (fail open).
fn verdict_for(pid: u32, cgroup_id: u64) -> u8 {
    // SAFETY: static map access; the key is a value we just built.
    let cgroups = unsafe { &*core::ptr::addr_of!(CGROUP_POLICY) };
    // SAFETY: map lookup with an owned key.
    if let Some(rule) = unsafe { cgroups.get(&cgroup_id) } {
        return *rule;
    }
    // SAFETY: static map access.
    let exes = unsafe { &*core::ptr::addr_of!(EXES) };
    // SAFETY: map lookup with an owned key.
    if let Some(path) = unsafe { exes.get(&pid) } {
        for slot in 0..EXE_RULES_MAX_U32 {
            if let Some(rule) = exe_rule_at(slot)
                && rule.len != 0
                && rule.matches(path.as_slice())
            {
                return rule.verdict();
            }
        }
    }
    // SAFETY: static map access.
    let defaults = unsafe { &*core::ptr::addr_of!(DEFAULTS) };
    defaults.get(0).copied().unwrap_or(verdict::ALLOW)
}

/// Verdict per cgroup id (Flatpak scopes, containers, services): stable
/// for the life of the cgroup, so no race at process start.
#[map(name = "IBEXWALL_CGROUP_POLICY")]
static mut CGROUP_POLICY: LruHashMap<u64, u8> = LruHashMap::with_max_entries(4096, 0);

/// The profile default, one entry: allow unless a profile says otherwise.
#[map(name = "IBEXWALL_DEFAULTS")]
static mut DEFAULTS: aya_ebpf::maps::Array<u8> =
    aya_ebpf::maps::Array::with_max_entries(1, 0);

/// Offset of the `__data_loc` filename in `sched_process_exec`, after the
/// 8-byte common header (stable: see the tracepoint's `format` file).
const EXEC_FILENAME_AT: usize = 8;

#[tracepoint]
pub fn ibexwall_exec(ctx: TracePointContext) -> u32 {
    let _ = remember_exec(&ctx);
    0
}

fn remember_exec(ctx: &TracePointContext) -> Result<(), i32> {
    // SAFETY: reads the u32 __data_loc word the kernel placed at a fixed
    // offset of the tracepoint record.
    let data_loc: u32 = unsafe { ctx.read_at(EXEC_FILENAME_AT) }?;
    // The low 16 bits are the string's offset from the record start.
    let offset = (data_loc & 0xffff) as usize;
    let mut path = [0u8; EXE_LEN];
    // SAFETY: the offset is bounded by the 16-bit mask and the read is
    // checked by the helper; the destination is our stack buffer.
    unsafe {
        let src = (ctx.as_ptr() as *const u8).add(offset);
        bpf_probe_read_kernel_str_bytes(src, &mut path)?;
    }
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let exes = unsafe { &*core::ptr::addr_of!(EXES) };
    exes.insert(&pid, &path, 0)
}

/// A cgroup/connect program lets the call proceed when it returns 1 and
/// fails it with EPERM when it returns 0. This monitor only observes, so
/// it returns 1 on every path, including when recording fails.
const ALLOW: i32 = 1;

#[cgroup_sock_addr(connect4)]
pub fn ibexwall_connect4(ctx: SockAddrContext) -> i32 {
    decide(&ctx, 4)
}

#[cgroup_sock_addr(connect6)]
pub fn ibexwall_connect6(ctx: SockAddrContext) -> i32 {
    decide(&ctx, 6)
}

/// UDP without connect() (DNS, QUIC) goes through sendmsg: the same
/// verdict, no event per datagram (that would flood the ring buffer).
#[cgroup_sock_addr(sendmsg4)]
pub fn ibexwall_sendmsg4(_ctx: SockAddrContext) -> i32 {
    decide_only()
}

#[cgroup_sock_addr(sendmsg6)]
pub fn ibexwall_sendmsg6(_ctx: SockAddrContext) -> i32 {
    decide_only()
}

/// Flow id to the process that made it, for the Ask queue: the packet
/// carries only the mark, and the mark carries the id.
#[map(name = "IBEXWALL_ASK_FLOWS")]
static mut ASK_FLOWS: LruHashMap<u32, [u8; ibexwall_net_common::ASK_FLOW_LEN]> =
    LruHashMap::with_max_entries(4096, 0);

const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;

/// Marks the socket so nftables queues its first packet, and records who
/// it is. Best effort: a failure leaves the connection unmarked, which
/// means allowed (fail open).
fn mark_for_ask(ctx: &SockAddrContext, pid: u32, cgroup_id: u64) {
    use ibexwall_net_common::{ASK_MARK_VALUE};
    let sock = ctx.sock_addr as *mut core::ffi::c_void;
    let mut current: u32 = 0;
    // SAFETY: helper calls with a stack buffer of the stated length.
    unsafe {
        aya_ebpf::helpers::generated::bpf_getsockopt(
            sock,
            SOL_SOCKET,
            SO_MARK,
            &mut current as *mut u32 as *mut core::ffi::c_void,
            4,
        );
    }
    // SAFETY: plain helper call.
    let id = unsafe { aya_ebpf::helpers::generated::bpf_get_prandom_u32() } & 0xffff;
    let mut flow = [0u8; ibexwall_net_common::ASK_FLOW_LEN];
    flow[..4].copy_from_slice(&pid.to_le_bytes());
    flow[4..].copy_from_slice(&cgroup_id.to_le_bytes());
    // SAFETY: static map access with owned key and value.
    let flows = unsafe { &*core::ptr::addr_of!(ASK_FLOWS) };
    if flows.insert(&id, &flow, 0).is_err() {
        return;
    }
    let mut marked: u32 = (current & 0xff00_0000) | ASK_MARK_VALUE | id;
    // SAFETY: helper call with a stack buffer of the stated length.
    unsafe {
        aya_ebpf::helpers::generated::bpf_setsockopt(
            sock,
            SOL_SOCKET,
            SO_MARK,
            &mut marked as *mut u32 as *mut core::ffi::c_void,
            4,
        );
    }
}

fn decide_only() -> i32 {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if verdict_for(pid, cgroup_id) == verdict::BLOCK {
        return 0;
    }
    ALLOW
}

/// Observes, then decides: a block verdict fails the call (0); everything
/// else, including a recording failure, lets it through (1). Ask is not a
/// verdict the connect hook can act on alone; until the queue lands it
/// behaves like allow.
fn decide(ctx: &SockAddrContext, family: u8) -> i32 {
    let _ = record(ctx, family);
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    match verdict_for(pid, cgroup_id) {
        verdict::BLOCK => return 0,
        verdict::ASK => mark_for_ask(ctx, pid, cgroup_id),
        _ => {}
    }
    ALLOW
}

/// Raw kernel-side fields, exactly as the hook provides them: the IP and
/// port byte orders are converted in userspace, in one place.
fn record(ctx: &SockAddrContext, family: u8) -> Result<(), i32> {
    let addr = unsafe { &*ctx.sock_addr };
    // The address fields hold the sockaddr's own bytes in memory; on the
    // little-endian BPF target to_ne_bytes reproduces them exactly (the
    // VM spike checks asymmetric addresses, which catch a byte swap).
    // Each program may only read the fields its attach type allows:
    // connect4 must not touch user_ip6 and connect6 must not touch
    // user_ip4, or the verifier rejects the load. `family` is a constant
    // here, so the other branch compiles away entirely.
    let (ip4, ip6) = if family == 4 {
        (addr.user_ip4.to_ne_bytes(), [0u8; 16])
    } else {
        let mut bytes = [0u8; 16];
        for (word, slot) in addr.user_ip6.iter().zip(bytes.chunks_exact_mut(4)) {
            slot.copy_from_slice(&word.to_ne_bytes());
        }
        ([0, 0, 0, 0], bytes)
    };
    let mut event = ConnectEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        comm: [0; 16],
        family,
        // The sockaddr's 16-bit port sits in the low half of this field
        // in network byte order; from_be swaps it by value.
        port: u16::from_be((addr.user_port & 0xffff) as u16),
        ip4,
        ip6,
        exe: [0; EXE_LEN],
    };
    let pid = event.pid;
    let exes = unsafe { &*core::ptr::addr_of!(EXES) };
    if let Some(path) = exes.get_ptr(&pid) {
        // SAFETY: the pointer comes from the map lookup and is valid for
        // the program's duration; the value is exactly EXE_LEN bytes.
        event.exe = unsafe { *path };
    }
    event.comm = bpf_get_current_comm().unwrap_or([0; 16]);
    let mut bytes = [0u8; EVENT_LEN];
    event.write_to(&mut bytes);
    // Best effort by design: a full buffer drops the event, never blocks
    // the connection.
    let ring = unsafe { &mut *core::ptr::addr_of_mut!(EVENTS) };
    if let Some(mut entry) = ring.reserve_bytes(EVENT_LEN, 0) {
        entry.copy_from_slice(&bytes);
        entry.submit(0);
    }
    Ok(())
}

#[cfg(not(target_arch = "bpf"))]
fn main() {}

#[panic_handler]
#[cfg(target_arch = "bpf")]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
