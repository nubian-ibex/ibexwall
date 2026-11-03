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
use ibexwall_net_common::{ConnectEvent, EVENT_LEN, EXE_LEN};

// The map name is "IBEXWALL_CONNECTS" in the macro below (it needs a
// literal) and EVENTS_MAP on the loader side; keep them in sync.

#[map(name = "IBEXWALL_CONNECTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 14, 0);

/// pid to the path it was executed with. LRU, so exited processes age out
/// without an exit hook; a pid reused by a new exec is simply overwritten.
#[map(name = "IBEXWALL_EXES")]
static mut EXES: LruHashMap<u32, [u8; EXE_LEN]> = LruHashMap::with_max_entries(8192, 0);

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
    let _ = record(&ctx, 4);
    ALLOW
}

#[cgroup_sock_addr(connect6)]
pub fn ibexwall_connect6(ctx: SockAddrContext) -> i32 {
    let _ = record(&ctx, 6);
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
