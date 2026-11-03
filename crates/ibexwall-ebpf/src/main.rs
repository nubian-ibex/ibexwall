// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-2.0-only OR MIT

//! The connect monitor: one eBPF program per address family at the
//! cgroup/connect hooks. Monitor only: it records and always allows.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{cgroup_sock_addr, map},
    maps::RingBuf,
    programs::SockAddrContext,
};
use ibexwall_net_common::{ConnectEvent, EVENT_LEN};

// The map name is "IBEXWALL_CONNECTS" in the macro below (it needs a
// literal) and EVENTS_MAP on the loader side; keep them in sync.

#[map(name = "IBEXWALL_CONNECTS")]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(1 << 14, 0);

#[cgroup_sock_addr(connect4)]
pub fn ibexwall_connect4(ctx: SockAddrContext) -> i32 {
    match record(&ctx, 4) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

#[cgroup_sock_addr(connect6)]
pub fn ibexwall_connect6(ctx: SockAddrContext) -> i32 {
    match record(&ctx, 6) {
        Ok(()) => 0,
        Err(code) => code,
    }
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
    };
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
