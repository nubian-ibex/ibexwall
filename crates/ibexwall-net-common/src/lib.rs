// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Types shared between the eBPF programs (`ibexwall-ebpf`, `no_std`) and
//! the loader (`ibexwall-ebpf-loader`). `no_std` and dependency free so
//! both sides can use it; the wire format is explicit little-endian bytes,
//! never a raw struct copy, so the eBPF target's layout cannot matter.

#![no_std]
#![forbid(unsafe_code)]

/// One outbound connection attempt, observed at the cgroup/connect hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectEvent {
    /// The process id visible in `/proc` (tgid in kernel terms).
    pub pid: u32,
    /// The cgroup the process was in (`bpf_get_current_cgroup_id`).
    pub cgroup_id: u64,
    /// `comm`, truncated to 16 bytes by the kernel.
    pub comm: [u8; 16],
    /// 4 or 6.
    pub family: u8,
    /// Destination port in host order.
    pub port: u16,
    /// Destination IPv4 in network order (family 4).
    pub ip4: [u8; 4],
    /// Destination IPv6 in network order (family 6).
    pub ip6: [u8; 16],
}

/// The ring buffer map name the programs and the loader agree on.
pub const EVENTS_MAP: &str = "IBEXWALL_CONNECTS";

/// The event wire length. `pid 4 + cgroup 8 + comm 16 + family 1 +
/// port 2 + ip4 4 + ip6 16 = 51`; padded to a multiple of 4.
pub const EVENT_LEN: usize = 52;

impl ConnectEvent {
    /// Serializes to the wire format (little-endian scalars).
    pub fn write_to(&self, out: &mut [u8; EVENT_LEN]) {
        out[0..4].copy_from_slice(&self.pid.to_le_bytes());
        out[4..12].copy_from_slice(&self.cgroup_id.to_le_bytes());
        out[12..28].copy_from_slice(&self.comm);
        out[28] = self.family;
        out[30..32].copy_from_slice(&self.port.to_le_bytes());
        out[32..36].copy_from_slice(&self.ip4);
        out[36..52].copy_from_slice(&self.ip6);
    }

    /// Parses one event; `None` when the record is not exactly
    /// [`EVENT_LEN`] bytes (a length we never write, so it cannot be ours).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != EVENT_LEN {
            return None;
        }
        let le32 = |range: &[u8]| u32::from_le_bytes(range.try_into().expect("four byte slice"));
        let le16 = |range: &[u8]| u16::from_le_bytes(range.try_into().expect("two byte slice"));
        Some(Self {
            pid: le32(&bytes[0..4]),
            cgroup_id: u64::from_le_bytes(bytes[4..12].try_into().expect("eight byte slice")),
            comm: bytes[12..28].try_into().expect("sixteen byte slice"),
            family: bytes[28],
            port: le16(&bytes[30..32]),
            ip4: bytes[32..36].try_into().expect("four byte slice"),
            ip6: bytes[36..52].try_into().expect("sixteen byte slice"),
        })
    }

    /// The readable process name (comm, NUL trimmed).
    pub fn comm_str(&self) -> &str {
        let end = self.comm.iter().position(|b| *b == 0).unwrap_or(16);
        core::str::from_utf8(&self.comm[..end]).unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ConnectEvent {
        let mut comm = [0u8; 16];
        comm[..5].copy_from_slice(b"curl\0");
        ConnectEvent {
            pid: 4242,
            cgroup_id: 0x0102_0304_0506_0708,
            comm,
            family: 4,
            port: 443,
            ip4: [9, 9, 9, 9],
            ip6: [0x26, 0x20, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe],
        }
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let event = sample();
        let mut bytes = [0u8; EVENT_LEN];
        event.write_to(&mut bytes);
        assert_eq!(ConnectEvent::parse(&bytes), Some(event));
        assert_eq!(event.comm_str(), "curl");
    }

    #[test]
    fn refuses_records_we_never_write() {
        assert!(ConnectEvent::parse(&[0u8; 8]).is_none());
        assert!(ConnectEvent::parse(&[0u8; 64]).is_none());
        // A corrupt family is preserved as-is: the reader labels it.
        let mut bytes = [0u8; EVENT_LEN];
        bytes[28] = 5;
        assert_eq!(ConnectEvent::parse(&bytes).unwrap().family, 5);
    }

    #[test]
    fn the_wire_length_is_a_multiple_of_four() {
        assert_eq!(EVENT_LEN % 4, 0);
    }
}
