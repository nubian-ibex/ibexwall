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
    /// The path the process was executed with (`sched_process_exec`),
    /// NUL padded; empty when the kernel never saw its exec (a fork that
    /// did not exec, or an entry evicted from the pid map).
    pub exe: [u8; EXE_LEN],
}

/// Bytes kept of the exec path; longer paths are truncated.
pub const EXE_LEN: usize = 128;

/// The ring buffer map name the programs and the loader agree on.
pub const EVENTS_MAP: &str = "IBEXWALL_CONNECTS";

/// Verdicts as the maps store them (wire values, shared by both sides).
pub mod verdict {
    /// Allow (and keep observing).
    pub const ALLOW: u8 = 0;
    /// Fail the call with EPERM.
    pub const BLOCK: u8 = 1;
    /// Mark the flow for the queue (Ask mode; the S6-a spike).
    pub const ASK: u8 = 2;
}

/// One exe rule as the eBPF rules array stores it: a path prefix and the
/// verdict. Fixed size so both sides agree on the layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExeRule {
    /// `verdict::ALLOW`, `BLOCK` or `ASK`; 0 length means the slot is free.
    pub verdict: u8,
    /// Bytes of the prefix actually used.
    pub len: u8,
    /// The executable path prefix, NUL padded.
    pub prefix: [u8; EXE_RULE_PREFIX_LEN],
}

/// Longest executable path prefix a rule may carry.
pub const EXE_RULE_PREFIX_LEN: usize = 96;
/// How many exe rules the array holds (the loop in the hook is bounded).
pub const EXE_RULES_MAX: usize = 16;

impl ExeRule {
    /// The wire form: verdict, len, then the prefix.
    pub fn write_to(&self, out: &mut [u8; EXE_RULE_LEN]) {
        out[0] = self.verdict;
        out[1] = self.len;
        out[2..].copy_from_slice(&self.prefix);
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != EXE_RULE_LEN {
            return None;
        }
        let len = bytes[1] as usize;
        if len > EXE_RULE_PREFIX_LEN {
            return None;
        }
        Some(Self {
            verdict: bytes[0],
            len: bytes[1],
            prefix: bytes[2..].try_into().expect("exe rule sized slice"),
        })
    }

    /// True when `path` starts with this rule's prefix.
    pub fn matches(&self, path: &[u8]) -> bool {
        let len = self.len as usize;
        path.len() >= len && path[..len] == self.prefix[..len]
    }
}

/// The wire length of one exe rule: 1 + 1 + 96.
pub const EXE_RULE_LEN: usize = 2 + EXE_RULE_PREFIX_LEN;

/// The packet mark an Ask flow carries: `ASK_MARK_VALUE` under
/// `ASK_MARK_MASK`, with a 16-bit flow id in the low half. The loader's
/// answer for a refused flow sets `REFUSED_MARK_VALUE`, which nftables
/// rejects. Bits above the mask are left as the application had them.
pub const ASK_MARK_MASK: u32 = 0x00ff_0000;
pub const ASK_MARK_VALUE: u32 = 0x0001_0000;
pub const REFUSED_MARK_VALUE: u32 = 0x0002_0000;
/// The NFQUEUE number of the Ask chain.
pub const ASK_QUEUE: u16 = 4242;
/// The map from a flow id to who made it: pid (4 bytes LE) then cgroup id
/// (8 bytes LE).
pub const ASK_FLOWS_MAP: &str = "IBEXWALL_ASK_FLOWS";
pub const ASK_FLOW_LEN: usize = 12;

/// Name of the verdict maps the loader keeps in sync.
pub const CGROUP_POLICY_MAP: &str = "IBEXWALL_CGROUP_POLICY";
pub const PID_POLICY_MAP: &str = "IBEXWALL_PID_POLICY";
pub const DEFAULTS_MAP: &str = "IBEXWALL_DEFAULTS";
pub const EXE_RULES_MAP: &str = "IBEXWALL_EXE_RULES";

/// Name of the pid-to-exec-path map the connect hook reads.
pub const EXES_MAP: &str = "IBEXWALL_EXES";

/// Where the exe path starts in the wire format.
const EXE_AT: usize = 52;

/// The event wire length: the 52-byte fixed header (`pid 4 + cgroup 8 +
/// comm 16 + family 1 + pad 1 + port 2 + ip4 4 + ip6 16`, padded to a
/// multiple of 4) followed by the exe path.
pub const EVENT_LEN: usize = EXE_AT + EXE_LEN;

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
        out[EXE_AT..].copy_from_slice(&self.exe);
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
            exe: bytes[EXE_AT..].try_into().expect("exe sized slice"),
        })
    }

    /// The exec path the kernel recorded, NUL trimmed; `None` when absent
    /// or not valid UTF-8 (paths are untrusted data, never interpolated).
    pub fn exe_str(&self) -> Option<&str> {
        let end = self.exe.iter().position(|b| *b == 0).unwrap_or(EXE_LEN);
        match core::str::from_utf8(&self.exe[..end]) {
            Ok(text) if !text.is_empty() => Some(text),
            _ => None,
        }
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
        let mut exe = [0u8; EXE_LEN];
        exe[..13].copy_from_slice(b"/usr/bin/curl");
        ConnectEvent {
            pid: 4242,
            cgroup_id: 0x0102_0304_0506_0708,
            comm,
            family: 4,
            port: 443,
            ip4: [9, 9, 9, 9],
            ip6: [0x26, 0x20, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe],
            exe,
        }
    }

    #[test]
    fn round_trips_through_the_wire_format() {
        let event = sample();
        let mut bytes = [0u8; EVENT_LEN];
        event.write_to(&mut bytes);
        assert_eq!(ConnectEvent::parse(&bytes), Some(event));
        assert_eq!(event.comm_str(), "curl");
        assert_eq!(event.exe_str(), Some("/usr/bin/curl"));
    }

    #[test]
    fn an_empty_or_invalid_exe_reads_as_absent() {
        let mut event = sample();
        event.exe = [0; EXE_LEN];
        assert_eq!(event.exe_str(), None);
        event.exe[0] = 0xff;
        assert_eq!(event.exe_str(), None);
        // A path that fills the field has no NUL and still parses.
        event.exe = [b'a'; EXE_LEN];
        assert_eq!(event.exe_str().map(str::len), Some(EXE_LEN));
    }

    #[test]
    fn refuses_records_we_never_write() {
        assert!(ConnectEvent::parse(&[0u8; 8]).is_none());
        assert!(ConnectEvent::parse(&[0u8; 52]).is_none());
        // A corrupt family is preserved as-is: the reader labels it.
        let mut bytes = [0u8; EVENT_LEN];
        bytes[28] = 5;
        assert_eq!(ConnectEvent::parse(&bytes).unwrap().family, 5);
    }

    #[test]
    fn the_wire_length_is_a_multiple_of_four() {
        assert_eq!(EVENT_LEN % 4, 0);
    }

    fn rule(prefix: &str, verdict: u8) -> ExeRule {
        let mut bytes = [0u8; EXE_RULE_PREFIX_LEN];
        bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
        ExeRule {
            verdict,
            len: prefix.len() as u8,
            prefix: bytes,
        }
    }

    #[test]
    fn an_exe_rule_round_trips_and_matches_by_prefix() {
        let r = rule("/usr/bin/curl", verdict::BLOCK);
        let mut wire = [0u8; EXE_RULE_LEN];
        r.write_to(&mut wire);
        assert_eq!(ExeRule::parse(&wire), Some(r));
        assert!(r.matches(b"/usr/bin/curl"));
        assert!(r.matches(b"/usr/bin/curl-wrapper"));
        assert!(!r.matches(b"/usr/bin/cur"));
        assert!(!r.matches(b"/opt/usr/bin/curl"));
        // A free slot (length 0) is the caller's to skip; it would match all.
        assert!(rule("", verdict::ALLOW).matches(b"/anything"));
    }

    #[test]
    fn a_corrupt_exe_rule_is_refused() {
        assert!(ExeRule::parse(&[0u8; 10]).is_none());
        let mut wire = [0u8; EXE_RULE_LEN];
        wire[1] = (EXE_RULE_PREFIX_LEN + 1) as u8;
        assert!(ExeRule::parse(&wire).is_none());
    }
}
