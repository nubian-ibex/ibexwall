// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Caller identity on a varlink connection (ADR-0025): `SO_PEERCRED`
//! gives pid/uid without a race; the daemon reads the peer's start time
//! from /proc so authorization never trusts a bare, reusable PID.

use std::io;

use tokio::net::UnixStream;

/// Effective uid of this process (no libc, no unsafe).
pub fn current_uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Identity of a connected caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub uid: u32,
    pub pid: u32,
    pub start_time: u64,
}

impl Identity {
    /// Audit-log actor string (`user:<uid>`).
    pub fn actor(&self) -> String {
        format!("user:{}", self.uid)
    }
}

/// Reads uid/pid of the connecting peer via `SO_PEERCRED`.
pub fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, u32)> {
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    let uid = cred.uid.as_raw();
    let pid = cred.pid.as_raw_pid();
    Ok((uid, pid.unsigned_abs()))
}

/// Reads field 22 (start time in clock ticks) of `/proc/<pid>/stat`.
pub fn proc_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_stat_start_time(&stat)
        .ok_or_else(|| io::Error::other(format!("cannot parse /proc/{pid}/stat")))
}

/// Parses the start time out of a stat line; exposed for tests.
pub fn parse_proc_stat_start_time(stat: &str) -> Option<u64> {
    // Layout: pid (comm) state ppid ... starttime is field 22 overall.
    // `comm` may contain spaces and parentheses, so split after the
    // LAST ')'.
    let after = stat.rsplit(')').next()?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // Fields before the ')' are 1 (pid) and 2 (comm); the remainder
    // starts at field 3 (state).
    // field 22 => fields[22 - 3]
    let raw = *fields.get(19)?;
    raw.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_start_time_from_a_sample_stat_line() {
        // Fields after `(comm)`: 3 state, ..., 19 nice, 20 num_threads,
        // 21 itrealvalue, 22 starttime (= 99887766).
        let line = "4242 (some (weird) name) R 1 4242 4242 0 -1 4194560 123 0 0 0 1 2 3 4 5 20 0 1 99887766 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
        assert_eq!(parse_proc_stat_start_time(line), Some(99_887_766));
    }

    #[test]
    fn rejects_short_stat_lines() {
        assert_eq!(parse_proc_stat_start_time("1 (init) S 1"), None);
    }

    #[test]
    fn reads_the_start_time_of_this_process() {
        let pid = std::process::id();
        assert!(proc_start_time(pid).unwrap() > 0);
    }
}
