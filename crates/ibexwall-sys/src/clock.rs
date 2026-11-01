// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Clock seam: the change engine and audit chain depend on time, so
//! tests drive a fake clock. RFC 3339 formatting is implemented locally
//! (no chrono dependency) using the civil-from-days algorithm.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn unix_now(&self) -> i64;
    /// Current time as `YYYY-MM-DDTHH:MM:SSZ`.
    fn rfc3339_now(&self) -> String {
        format_rfc3339(self.unix_now())
    }
}

#[derive(Debug, Default)]
pub struct RealClock;

impl Clock for RealClock {
    fn unix_now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

#[derive(Debug, Default)]
pub struct FakeClock {
    now: Mutex<i64>,
}

impl FakeClock {
    pub fn new(start: i64) -> Self {
        Self {
            now: Mutex::new(start),
        }
    }

    pub fn advance(&self, seconds: i64) {
        *self.now.lock().unwrap() += seconds;
    }

    pub fn set(&self, unix: i64) {
        *self.now.lock().unwrap() = unix;
    }
}

impl Clock for FakeClock {
    fn unix_now(&self) -> i64 {
        *self.now.lock().unwrap()
    }
}

/// Formats Unix seconds as UTC RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
/// Days-from-civil inverse (Howard Hinnant's algorithm).
pub fn format_rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs_of_day = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Converts days since 1970-01-01 into (year, month, day).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_timestamps() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2026-11-01T12:00:00Z (verified via calendar.timegm).
        assert_eq!(format_rfc3339(1_793_534_400), "2026-11-01T12:00:00Z");
        // Leap day: 2024-02-29T00:00:00Z.
        assert_eq!(format_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn fake_clock_advances() {
        let clock = FakeClock::new(1_793_534_400);
        assert_eq!(clock.rfc3339_now(), "2026-11-01T12:00:00Z");
        clock.advance(90);
        assert_eq!(clock.rfc3339_now(), "2026-11-01T12:01:30Z");
    }
}
