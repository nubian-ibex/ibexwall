// SPDX-FileCopyrightText: 2026 Nubian Ibex and IbexWall contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! A sliding-window limiter with an injected clock, so it is tested without
//! sleeping.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct Limiter {
    per_window: u32,
    window: Duration,
    hits: VecDeque<Instant>,
}

impl Limiter {
    pub fn new(per_window: u32, window: Duration) -> Self {
        Self {
            per_window,
            window,
            hits: VecDeque::new(),
        }
    }

    /// True when the call may go ahead (and counts it).
    pub fn allow(&mut self, now: Instant) -> bool {
        while self
            .hits
            .front()
            .is_some_and(|at| now.duration_since(*at) >= self.window)
        {
            self.hits.pop_front();
        }
        if self.hits.len() as u32 >= self.per_window {
            return false;
        }
        self.hits.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_over_the_limit_are_refused_until_the_window_passes() {
        let start = Instant::now();
        let mut limiter = Limiter::new(3, Duration::from_secs(60));
        assert!(limiter.allow(start));
        assert!(limiter.allow(start + Duration::from_secs(1)));
        assert!(limiter.allow(start + Duration::from_secs(2)));
        assert!(!limiter.allow(start + Duration::from_secs(3)));
        // All three old calls have left the window by 62s: room for three.
        for _ in 0..3 {
            assert!(limiter.allow(start + Duration::from_secs(62)));
        }
        assert!(!limiter.allow(start + Duration::from_secs(62)));
    }

    #[test]
    fn a_refused_call_does_not_extend_the_wait() {
        let start = Instant::now();
        let mut limiter = Limiter::new(1, Duration::from_secs(10));
        assert!(limiter.allow(start));
        for second in 1..10 {
            assert!(!limiter.allow(start + Duration::from_secs(second)));
        }
        assert!(limiter.allow(start + Duration::from_secs(10)));
    }
}
