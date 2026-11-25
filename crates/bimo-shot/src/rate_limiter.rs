//! Rate limiter for screen shots — enforces §6 of the shot spec
//! (`track-a-unit2-eye-shot-spike.md`) literally, in code.
//!
//! §6 (frozen in cycle 26, council condition "blocks a named harm"):
//! shots are on-demand / on-alert only; expected rate is at most one
//! shot per minute; the hard maximum is 1/second sustained, with a
//! burst of 5 shots in 10 seconds. Above the maximum the request is
//! REFUSED explicitly and logged (`shot.rate_limited`) — never queued
//! silently.
//!
//! Enforced rule (one rolling window): at most **5 accepted shots
//! in any rolling 10-second window**. The sustained rate then
//! converges to 0.5 shots/second (a burst of 5, then the window
//! refills) — inside the §6 ceiling of 1/second sustained — and the
//! draft's acceptance test holds exactly: 7 requests in one second
//! execute 5 and refuse 2; one request per minute for 5 minutes
//! executes all 5 with no refusal.
//!
//! Platform-independent (std only): the limiter owns no clock. The
//! caller passes `Instant`s, so unit tests drive it with exact
//! offsets instead of sleeping. The production caller passes
//! `Instant::now()`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Burst allowance: at most this many accepted shots in any rolling
/// window of `WINDOW`.
pub const BURST_MAX: usize = 5;
/// Rolling window for the burst allowance (§6: "burst of 5 in 10 s").
pub const WINDOW: Duration = Duration::from_secs(10);

/// Outcome of one `try_acquire` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acquire {
    /// The shot may proceed.
    Allowed,
    /// The shot is refused: the §6 ceiling is hit. The caller must
    /// log a `shot.rate_limited` event (never queue silently).
    Refused,
}

/// Rolling-window rate limiter for shots (§6).
#[derive(Debug)]
pub struct RateLimiter {
    /// Accepted-shot timestamps inside the current rolling window,
    /// oldest first. Entries older than `WINDOW` are dropped lazily
    /// on each call, so memory stays bounded (at most `BURST_MAX`).
    accepted: VecDeque<Instant>,
    /// Total refusals since creation (for the `shot.rate_limited`
    /// event's `rejected` counter and for tests).
    pub refused_total: u64,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            accepted: VecDeque::new(),
            refused_total: 0,
        }
    }

    /// Try to acquire permission for one shot at `now`.
    /// Pure w.r.t. the clock: the same sequence of instants always
    /// gives the same sequence of outcomes.
    pub fn try_acquire(&mut self, now: Instant) -> Acquire {
        // Drop accepted shots that fell out of the rolling window.
        // `now - WINDOW` cannot underflow here: `Instant` arithmetic
        // saturates on subtraction of a larger duration in practice,
        // but guard anyway — a window edge is never worth a panic.
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        while let Some(&t) = self.accepted.front() {
            if t <= cutoff {
                self.accepted.pop_front();
            } else {
                break;
            }
        }
        if self.accepted.len() < BURST_MAX {
            self.accepted.push_back(now);
            Acquire::Allowed
        } else {
            self.refused_total += 1;
            Acquire::Refused
        }
    }

    /// Accepted shots currently inside the rolling window (test seam).
    pub fn accepted_in_window(&self) -> usize {
        self.accepted.len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    /// Draft acceptance test 1: 7 requests in one second execute 5
    /// and refuse 2.
    #[test]
    fn seven_in_one_second_executes_five_refuses_two() {
        let mut lim = RateLimiter::new();
        let start = t0();
        let mut allowed = 0;
        let mut refused = 0;
        for i in 0..7 {
            let now = start + Duration::from_millis(i * 100);
            match lim.try_acquire(now) {
                Acquire::Allowed => allowed += 1,
                Acquire::Refused => refused += 1,
            }
        }
        assert_eq!(allowed, 5, "burst of 5 in 10 s");
        assert_eq!(refused, 2);
        assert_eq!(lim.refused_total, 2);
    }

    /// Draft acceptance test 2: one request per minute for 5 minutes
    /// executes all 5 with no refusal.
    #[test]
    fn one_per_minute_for_five_minutes_all_allowed() {
        let mut lim = RateLimiter::new();
        let start = t0();
        for i in 0..5 {
            let now = start + Duration::from_secs(60 * i);
            assert_eq!(
                lim.try_acquire(now),
                Acquire::Allowed,
                "minute {i} must be allowed"
            );
        }
        assert_eq!(lim.refused_total, 0);
    }

    /// The window rolls: after 10 s the burst allowance is back.
    #[test]
    fn window_rolls_after_ten_seconds() {
        let mut lim = RateLimiter::new();
        let start = t0();
        for _ in 0..5 {
            assert_eq!(lim.try_acquire(start), Acquire::Allowed);
        }
        assert_eq!(lim.try_acquire(start), Acquire::Refused);
        // 10 s + 1 ms later the first five are out of the window.
        let later = start + WINDOW + Duration::from_millis(1);
        assert_eq!(lim.try_acquire(later), Acquire::Allowed);
        assert_eq!(lim.accepted_in_window(), 1);
    }

    /// Sustained 1/second never passes: the 5-per-10-s rolling cap
    /// converges to 0.5/s (a burst of 5, then the window refills) —
    /// inside the §6 ceiling of 1/s sustained. The test pins that
    /// fact so a later "optimisation" cannot silently raise the
    /// ceiling: 30 requests at 1/s yield 5 + 5 + 5 = 15 accepted.
    #[test]
    fn sustained_rate_capped_below_one_per_second() {
        let mut lim = RateLimiter::new();
        let start = t0();
        let mut allowed = 0;
        // One request per second for 30 seconds.
        for i in 0..30 {
            if lim.try_acquire(start + Duration::from_secs(i)) == Acquire::Allowed {
                allowed += 1;
            }
        }
        // Bursts at t=0..4, t=10..14, t=20..24 — 5 each.
        assert_eq!(allowed, 15, "sustained rate must stay at 0.5/s");
    }
}
