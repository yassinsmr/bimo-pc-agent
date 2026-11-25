//! bimo-shot — screen shots for the Eye (Track A Unit 2, shot
//! integration, cycle 28).
//!
//! - `rate_limiter`: §6 enforcement, platform-independent (unit-tested
//!   on Linux).
//! - `capture` + `service` (Windows only): one persistent Graphics
//!   Capture session, JPEG quality 80, max width 1920, one frame per
//!   request, rate-limited. The session is persistent by council
//!   decision (cycle 27): the measured warm cost (13.75 ms/shot)
//!   holds only for that pattern.
//!
//! The crate never touches the log: it returns `ShotOutcome`s and the
//! eye (`bimo-eye`, feature `eye-shots`) turns them into `shot.taken`
//! / `shot.rate_limited` / `shot.failed` events in its own encrypted,
//! hash-chained JSONL. No window titles ever leave this crate — a shot
//! file contains pixels, the event carries only the file name, size
//! and cost numbers.

pub mod rate_limiter;

#[cfg(windows)]
pub mod capture;
#[cfg(windows)]
pub mod service;

pub use rate_limiter::{Acquire, RateLimiter, BURST_MAX, WINDOW};
