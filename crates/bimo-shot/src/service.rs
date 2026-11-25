//! The shot service: rate limiter + persistent capture session.
//!
//! One `ShotService` owns one `RateLimiter` and one `CaptureSession`
//! for the lifetime of the eye. A shot request goes:
//! rate limiter (§6, hard refusal) → persistent session (warm) → on
//! session failure, ONE restart (cold) and one retry → error.
//!
//! The service is the only entry point the eye uses for shots. It
//! serialises requests with an internal mutex: concurrent callers are
//! refused (`"shot busy"`) rather than queued, because a queued shot
//! is a stale shot (the screen has moved on).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use crate::capture::{CaptureSession, ShotInfo};
use crate::rate_limiter::{Acquire, RateLimiter};

/// Outcome of one `request_shot` call.
#[derive(Debug)]
pub enum ShotOutcome {
    /// A frame was captured and written to disk.
    Taken(ShotInfo),
    /// Refused by the §6 rate limiter. The eye logs this as
    /// `shot.rate_limited` (with `rejected`, the running total).
    RateLimited { rejected_total: u64 },
    /// Capture failed (no frame, session error). The eye logs this as
    /// `shot.failed` — a failure is data, never silence.
    Failed { reason: String },
}

/// Where shot files live, relative to the eye's data dir.
pub const SHOTS_DIR: &str = "shots";

/// The shot service (Windows only — capture needs Graphics Capture).
pub struct ShotService {
    limiter: RateLimiter,
    session: Option<CaptureSession>,
    data_dir: PathBuf,
    /// Serialises requests (see module docs).
    lock: Mutex<()>,
    /// Monotonic shot counter for file names (`shot-000001.jpg`).
    counter: u64,
}

impl ShotService {
    pub fn new(data_dir: PathBuf) -> Self {
        ShotService {
            limiter: RateLimiter::new(),
            session: None,
            data_dir,
            lock: Mutex::new(()),
            counter: 0,
        }
    }

    /// Request one shot for `reason` (recorded in the log event).
    /// `reason` is a short machine-readable tag (`"on-demand"`,
    /// `"alert:<what>"`); it is NOT a window title and never carries
    /// screen content.
    pub fn request_shot(&mut self, reason: &str) -> ShotOutcome {
        let _guard = match self.lock.lock() {
            Ok(g) => g,
            Err(_) => {
                return ShotOutcome::Failed {
                    reason: "shot service lock poisoned".to_string(),
                }
            }
        };
        let _ = reason; // kept for the caller's event; the service
        // itself does not log (the eye owns the log).
        match self.limiter.try_acquire(Instant::now()) {
            Acquire::Refused => {
                return ShotOutcome::RateLimited {
                    rejected_total: self.limiter.refused_total,
                }
            }
            Acquire::Allowed => {}
        }
        self.counter += 1;
        let out_path = self.shot_path(self.counter);
        if let Err(e) = std::fs::create_dir_all(self.data_dir.join(SHOTS_DIR)) {
            return ShotOutcome::Failed {
                reason: format!("cannot create shots dir: {e}"),
            };
        }
        // First attempt on the persistent session (warm). A fresh
        // service has no session yet: the first shot opens it (cold).
        if self.session.is_none() {
            self.session = Some(CaptureSession::start_new());
        }
        match self.try_session(&out_path) {
            Ok(info) => ShotOutcome::Taken(info),
            Err(first_err) => {
                // ONE restart (cold) + ONE retry — the draft's rule.
                // A second failure is a real failure, not a retry loop.
                eprintln!("[bimo-shot] session shot failed ({first_err}); restarting session once");
                if let Some(old) = self.session.take() {
                    old.stop();
                }
                self.session = Some(CaptureSession::start_new());
                match self.try_session(&out_path) {
                    Ok(info) => ShotOutcome::Taken(info),
                    Err(second_err) => ShotOutcome::Failed {
                        reason: format!("warm: {first_err}; cold retry: {second_err}"),
                    },
                }
            }
        }
    }

    fn try_session(&self, out_path: &Path) -> Result<ShotInfo, String> {
        match &self.session {
            Some(s) => s.request(out_path),
            None => Err("no capture session".to_string()),
        }
    }

    fn shot_path(&self, n: u64) -> PathBuf {
        self.data_dir
            .join(SHOTS_DIR)
            .join(format!("shot-{n:06}.jpg"))
    }

    /// Stop the session (eye shutdown). Best-effort: see
    /// `CaptureSession::stop` — the thread may be abandoned.
    pub fn stop(&mut self) {
        if let Some(s) = self.session.take() {
            s.stop();
        }
    }

    /// Test seam: how many shots this service has accepted (the file
    /// counter). The rate limiter's own counts are in `refused_total`.
    pub fn shots_requested(&self) -> u64 {
        self.counter
    }
}
