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
use std::time::{Duration, Instant, SystemTime};

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
/// Max age of a stored shot file (cycle 31): 7 days.
pub const SHOTS_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Max total size of the shots dir (cycle 31): 500 MB.
pub const SHOTS_MAX_BYTES: u64 = 500 * 1024 * 1024;

/// Prune the shots dir (cycle 31): delete files older than
/// `max_age`, then while the total exceeds `max_bytes` delete the
/// oldest first. Only `shot-*` files are touched. `now` is a
/// parameter so unit tests are deterministic. Returns
/// (files removed, bytes freed).
pub fn prune_shots(dir: &Path, max_age: Duration, max_bytes: u64, now: SystemTime) -> (u64, u64) {
    let mut files: Vec<(PathBuf, SystemTime, u64)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !(name.starts_with("shot-")
                && (name.ends_with(".jpg") || name.ends_with(".jpg.dpapi")))
            {
                continue;
            }
            if let Ok(m) = e.metadata() {
                files.push((
                    p,
                    m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    m.len(),
                ));
            }
        }
    }
    // Oldest first (mtime, then name for determinism).
    files.sort_by(|a, b| (a.1, a.0.clone()).cmp(&(b.1, b.0.clone())));
    let cutoff = now.checked_sub(max_age).unwrap_or(SystemTime::UNIX_EPOCH);
    let mut removed = 0u64;
    let mut freed = 0u64;
    let mut total: u64 = files.iter().map(|f| f.2).sum();
    let mut keep: Vec<(PathBuf, SystemTime, u64)> = Vec::new();
    for f in files {
        if f.1 < cutoff {
            if std::fs::remove_file(&f.0).is_ok() {
                removed += 1;
                freed += f.2;
                total -= f.2;
            }
            continue;
        }
        keep.push(f);
    }
    let mut idx = 0;
    while total > max_bytes && idx < keep.len() {
        let f = &keep[idx];
        if std::fs::remove_file(&f.0).is_ok() {
            removed += 1;
            freed += f.2;
            total -= f.2;
        }
        idx += 1;
    }
    (removed, freed)
}

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
        let outcome = match self.try_session(&out_path) {
            Ok(info) => Ok(info),
            Err(first_err) => {
                // ONE restart (cold) + ONE retry — the draft's rule.
                // A second failure is a real failure, not a retry loop.
                eprintln!("[bimo-shot] session shot failed ({first_err}); restarting session once");
                if let Some(old) = self.session.take() {
                    old.stop();
                }
                self.session = Some(CaptureSession::start_new());
                match self.try_session(&out_path) {
                    Ok(info) => Ok(info),
                    Err(second_err) => Err(format!("warm: {first_err}; cold retry: {second_err}")),
                }
            }
        };
        match outcome {
            Ok(info) => self.finalize_shot(info, &out_path),
            Err(reason) => ShotOutcome::Failed { reason },
        }
    }
    
    /// Encrypt the shot fail-closed, re-stat its stored size, and
    /// prune the shots dir (cycle 31). A failed encryption deletes
    /// the plain JPEG and fails the shot — a plain shot never stays
    /// on disk. A prune failure never fails the shot.
    fn finalize_shot(&self, mut info: ShotInfo, out_path: &Path) -> ShotOutcome {
        if let Err(e) = crate::crypto::protect_file(out_path) {
            let _ = std::fs::remove_file(out_path);
            return ShotOutcome::Failed {
                reason: format!("shot encryption failed: {e}"),
            };
        }
        info.bytes = std::fs::metadata(out_path)
            .map(|m| m.len())
            .unwrap_or(info.bytes);
        let (pruned, freed) = prune_shots(
            &self.data_dir.join(SHOTS_DIR),
            SHOTS_MAX_AGE,
            SHOTS_MAX_BYTES,
            SystemTime::now(),
        );
        info.pruned = pruned;
        info.pruned_bytes = freed;
        ShotOutcome::Taken(info)
    }

    fn try_session(&self, out_path: &Path) -> Result<ShotInfo, String> {
        match &self.session {
            Some(s) => s.request(out_path),
            None => Err("no capture session".to_string()),
        }
    }

    /// The stored file is DPAPI ciphertext, not a JPEG (hence the .dpapi suffix).
    fn shot_path(&self, n: u64) -> PathBuf {
        self.data_dir
            .join(SHOTS_DIR)
            .join(format!("shot-{n:06}.jpg.dpapi"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn seed(dir: &Path, name: &str, bytes: usize) {
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        f.write_all(&vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn prune_removes_oldest_over_budget_and_aged_out() {
        let dir = std::env::temp_dir().join(format!("bimo-shot-prune-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        seed(&dir, "shot-000001.jpg.dpapi", 60);
        seed(&dir, "shot-000002.jpg.dpapi", 60);
        seed(&dir, "shot-000003.jpg.dpapi", 60);
        seed(&dir, "keep-me.txt", 60);
        // 180 bytes total, budget 100: the two oldest go.
        let (removed, freed) = prune_shots(&dir, Duration::from_secs(7 * 24 * 3600), 100, SystemTime::now());
        assert_eq!((removed, freed), (2, 120));
        assert!(!dir.join("shot-000001.jpg.dpapi").exists());
        assert!(!dir.join("shot-000002.jpg.dpapi").exists());
        assert!(dir.join("shot-000003.jpg.dpapi").exists());
        assert!(dir.join("keep-me.txt").exists());
        // max_age 0: everything shot-shaped is aged out.
        let (removed, _) = prune_shots(&dir, Duration::ZERO, u64::MAX, SystemTime::now());
        assert_eq!(removed, 1);
        assert!(!dir.join("shot-000003.jpg.dpapi").exists());
        assert!(dir.join("keep-me.txt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
    
