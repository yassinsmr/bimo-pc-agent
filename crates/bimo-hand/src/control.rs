//! Control plane: stop file, heartbeat, dead-man's switch, mutual
//! monitoring — mirroring bimo-eye `control.rs`.
//!
//! - A control thread polls `hand.stop` every 500 ms. While it is present,
//!   execution stops at once, running commands are killed (cooperative
//!   then forced), `hand.stopped` (`{"ts","reason"}`) is written and the
//!   heartbeat file is removed. Removing `hand.stop` resumes: queued stays
//!   queued, stopped stays stopped — no auto-resume.
//! - Heartbeat: the worker writes `hand.heartbeat` (ts) and
//!   `hand.heartbeat.json` (`{"ts"}`) every beat; interval configurable
//!   (production 30 s, test 2 s).
//! - Dead-man's switch: 2 consecutive missed beats + one documented failed
//!   reconnect attempt = alert. A reconnect attempt is the supervisor
//!   writing `hand.ping` and waiting 5 s for `hand.pong`; no pong writes
//!   `hand.deadman` (`{"ts","missed_beats":2,"reconnect":"failed"}`)
//!   + an alert, and new commands are refused until the heartbeat returns.
//!   A known machine replacement restarts the counter without an alert
//!   (recorded in the log).
//! - Mutual monitoring: the supervisor writes `supervisor.heartbeat`; the
//!   worker logs a `supervisor.heartbeat-stale` warning when it goes stale
//!   past 2 beats.

use crate::{alert_event, append_log_line, read_json_file, utc_now_secs, write_json_file};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const STOP_FILE: &str = "hand.stop";
pub const STOPPED_FILE: &str = "hand.stopped";
/// The running command's identity, published by the supervisor at
/// command start (`{"id","kind","started_ts"}`) and removed at command
/// end. Council 35 cond. 1: the single arming authority — the worker
/// loop consults the TTL exemption against this kind, the same rule
/// the supervisor's monitor loop consults.
pub const CURRENT_COMMAND_FILE: &str = "hand.current-command.json";
pub const HEARTBEAT_FILE: &str = "hand.heartbeat";
pub const HEARTBEAT_JSON: &str = "hand.heartbeat.json";
pub const SUPERVISOR_HEARTBEAT: &str = "supervisor.heartbeat";
pub const SUPERVISOR_STALE_FILE: &str = "hand.supervisor-stale.json";
pub const PING_FILE: &str = "hand.ping";
pub const PONG_FILE: &str = "hand.pong";
pub const DEADMAN_FILE: &str = "hand.deadman";
pub const PAUSE_HEARTBEAT_FILE: &str = "hand.pause-heartbeat";
/// The control thread polls the stop file at this interval.
pub const STOP_POLL_MS: u64 = 500;
/// Missed beats that trip the dead-man's switch.
pub const DEADMAN_MISSED_BEATS: u64 = 2;
/// How long a reconnect attempt waits for `hand.pong`.
pub const RECONNECT_WAIT_SECS: u64 = 5;

/// The control plane for one data directory.
#[derive(Debug, Clone)]
pub struct HandControl {
    pub data_dir: PathBuf,
    /// Heartbeat interval in seconds (30 production, 2 in tests).
    pub heartbeat_secs: u64,
}

impl HandControl {
    pub fn new(data_dir: &Path, heartbeat_secs: u64) -> Self {
        HandControl {
            data_dir: data_dir.to_path_buf(),
            heartbeat_secs,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.data_dir.join(name)
    }

    // -- stop file -----------------------------------------------------

    pub fn stop_present(&self) -> bool {
        self.path(STOP_FILE).exists()
    }

    /// The reason recorded in `hand.stop`, if any.
    pub fn stop_reason(&self) -> Option<String> {
        read_json_file(&self.path(STOP_FILE))
            .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(|s| s.to_string()))
    }

    pub fn write_stop(&self, reason: &str) -> Result<(), String> {
        write_json_file(
            &self.path(STOP_FILE),
            &json!({"ts": utc_now_secs(), "reason": reason}),
        )
    }

    pub fn clear_stop(&self) -> Result<(), String> {
        let p = self.path(STOP_FILE);
        if p.exists() {
            fs::remove_file(p).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    /// Apply the stop: write `hand.stopped` and remove the heartbeat.
    /// Queued stays queued, stopped stays stopped — no auto-resume.
    pub fn apply_stop(&self, reason: &str) -> Result<(), String> {
        write_json_file(
            &self.path(STOPPED_FILE),
            &json!({"ts": utc_now_secs(), "reason": reason}),
        )?;
        self.remove_heartbeat();
        Ok(())
    }

    pub fn stopped_info(&self) -> Option<Value> {
        read_json_file(&self.path(STOPPED_FILE))
    }

    /// Remove `hand.stopped` only when its recorded reason matches.
    /// Council 35 cond. 1 (defence in depth): when the supervisor's
    /// monitor loop ignores a TTL stop, a `hand.stopped` the worker may
    /// already have written for that same TTL event must not be left
    /// behind to contradict the survived run. Returns true when a
    /// record was removed. A non-matching record is never touched.
    pub fn clear_stopped_if_reason(&self, reason: &str) -> Result<bool, String> {
        let p = self.path(STOPPED_FILE);
        let recorded = self
            .stopped_info()
            .and_then(|v| v.get("reason").and_then(|r| r.as_str()).map(|s| s.to_string()));
        match recorded {
            Some(r) if r == reason => {
                fs::remove_file(p).map_err(|e| e.to_string())?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// The kind of the command currently running, if the supervisor
    /// published one. `None` when idle or when the record is absent
    /// or unparsable (a torn write is read as "no command" — the
    /// caller then falls back to the pre-c81 behaviour of applying
    /// the stop).
    pub fn current_command_kind(&self) -> Option<String> {
        read_json_file(&self.path(CURRENT_COMMAND_FILE))
            .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(|s| s.to_string()))
    }

    // -- heartbeat ------------------------------------------------------

    /// Write one heartbeat beat. Returns `Ok(false)` (no write) while the
    /// test hook `hand.pause-heartbeat` is present.
    pub fn write_heartbeat(&self) -> Result<bool, String> {
        if self.path(PAUSE_HEARTBEAT_FILE).exists() {
            return Ok(false);
        }
        let ts = utc_now_secs();
        fs::write(self.path(HEARTBEAT_FILE), ts.to_string()).map_err(|e| e.to_string())?;
        write_json_file(&self.path(HEARTBEAT_JSON), &json!({"ts": ts}))?;
        Ok(true)
    }

    pub fn remove_heartbeat(&self) {
        let _ = fs::remove_file(self.path(HEARTBEAT_FILE));
        let _ = fs::remove_file(self.path(HEARTBEAT_JSON));
    }

    pub fn heartbeat_ts(&self) -> Option<u64> {
        read_json_file(&self.path(HEARTBEAT_JSON))
            .and_then(|v| v.get("ts").and_then(|t| t.as_u64()))
            .or_else(|| {
                fs::read_to_string(self.path(HEARTBEAT_FILE))
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
            })
    }

    /// Whole beats missed since `last_ts`, at `interval_secs` per beat.
    pub fn missed_beats(last_ts: u64, now_secs: u64, interval_secs: u64) -> u64 {
        if now_secs <= last_ts || interval_secs == 0 {
            return 0;
        }
        (now_secs - last_ts) / interval_secs
    }

    // -- supervisor heartbeat (mutual monitoring) ------------------------

    pub fn write_supervisor_heartbeat(&self) -> Result<(), String> {
        write_json_file(
            &self.path(SUPERVISOR_HEARTBEAT),
            &json!({"ts": utc_now_secs()}),
        )
    }

    pub fn supervisor_heartbeat_ts(&self) -> Option<u64> {
        read_json_file(&self.path(SUPERVISOR_HEARTBEAT))
            .and_then(|v| v.get("ts").and_then(|t| t.as_u64()))
    }

    /// True when the supervisor heartbeat is stale past 2 beats. When
    /// stale, the worker records a `supervisor.heartbeat-stale` warning.
    pub fn supervisor_heartbeat_stale(&self) -> bool {
        match self.supervisor_heartbeat_ts() {
            None => true,
            Some(ts) => {
                Self::missed_beats(ts, utc_now_secs(), self.heartbeat_secs)
                    >= DEADMAN_MISSED_BEATS
            }
        }
    }

    pub fn record_supervisor_stale(&self) {
        let ts = utc_now_secs();
        let value = json!({"ts": ts, "event": "supervisor.heartbeat-stale"});
        let _ = write_json_file(&self.path(SUPERVISOR_STALE_FILE), &value);
        append_log_line(&self.data_dir, "hand.log.jsonl", &value);
    }

    // -- dead-man's switch ----------------------------------------------

    /// One reconnect attempt: write `hand.ping`, wait up to
    /// `RECONNECT_WAIT_SECS` for `hand.pong`. Returns true on pong.
    pub fn reconnect_attempt(&self) -> bool {
        let _ = write_json_file(&self.path(PING_FILE), &json!({"ts": utc_now_secs()}));
        let deadline = Instant::now() + Duration::from_secs(RECONNECT_WAIT_SECS);
        loop {
            if self.path(PONG_FILE).exists() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The full dead-man check: 2 missed beats + a failed reconnect
    /// attempt writes `hand.deadman` + an alert. Returns true when the
    /// dead-man file was (or is) present.
    pub fn deadman_check(&self, last_beat_ts: u64) -> bool {
        let missed = Self::missed_beats(last_beat_ts, utc_now_secs(), self.heartbeat_secs);
        if missed < DEADMAN_MISSED_BEATS {
            return self.path(DEADMAN_FILE).exists();
        }
        if !self.reconnect_attempt() {
            let ts = utc_now_secs();
            let value = json!({"ts": ts, "missed_beats": missed, "reconnect": "failed"});
            let _ = write_json_file(&self.path(DEADMAN_FILE), &value);
            let _ = alert_event(&self.data_dir, "deadman", value);
            return true;
        }
        false
    }

    pub fn is_deadman(&self) -> bool {
        self.path(DEADMAN_FILE).exists()
    }

    pub fn clear_deadman(&self) {
        let _ = fs::remove_file(self.path(DEADMAN_FILE));
        let _ = fs::remove_file(self.path(PING_FILE));
        let _ = fs::remove_file(self.path(PONG_FILE));
    }

    /// A known machine replacement restarts the dead-man counter without
    /// an alert; the replacement is recorded in the log.
    pub fn record_machine_replacement(&self, note: &str) {
        self.clear_deadman();
        append_log_line(
            &self.data_dir,
            "hand.log.jsonl",
            &json!({"ts": utc_now_secs(), "event": "machine-replacement", "note": note}),
        );
    }
}

/// Run `f` on a thread and wait at most `timeout` for it (the eye's
/// `join_timeout` pattern, cycle 36). Returns `None` when the thread is
/// still hung after the timeout — the caller must never wait forever.
pub fn run_with_timeout<T, F>(f: F, timeout: Duration) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    // Unique per call: parallel tests share one process and one second,
    // so a (pid, second) name collides and one test deletes another's
    // directory mid-test (run 12: heartbeat_paused_by_hook_file failed
    // with NotFound at fs::write). Same pattern as queue.rs.
    fn test_dir() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "bimo-hand-ctest-{}-{}",
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn join_timeout_returns_none_for_a_hung_thread() {
        let start = Instant::now();
        let result = run_with_timeout(
            || {
                std::thread::sleep(Duration::from_secs(30));
                42u32
            },
            Duration::from_secs(2),
        );
        assert!(result.is_none());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn join_timeout_returns_the_value_when_it_finishes() {
        assert_eq!(run_with_timeout(|| 7u32, Duration::from_secs(2)), Some(7));
    }

    #[test]
    fn stop_round_trip_removes_heartbeat_and_writes_stopped() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        assert!(ctl.write_heartbeat().unwrap());
        assert!(ctl.heartbeat_ts().is_some());
        ctl.write_stop("test").unwrap();
        assert!(ctl.stop_present());
        ctl.apply_stop("test").unwrap();
        assert!(!ctl.path(HEARTBEAT_FILE).exists());
        assert!(ctl.stopped_info().is_some());
        ctl.clear_stop().unwrap();
        assert!(!ctl.stop_present());
        // Resume: a new beat is written again.
        assert!(ctl.write_heartbeat().unwrap());
        assert!(ctl.heartbeat_ts().is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missed_beats_counts_whole_beats() {
        assert_eq!(HandControl::missed_beats(100, 100, 2), 0);
        assert_eq!(HandControl::missed_beats(100, 103, 2), 1);
        assert_eq!(HandControl::missed_beats(100, 104, 2), 2);
    }

    #[test]
    fn heartbeat_paused_by_hook_file() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        fs::write(ctl.path(PAUSE_HEARTBEAT_FILE), "").unwrap();
        assert!(!ctl.write_heartbeat().unwrap());
        assert!(ctl.heartbeat_ts().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn current_command_kind_round_trip_and_absent() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        assert_eq!(ctl.current_command_kind(), None);
        write_json_file(
            &ctl.path(CURRENT_COMMAND_FILE),
            &json!({"id": "x", "kind": "update", "started_ts": 1}),
        )
        .unwrap();
        assert_eq!(ctl.current_command_kind().as_deref(), Some("update"));
        // Torn/unparsable record reads as "no command".
        fs::write(ctl.path(CURRENT_COMMAND_FILE), "{not json").unwrap();
        assert_eq!(ctl.current_command_kind(), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_stopped_if_reason_only_removes_matching() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        // Absent record: nothing removed.
        assert!(!ctl.clear_stopped_if_reason("ttl").unwrap());
        ctl.apply_stop("ttl").unwrap();
        // Non-matching reason: kept.
        assert!(!ctl.clear_stopped_if_reason("hand.stop").unwrap());
        assert!(ctl.stopped_info().is_some());
        // Matching reason: removed.
        assert!(ctl.clear_stopped_if_reason("ttl").unwrap());
        assert!(ctl.stopped_info().is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
