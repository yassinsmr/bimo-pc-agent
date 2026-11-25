//! Stop button + heartbeat (council condition 9 + eye-core council
//! condition 5: no silent silencing).
//!
//! - `%LOCALAPPDATA%\BimoAgent\eye.stop` (here: `data_dir/eye.stop`):
//!   while present, watching + hashing + snapshotting stop at once and
//!   the writer records `agent.stop` (reason `eye.stop-file`). Removing
//!   the file resumes. The writer keeps running the whole time.
//! - `eye.pause`: same, but only watching pauses — the writer keeps
//!   going and the heartbeat keeps beating.
//! - Heartbeat: `eye.heartbeat` every N seconds while the eye is alive
//!   and not stopped. The guardian (later unit) treats >90 s without a
//!   heartbeat as a dead eye.
//!
//! Condition 5 — the stop must leave a trace OUTSIDE the eye's own
//! log, so silencing the eye cannot hide itself:
//! - `heartbeat.json` in `data_dir` is rewritten on every beat
//!   (`{"ts": "..."}`); the alerts unit watches its freshness.
//! - While stopped, `heartbeat.json` is REMOVED and `eye.stopped`
//!   (`{"ts": "...", "reason": "eye.stop-file"}`) is written instead.
//!   A missing heartbeat file + a present `eye.stopped` is the
//!   detectable signature of a deliberate stop, as opposed to a crash
//!   (heartbeat file present but stale).
//! - Honest limit, documented: any process running as the same user
//!   can create `eye.stop` / `eye.pause` — there is no privilege
//!   boundary here. The point of the marker files is detection, not
//!   prevention.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::EyeEvent;

/// Write the heartbeat marker file (outside-the-log trace, condition 5).
fn write_heartbeat_file(data_dir: &std::path::Path) {
    let text = format!(
        "{{\"ts\": \"{}\"}}",
        crate::utc_now_rfc3339()
    );
    let _ = std::fs::write(data_dir.join("heartbeat.json"), text);
}

/// Write the stopped marker file (outside-the-log trace, condition 5).
fn write_stopped_file(data_dir: &std::path::Path, reason: &str) {
    let text = format!(
        "{{\"ts\": \"{}\", \"reason\": \"{}\"}}",
        crate::utc_now_rfc3339(),
        reason
    );
    let _ = std::fs::write(data_dir.join("eye.stopped"), text);
}

/// Start the control thread. `data_dir` holds the `eye.stop` /
/// `eye.pause` flag files.
pub fn start_control(
    data_dir: PathBuf,
    tx: SyncSender<EyeEvent>,
    paused: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    heartbeat_secs: u64,
    game_mode: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let stop_file = data_dir.join("eye.stop");
        let pause_file = data_dir.join("eye.pause");
        let heartbeat_file = data_dir.join("heartbeat.json");
        let stopped_file = data_dir.join("eye.stopped");
    let gamemode_file = data_dir.join("eye.gamemode");
    let wipe_file = data_dir.join("eye.wipe");
    // Game mode is start-time config OR the flag file: either one
    // turns it on (cycle 31 — the flag lets the game-mode unit
    // toggle it at runtime later).
    let initial_game_mode = game_mode.load(Ordering::Relaxed);
    let mut wipe_notified = false;
        let mut was_stopped = false;
        let mut last_heartbeat = std::time::Instant::now()
            - Duration::from_secs(heartbeat_secs); // beat immediately
        while !stop.load(Ordering::Relaxed) {
            eprintln!("[diag] control tick");
            let is_stopped = stop_file.exists();
            let is_paused = pause_file.exists() || is_stopped;
            stopped.store(is_stopped, Ordering::Relaxed);
            paused.store(is_paused, Ordering::Relaxed);
        // Game mode: config OR flag file (cycle 31).
        game_mode.store(
            initial_game_mode || gamemode_file.exists(),
            Ordering::Relaxed,
        );
        // A wipe requested mid-run applies on the NEXT start only
        // (cycle 31): deleting the log under the running writer
        // would race it. One warning, then silence until removed.
        if wipe_file.exists() && !wipe_notified {
            wipe_notified = true;
            let _ = tx.send(EyeEvent::Warning {
                message: "eye.wipe requested while running — applies on next start; eye data NOT deleted mid-run".to_string(),
            });
        }
        if !wipe_file.exists() {
            wipe_notified = false;
        }
            if is_stopped && !was_stopped {
                // Stop leaves a trace outside the log (condition 5).
                let _ = std::fs::remove_file(&heartbeat_file);
                write_stopped_file(&data_dir, "eye.stop-file");
                let _ = tx.send(EyeEvent::AgentStop {
                    reason: "eye.stop-file".to_string(),
                });
            }
            if !is_stopped && was_stopped {
                let _ = std::fs::remove_file(&stopped_file);
                let _ = tx.send(EyeEvent::AgentStart {
                    scope_note: "eye resumed after eye.stop-file".to_string(),
                    crypto: crate::crypto::detect_mode()
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|_| "unavailable".to_string()),
                });
                // Beat immediately on resume so the marker is fresh.
                write_heartbeat_file(&data_dir);
                last_heartbeat = std::time::Instant::now();
            }
            was_stopped = is_stopped;
            if !is_stopped
                && last_heartbeat.elapsed() >= Duration::from_secs(heartbeat_secs)
            {
                let _ = tx.send(EyeEvent::Heartbeat);
                write_heartbeat_file(&data_dir);
                last_heartbeat = std::time::Instant::now();
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    })
}
