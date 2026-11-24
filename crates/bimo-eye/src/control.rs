//! Stop button + heartbeat (council condition 9).
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

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::EyeEvent;

/// Start the control thread. `data_dir` holds the `eye.stop` /
/// `eye.pause` flag files.
pub fn start_control(
    data_dir: PathBuf,
    tx: SyncSender<EyeEvent>,
    paused: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    heartbeat_secs: u64,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let stop_file = data_dir.join("eye.stop");
        let pause_file = data_dir.join("eye.pause");
        let mut was_stopped = false;
        let mut last_heartbeat = std::time::Instant::now()
            - Duration::from_secs(heartbeat_secs); // beat immediately
        while !stop.load(Ordering::Relaxed) {
            let is_stopped = stop_file.exists();
            let is_paused = pause_file.exists() || is_stopped;
            stopped.store(is_stopped, Ordering::Relaxed);
            paused.store(is_paused, Ordering::Relaxed);
            if is_stopped && !was_stopped {
                let _ = tx.send(EyeEvent::AgentStop {
                    reason: "eye.stop-file".to_string(),
                });
            }
            if !is_stopped && was_stopped {
                let _ = tx.send(EyeEvent::AgentStart {
                    scope_note: "eye resumed after eye.stop-file".to_string(),
                    crypto: crate::crypto::detect_mode().as_str().to_string(),
                });
            }
            was_stopped = is_stopped;
            if !is_stopped
                && last_heartbeat.elapsed() >= Duration::from_secs(heartbeat_secs)
            {
                let _ = tx.send(EyeEvent::Heartbeat);
                last_heartbeat = std::time::Instant::now();
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    })
}
