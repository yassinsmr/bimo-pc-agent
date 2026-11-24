//! Orchestration (spec section 4): five threads + one writer.
//!
//! - watcher: raw file events (debounced 2 s) → channel
//! - snapshotter: process list every N s → channel
//! - hash worker: SHA-256 of installers/archives → channel
//! - control: stop/pause flag files + heartbeat → channel
//! - writer (single): owns the JSONL log + hash chain; forwards
//!   hashable files to the hash worker and emits `install.detected`
//!   (always low confidence) for `.exe` / `.msi` completions.
//!
//! Backpressure (condition 12): the event channel is bounded at
//! 10,000 events. Routine `proc.*` events are dropped when full
//! (`try_send`); critical file events block instead of being lost.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::hash_worker::{is_hashable, start_hash_worker};
use crate::log::{verify_file, LogWriter, VerifyReport};
use crate::{control, snapshot, watch, EyeEvent};

/// Bounded event queue (condition 12).
pub const EVENT_QUEUE_CAP: usize = 10_000;

pub struct EyeConfig {
    pub watch_dirs: Vec<PathBuf>,
    pub data_dir: PathBuf,
    pub debounce_secs: u64,
    pub snapshot_secs: u64,
    pub heartbeat_secs: u64,
    pub game_mode: bool,
}

impl Default for EyeConfig {
    fn default() -> Self {
        EyeConfig {
            watch_dirs: Vec::new(),
            data_dir: PathBuf::from("bimo-eye-data"),
            debounce_secs: 2,
            snapshot_secs: 10,
            heartbeat_secs: 30,
            game_mode: false,
        }
    }
}

pub struct EyeHandle {
    pub log_path: PathBuf,
    pub data_dir: PathBuf,
    stop_flag: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

impl EyeHandle {
    /// Graceful stop: signals every thread, joins them, the writer
    /// records a final `agent.stop` and closes the log.
    pub fn stop(mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }

    pub fn log_path(&self) -> PathBuf {
        self.log_path.clone()
    }
}

fn is_installer(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let e = e.to_lowercase();
            e == "exe" || e == "msi"
        })
        .unwrap_or(false)
}

/// Verify the current log file in `data_dir`.
pub fn verify_log(data_dir: &Path) -> Result<VerifyReport, String> {
    verify_file(&data_dir.join("eye-events.jsonl"))
}

pub fn start(cfg: EyeConfig) -> Result<EyeHandle, String> {
    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("cannot create data dir: {e}"))?;
    let (mut writer, resume_note) = LogWriter::open(&cfg.data_dir)?;
    let log_path = writer.path();
    let crypto_mode = writer.crypto();

    let scope_note = format!(
        "eye v1 watches ONLY: {}. NOT covered: everything outside these folders (condition 7).",
        cfg.watch_dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    writer.write(&EyeEvent::AgentStart {
        scope_note: scope_note.clone(),
        crypto: crypto_mode.as_str().to_string(),
    })?;
    if let Some(note) = resume_note {
        writer.write(&EyeEvent::Warning { message: note })?;
    }
    #[cfg(windows)]
    if crypto_mode == crate::crypto::CryptoMode::Plain {
        writer.write(&EyeEvent::Warning {
            message: "DPAPI unavailable: log is written in plaintext; encryption stays an arrival-day item".to_string(),
        })?;
    }

    let (tx, rx): (SyncSender<EyeEvent>, Receiver<EyeEvent>) = sync_channel(EVENT_QUEUE_CAP);
    let (hash_tx, hash_rx) = std::sync::mpsc::sync_channel::<PathBuf>(100);
    let paused = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let game_mode = Arc::new(AtomicBool::new(cfg.game_mode));

    // Writer thread: owns the log, forwards hash work, infers installs.
    let writer_handle = std::thread::spawn(move || {
        writer_loop(writer, rx, hash_tx);
    });

    let watcher_handle = watch::start_watcher(
        cfg.watch_dirs.clone(),
        tx.clone(),
        paused.clone(),
        stop_flag.clone(),
        Duration::from_secs(cfg.debounce_secs),
    )?;
    let snapshot_handle = snapshot::start_snapshotter(
        tx.clone(),
        Duration::from_secs(cfg.snapshot_secs),
        paused.clone(),
        stop_flag.clone(),
    );
    let hash_handle = start_hash_worker(
        hash_rx,
        tx.clone(),
        game_mode.clone(),
        stop_flag.clone(),
    );
    let control_handle = control::start_control(
        cfg.data_dir.clone(),
        tx.clone(),
        paused.clone(),
        stopped.clone(),
        stop_flag.clone(),
        cfg.heartbeat_secs,
    );

    // Drop the original sender: the writer exits when every producer
    // thread has ended and dropped its own clone.
    drop(tx);

    Ok(EyeHandle {
        log_path,
        data_dir: cfg.data_dir,
        stop_flag,
        handles: vec![
            watcher_handle,
            snapshot_handle,
            hash_handle,
            control_handle,
            writer_handle,
        ],
    })
}

fn writer_loop(
    mut writer: LogWriter,
    rx: Receiver<EyeEvent>,
    hash_tx: SyncSender<PathBuf>,
) {
    while let Ok(ev) = rx.recv() {
        let mut extra: Option<EyeEvent> = None;
        if let EyeEvent::FileCompleted { path, .. } = &ev {
            if is_installer(path) {
                extra = Some(EyeEvent::InstallDetected {
                    path: path.clone(),
                });
            }
            if is_hashable(path) {
                let _ = hash_tx.try_send(path.clone());
            }
        }
        if writer.write(&ev).is_err() {
            // The log is the product: if it cannot be written, there is
            // nothing sensible left to do but stop.
            break;
        }
        if let Some(ev2) = extra {
            if writer.write(&ev2).is_err() {
                break;
            }
        }
    }
    let _ = writer.write(&EyeEvent::AgentStop {
        reason: "eye.stop".to_string(),
    });
    writer.close();
}
