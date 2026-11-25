//! Orchestration (spec section 4): seven producers + one writer.
//!
//! - watcher: raw file events (debounced 2 s) → channel
//! - snapshotter: process list every N s → channel
//! - hash worker: SHA-256 of installers/archives → channel
//! - control: stop/pause flag files + heartbeat → channel
//! - window tracker (cycle-21 merge): `SetWinEventHook` events via
//!   `bimo-wintrack`, bridged into the same channel (Windows only;
//!   skipped entirely off Windows). Routine events: dropped + counted
//!   (`log.gap`) when the bounded queue is full, never blocking.
//! - shot producer (cycle 28, feature `eye-shots`, Windows only):
//!   polls the `shot.request` flag file, takes ONE shot per request
//!   through the `bimo-shot` service (rate limiter + persistent
//!   session) → channel as `shot.taken` / `shot.rate_limited` /
//!   `shot.failed`.
//! - writer (single): owns the JSONL log + hash chain; forwards
//!   hashable files to the hash worker and emits `install.detected`
//!   (always low confidence) for `.exe` / `.msi` completions.
//!
//! Backpressure (condition 12): the event channel is bounded at
//! 10,000 events. Routine `proc.*` events are dropped when full
//! (`try_send`); critical file events block instead of being lost.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    pub reconcile_secs: u64,
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
        reconcile_secs: 300,
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
    /// Window tracker (Windows only). `None` off Windows.
    wintrack: Option<bimo_wintrack::WinTrack>,
    /// Bridge thread: `WinEvent` → `EyeEvent` into the eye channel.
    win_bridge: Option<JoinHandle<()>>,
    /// Shot producer (feature `eye-shots`, Windows only).
    shot_producer: Option<JoinHandle<()>>,
}

impl EyeHandle {
    /// Graceful stop: signals every thread, joins them, the writer
    /// records a final `agent.stop` and closes the log.
    pub fn stop(mut self) { eprintln!("[trace] stop() entry");
        self.stop_flag.store(true, Ordering::Relaxed);
        // The bridge exits on the stop flag (≤200 ms poll); join it
        // first so its channel clone drops, then stop the tracker
        // (joins its pump + watchdog), then the other producers.
        eprintln!("[trace] before join win_bridge"); if let Some(h) = self.win_bridge.take() {
            let _ = h.join(); eprintln!("[trace] after join win_bridge");
        }
        eprintln!("[trace] before WinTrack stop"); if let Some(t) = self.wintrack.take() {
            t.stop(); eprintln!("[trace] after WinTrack stop");
        }
        // Shot producer next (≤500 ms poll + session stop): join it
        // before the writer so its channel clone drops and the writer
        // can exit once every other producer is gone.
        eprintln!("[trace] before join shot producer"); if let Some(h) = self.shot_producer.take() {
            let _ = h.join(); eprintln!("[trace] after join shot producer");
        }
        eprintln!("[trace] before join remaining handles");
        // Join order is start() order: watcher, snapshot, hash,
        // reconcile, control, writer.
        let handle_names = ["watcher", "snapshot", "hash", "reconcile", "control", "writer"];
        for (i, h) in self.handles.drain(..).enumerate() {
            let name = handle_names.get(i).copied().unwrap_or("unknown");
            eprintln!("[trace] before join {}", name);
            let _ = h.join();
            eprintln!("[trace] after join {}", name);
        }
        eprintln!("[trace] stop() end");
    }

    pub fn log_path(&self) -> PathBuf {
        self.log_path.clone()
    }

    /// Request one shot (writes the `shot.request` flag file; the
    /// shot producer takes it within ~500 ms). Available with or
    /// without the `eye-shots` feature — but WITHOUT the feature no
    /// producer thread exists, so the file just sits there until a
    /// feature build reads it. The self-test asserts the feature path.
    pub fn request_shot(&self, reason: &str) -> Result<(), String> {
        #[cfg(all(feature = "eye-shots", windows))]
        {
            crate::shot::request_shot_file(&self.data_dir, reason)
        }
        #[cfg(not(all(feature = "eye-shots", windows)))]
        {
            let _ = reason;
            Err("shots are not wired in this build (feature `eye-shots` + Windows required)"
                .to_string())
        }
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

/// Start the window-event producer (cycle-21 merge, Windows only).
///
/// Returns `(tracker, bridge-thread)`. Off Windows both are `None`:
/// the eye runs exactly as before, with no window thread at all.
/// On Windows a failed hook install FAILS the eye start (fail-closed:
/// a silently blind eye is worse than a stopped one — the self-test
/// catches it on CI before any real run).
///
/// The bridge converts each `WinEvent` to an `EyeEvent` and
/// `try_send`s it into the bounded eye channel: window events are
/// routine, so a full queue drops + counts them (`log.gap`) instead
/// of blocking the hook thread. The bridge polls with a 200 ms
/// timeout and exits when the stop flag is set.
fn start_window_producer(
    tx: SyncSender<EyeEvent>,
    stop_flag: Arc<AtomicBool>,
    dropped_events: Arc<AtomicU64>,
) -> Result<(Option<bimo_wintrack::WinTrack>, Option<JoinHandle<()>>), String> {
    if !bimo_wintrack::tracker_supported() {
        return Ok((None, None));
    }
    let (win_tx, win_rx) = std::sync::mpsc::channel::<bimo_wintrack::WinEvent>();
    let tracker = bimo_wintrack::WinTrack::start(win_tx)
        .map_err(|e| format!("window tracker failed to start: {e}"))?;
    let bridge = std::thread::spawn(move || {
        loop {
            match win_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(wev) => {
                    let ev = EyeEvent::from(wev);
                    if tx.try_send(ev).is_err() {
                        dropped_events.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });
    Ok((Some(tracker), Some(bridge)))
}

pub fn start(cfg: EyeConfig) -> Result<EyeHandle, String> {
    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("cannot create data dir: {e}"))?;
    // Start-time wipe (cycle 31): `eye.wipe` present means the
    // operator wants prior eye data gone BEFORE a fresh log opens.
    let wiped = if cfg.data_dir.join("eye.wipe").exists() {
        Some(wipe_data_dir(&cfg.data_dir))
    } else {
        None
    };
    let (mut writer, resume_note) = LogWriter::open(&cfg.data_dir)?;
    let log_path = writer.path();
    let crypto_mode = writer.crypto();

    let scope_note = format!(
        "eye v1 watches ONLY: {}. NOT covered: everything outside these folders (condition 7). \
         Threat model (honest, eye-core council condition 3): the hash chain is tamper-EVIDENCE, \
         not integrity against an attacker with the same privileges; DPAPI protects against \
         another user / a stolen disk, not against malware running as Yassin.",
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
    if let Some((removed_files, freed_bytes)) = wiped {
        writer.write(&EyeEvent::EyeWiped {
            removed_files,
            freed_bytes,
        })?;
    }
    if let Some(note) = resume_note {
        writer.write(&EyeEvent::Warning { message: note })?;
    }
    // Plaintext is only ever used by explicit opt-in (council
    // condition 2) — the opt-in itself is recorded in the log.
    if crypto_mode == crate::crypto::CryptoMode::Plain {
        writer.write(&EyeEvent::Warning {
            message: "plaintext log: explicit opt-in BIMO_EYE_PLAINTEXT_OK=1 recorded; encryption stays an arrival-day item".to_string(),
        })?;
    }

    let (tx, rx): (SyncSender<EyeEvent>, Receiver<EyeEvent>) = sync_channel(EVENT_QUEUE_CAP);
    let (hash_tx, hash_rx) = std::sync::mpsc::sync_channel::<PathBuf>(100);
    let paused = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let game_mode = Arc::new(AtomicBool::new(cfg.game_mode));

    // Log honesty (council condition 4): producers count what they
    // drop; the writer turns the counts into `log.gap` events.
    let dropped_events = Arc::new(AtomicU64::new(0));
    let dropped_hashes = Arc::new(AtomicU64::new(0));

    // Writer thread: owns the log, forwards hash work, infers installs.
    let writer_dropped_events = dropped_events.clone();
    let writer_dropped_hashes = dropped_hashes.clone();
    let win_dropped_events = dropped_events.clone();
    let writer_handle = std::thread::spawn(move || {
        writer_loop(writer, rx, hash_tx, writer_dropped_events, writer_dropped_hashes);
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
        dropped_events,
    );
    let hash_handle = start_hash_worker(
        hash_rx,
        tx.clone(),
        game_mode.clone(),
        stop_flag.clone(),
    );
    let reconcile_handle = crate::reconcile::start_reconciler(
        cfg.watch_dirs.clone(),
        tx.clone(),
        paused.clone(),
        stop_flag.clone(),
        Duration::from_secs(cfg.reconcile_secs),
    );
    let control_handle = control::start_control(
        cfg.data_dir.clone(),
        tx.clone(),
        paused.clone(),
        stopped.clone(),
        stop_flag.clone(),
        cfg.heartbeat_secs,
        game_mode.clone(),
    );

    let (wintrack, win_bridge) = start_window_producer(
        tx.clone(),
        stop_flag.clone(),
        win_dropped_events,
    )?;

    // Shot producer (feature `eye-shots`, Windows only): polls the
    // `shot.request` flag file and takes one shot per request through
    // the `bimo-shot` service (rate limiter + persistent session).
    // Without the feature the eye runs exactly as before.
    #[cfg(all(feature = "eye-shots", windows))]
    let shot_producer = Some(crate::shot::start_shot_producer(
        tx.clone(),
        cfg.data_dir.clone(),
        stop_flag.clone(),
        game_mode.clone(),
    ));
    #[cfg(not(all(feature = "eye-shots", windows)))]
    let shot_producer: Option<JoinHandle<()>> = None;

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
            reconcile_handle,
            control_handle,
            writer_handle,
        ],
        wintrack,
        win_bridge,
        shot_producer,
    })
}

/// Take-and-reset a drop counter as a `log.gap` event, if anything
/// was dropped since the last check. Pure enough to unit-test: a gap
/// is data, never silence (council condition 4).
pub fn take_gap_event(counter: &AtomicU64, reason: &str) -> Option<EyeEvent> {
    let dropped = counter.swap(0, Ordering::Relaxed);
    if dropped == 0 {
        None
    } else {
        Some(EyeEvent::LogGap {
            dropped,
            reason: reason.to_string(),
        })
    }
}

fn writer_loop(
    mut writer: LogWriter,
    rx: Receiver<EyeEvent>,
    hash_tx: SyncSender<PathBuf>,
    dropped_events: Arc<AtomicU64>,
    dropped_hashes: Arc<AtomicU64>,
) {
    while let Ok(ev) = rx.recv() {
        // Record our own gaps BEFORE the event that follows them.
        if let Some(gap) =
            take_gap_event(&dropped_events, "event queue full: routine proc.* events dropped")
        {
            if writer.write(&gap).is_err() {
                break;
            }
        }
        if let Some(gap) = take_gap_event(
            &dropped_hashes,
            "hash queue full: hash requests dropped (files will be re-hashed on next completion)",
        ) {
            if writer.write(&gap).is_err() {
                break;
            }
        }
        let mut extra: Option<EyeEvent> = None;
        if let EyeEvent::FileCompleted { path, .. } = &ev {
            if is_installer(path) {
                extra = Some(EyeEvent::InstallDetected {
                    path: path.clone(),
                });
            }
            if is_hashable(path) && hash_tx.try_send(path.clone()).is_err() {
                dropped_hashes.fetch_add(1, Ordering::Relaxed);
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
    // Flush any gaps recorded after the last received event.
    if let Some(gap) =
        take_gap_event(&dropped_events, "event queue full: routine proc.* events dropped")
    {
        let _ = writer.write(&gap);
    }
    if let Some(gap) = take_gap_event(
        &dropped_hashes,
        "hash queue full: hash requests dropped (files will be re-hashed on next completion)",
    ) {
        let _ = writer.write(&gap);
    }
    let _ = writer.write(&EyeEvent::AgentStop {
        reason: "eye.stop".to_string(),
    });
    writer.close();
}

/// Delete prior eye data for `eye.wipe` (cycle-31 close-out).
/// Removes the log (+ rotations), all shot files, heartbeat /
/// stopped markers and a stale shot request. Never touches
/// `eye.stop` / `eye.pause` (operator intent) or the data dir
/// itself. Best effort: returns (files removed, bytes freed).
/// The `eye.wipe` flag itself is removed last, so a crash
/// mid-wipe re-wipes idempotently on the next start.
fn wipe_data_dir(data_dir: &Path) -> (u64, u64) {
    let mut removed = 0u64;
    let mut freed = 0u64;
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("eye-events") {
                let p = e.path();
                if let Ok(m) = e.metadata() {
                    let size = m.len();
                    if std::fs::remove_file(&p).is_ok() {
                        removed += 1;
                        freed += size;
                    }
                }
            }
        }
    }
    let shots = data_dir.join("shots");
    if let Ok(entries) = std::fs::read_dir(&shots) {
        for e in entries.flatten() {
            let p = e.path();
            if let Ok(m) = e.metadata() {
                let size = m.len();
                if std::fs::remove_file(&p).is_ok() {
                    removed += 1;
                    freed += size;
                }
            }
        }
    }
    let _ = std::fs::remove_dir(&shots);
    for f in ["heartbeat.json", "eye.stopped", "shot.request"] {
        let p = data_dir.join(f);
        if let Ok(m) = std::fs::metadata(&p) {
            let size = m.len();
            if std::fs::remove_file(&p).is_ok() {
                removed += 1;
                freed += size;
            }
        }
    }
    let _ = std::fs::remove_file(data_dir.join("eye.wipe"));
    (removed, freed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_event_emitted_and_counter_reset() {
        let c = AtomicU64::new(0);
        assert!(take_gap_event(&c, "x").is_none());
        c.fetch_add(7, Ordering::Relaxed);
        let ev = take_gap_event(&c, "queue full").expect("gap event");
        match ev {
            EyeEvent::LogGap { dropped, reason } => {
                assert_eq!(dropped, 7);
                assert_eq!(reason, "queue full");
            }
            _ => panic!("wrong event"),
        }
        assert_eq!(c.load(Ordering::Relaxed), 0);
        assert!(take_gap_event(&c, "x").is_none());
    }
}
