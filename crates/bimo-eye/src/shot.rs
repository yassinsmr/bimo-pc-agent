//! Shot producer for the eye (feature `eye-shots`, Windows only).
//!
//! Trigger: a `shot.request` flag file in `data_dir` (same pattern as
//! `eye.stop` / `eye.pause` in `control.rs`). The agent — or a test,
//! or `EyeHandle::request_shot` — writes the file with a one-line
//! reason (`"on-demand"` or `"alert:<what>"`); the producer thread
//! polls every 500 ms, takes the file, and takes ONE shot through the
//! `bimo-shot` service. The file is deleted as soon as it is taken,
//! so a request is never executed twice.
//!
//! The producer owns the `ShotService` (rate limiter + persistent
//! session) for the eye's lifetime. Results flow into the same bounded
//! eye channel as every other producer, as `shot.taken` /
//! `shot.rate_limited` / `shot.failed` events — the writer encrypts
//! them (DPAPI) and hash-chains them like every other event, so
//! `verify_file` covers shot events too.
//!
//! The shot thread is joined on eye stop (see `eye.rs`): it exits on
//! the stop flag within one poll interval.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::EyeEvent;

/// Name of the request flag file inside `data_dir`.
pub const SHOT_REQUEST_FILE: &str = "shot.request";

/// Write a shot request (the public trigger). The file content is the
/// one-line reason; an empty file means `"on-demand"`.
pub fn request_shot_file(data_dir: &std::path::Path, reason: &str) -> Result<(), String> {
    let reason = if reason.trim().is_empty() {
        "on-demand"
    } else {
        reason.trim()
    };
    // One line only: a multi-line reason would be a smuggled payload.
    let reason = reason.lines().next().unwrap_or("on-demand");
    std::fs::write(data_dir.join(SHOT_REQUEST_FILE), reason)
        .map_err(|e| format!("cannot write shot request: {e}"))
}

/// Start the shot producer thread. Returns the join handle (joined by
/// `EyeHandle::stop`). The thread owns the service; a service that
/// fails to take a shot logs `shot.failed` and keeps running — a dead
/// shot path must not kill the eye.
pub fn start_shot_producer(
    tx: SyncSender<EyeEvent>,
    data_dir: PathBuf,
    stop_flag: Arc<AtomicBool>,
    game_mode: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut service = bimo_shot::service::ShotService::new(data_dir.clone());
        let request_file = data_dir.join(SHOT_REQUEST_FILE);
    // Reason of the request currently deferred for game mode, if
    // any — used to notify exactly once per deferred request.
    let mut deferred_reason: Option<String> = None;
        while !stop_flag.load(Ordering::Relaxed) {
            if request_file.exists() {
                let reason = std::fs::read_to_string(&request_file)
                    .unwrap_or_else(|_| "on-demand".to_string());
                let reason = reason.lines().next().unwrap_or("on-demand").trim().to_string();
                let reason = if reason.is_empty() {
                    "on-demand".to_string()
                } else {
                    reason
                };
                // Game mode (cycle 31): an alert shot is DEFERRED, not
            // executed — the request file stays put until gaming
            // ends, and the deferral is logged exactly once.
            // On-demand shots still run (Yassin asked for them).
            if reason.starts_with("alert:") && game_mode.load(Ordering::Relaxed) {
                if deferred_reason.as_deref() != Some(reason.as_str()) {
                    deferred_reason = Some(reason.clone());
                    if tx
                        .send(EyeEvent::ShotDeferred {
                            reason: reason.clone(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            deferred_reason = None;
            // Delete FIRST: a request is executed at most once,
                // even if the shot itself fails.
                let _ = std::fs::remove_file(&request_file);
                let (ev, notify, pruned) = match service.request_shot(&reason) {
                    bimo_shot::service::ShotOutcome::Taken(info) => (
                    EyeEvent::ShotTaken {
                            file: info.file,
                            width: info.width,
                            height: info.height,
                            bytes: info.bytes,
                        quality: info.quality.to_string(),
                        cold: info.cold,
                        wait_ms: info.wait_ms as u64,
                        encode_ms: info.encode_ms as u64,
                    },
                    Some(crate::notify::NotifyOutcome::Taken),
                    (info.pruned, info.pruned_bytes),
                ),
                bimo_shot::service::ShotOutcome::RateLimited { rejected_total } => (
                        EyeEvent::ShotRateLimited {
                            reason: format!("{reason}: §6 burst 5/10s"),
                            rejected: rejected_total,
                        },
                    None,
                    (0, 0),
                ),
                bimo_shot::service::ShotOutcome::Failed { reason: err } => (
                        EyeEvent::ShotFailed {
                            reason: format!("{reason}: {err}"),
                        },
                            Some(crate::notify::NotifyOutcome::Failed),
                    (0, 0),
                ),
            };
            // Shot events are rare and critical: a blocking send
                // (not try_send) so they are never dropped as routine.
                // The writer only exits after all senders drop, and
                // this thread drops its sender on stop, so the send
                // cannot deadlock the shutdown path.
                if tx.send(ev).is_err() {
                    break;
                }
            if pruned.0 > 0 {
                let _ = tx.send(EyeEvent::ShotsPruned {
                    removed: pruned.0,
                    freed_bytes: pruned.1,
                });
            }
            // Toast (council ruling (c), cycle 31): alert shots
            // and failures only, never on-demand, never while
            // gaming. A failed toast never fails the shot.
            if let Some(outcome) = notify {
                if crate::notify::should_notify(
                    &reason,
                    outcome,
                    game_mode.load(Ordering::Relaxed),
                ) {
                    if let Err(e) = crate::notify::show_toast(
                        &data_dir,
                        &crate::notify::toast_text(outcome),
                    ) {
                        let _ = tx.send(EyeEvent::Warning {
                            message: format!("toast failed: {e}"),
                        });
                    }
                }
            }
                
            std::thread::sleep(Duration::from_millis(500));
        }
        service.stop();
    })
}
