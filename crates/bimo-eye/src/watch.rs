//! File watcher (spec section 4): `notify` + 2 s debouncer over the
//! configured folders only. A file counts as "completed" once it has
//! been quiet for the debounce window — downloads that arrive in pieces
//! produce exactly one `file.completed` event under their final name.
//!
//! Temporary names (`.tmp`, `.part`, `.crdownload`) are never reported
//! on their own; a rename into the final name reports both the rename
//! and the completion of the final file.
//!
//! Platform mapping that matters (cycle 15, proven in source):
//! notify's Windows backend reports EVERY content change as
//! `Modify(ModifyKind::Any)` (FILE_ACTION_MODIFIED → Any in
//! notify 7's windows.rs), while Linux inotify reports
//! `Modify(Data)`. `map_event` therefore treats every non-rename
//! Modify kind as a completion — matching kinds by name dropped
//! `Any` silently and Windows missed all later file changes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::EyeEvent;

/// Extensions that mark a file as "still downloading" — never logged
/// under these names.
const TEMP_SUFFIXES: [&str; 3] = [".tmp", ".part", ".crdownload"];

fn is_temp_name(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    TEMP_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Map one debounced notify event to eye events. Returns `None` for
/// noise (access events, temp files, directories).
///
/// Key semantic (notify-debouncer-full documents it: "doesn't emit
/// Modify events after a Create event"): a debounced event only fires
/// AFTER the file has been quiet for the debounce window — so the
/// arrival of a debounced `Create` IS the completion signal. A new
/// file therefore yields both `file.created` and `file.completed`.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
fn map_event(
    ev: &notify_debouncer_full::DebouncedEvent,
) -> Vec<EyeEvent> {
    use notify::EventKind;
    let mut out = Vec::new();
    let kind = &ev.event.kind;
    let paths = &ev.event.paths;
    if paths.is_empty() {
        return out;
    }
    // Directories are not files: skip (a directory create also fires
    // for its children separately, which is what we log).
    let is_dir_event = paths.iter().any(|p| p.is_dir());
    match kind {
        EventKind::Create(_) => {
            for p in paths {
                if !is_temp_name(p) && !p.is_dir() {
                    out.push(EyeEvent::FileCreated { path: p.clone() });
                    // Quiet for the debounce window already: complete.
                    if let Ok(meta) = std::fs::metadata(p) {
                        out.push(EyeEvent::FileCompleted {
                            path: p.clone(),
                            size: meta.len(),
                        });
                    }
                }
            }
        }
        EventKind::Modify(modify) => {
            use notify::event::ModifyKind;
            match modify {
                ModifyKind::Name(_) if paths.len() == 2 => {
                    let (from, to) = (&paths[0], &paths[1]);
                    if !is_temp_name(to) {
                        out.push(EyeEvent::FileRenamed {
                            from: from.clone(),
                            to: to.clone(),
                        });
                        // The file is now complete under its final name.
                        if let Ok(meta) = std::fs::metadata(to) {
                            out.push(EyeEvent::FileCompleted {
                                path: to.clone(),
                                size: meta.len(),
                            });
                        }
                    }
                }
                ModifyKind::Name(_) => {
                    // Single-path rename half (From or To without its
                    // pair): direction unknown — ignore it; the paired
                    // event or the file's own completion covers it.
                }
                _ => {
                    // Every other modification: Data, Metadata, Other
                    // AND Any. `Any` is what notify's Windows backend
                    // reports for EVERY content change
                    // (FILE_ACTION_MODIFIED maps to Modify(Any) in
                    // notify 7's windows.rs). The old match listed
                    // Data/Metadata/Other explicitly and dropped `Any`
                    // in the catch-all — so on Windows every later
                    // change to an existing file vanished silently
                    // (cycle 15: 1 completion for setup.exe, no re-hash).
                    // On Linux inotify reports Data, which is why the
                    // same test passed there.
                    for p in paths {
                        if !is_temp_name(p) && !p.is_dir() {
                            if let Ok(meta) = std::fs::metadata(p) {
                                out.push(EyeEvent::FileCompleted {
                                    path: p.clone(),
                                    size: meta.len(),
                                });
                            }
                        }
                    }
                }
            }
        }
        EventKind::Remove(_) => {
            for p in paths {
                if !is_temp_name(p) && !is_dir_event {
                    out.push(EyeEvent::FileDeleted { path: p.clone() });
                }
            }
        }
        _ => {}
    }
    out
}

/// Start the watcher thread. Returns the join handle. The thread ends
/// when the `stop` flag is set (checked between debouncer callbacks via
/// the shared flag; the debouncer itself runs until process exit — the
/// eye shuts it down by dropping the watcher at the end).
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub fn start_watcher(
    dirs: Vec<PathBuf>,
    tx: SyncSender<EyeEvent>,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    debounce: Duration,
) -> Result<JoinHandle<()>, String> {
    use notify::RecursiveMode;
    use notify_debouncer_full::new_debouncer;

    let tx_cb = tx.clone();
    let paused_cb = paused.clone();
    let mut debouncer = new_debouncer(
        debounce,
        None,
        move |result: notify_debouncer_full::DebounceEventResult| {
            if paused_cb.load(Ordering::Relaxed) {
                return; // paused: drop raw events, do not log them
            }
            let events = match result {
                Ok(events) => events,
                Err(errors) => {
                    for e in errors {
                        let _ = tx_cb.send(EyeEvent::Warning {
                            message: format!("watcher error: {e}"),
                        });
                    }
                    return;
                }
            };
            for ev in events {
                for mapped in map_event(&ev) {
                    // File events are critical (condition 12): block
                    // rather than drop when the queue is full.
                    let _ = tx_cb.send(mapped);
                }
            }
        },
    )
    .map_err(|e| format!("cannot create file watcher: {e}"))?;

    for dir in &dirs {
        if !dir.exists() {
            let _ = tx.send(EyeEvent::Warning {
                message: format!("watch folder missing, skipped: {}", dir.display()),
            });
            continue;
        }
        debouncer
            .watch(dir, RecursiveMode::Recursive)
            .map_err(|e| format!("cannot watch {}: {e}", dir.display()))?;
    }

    // Keep the debouncer alive on this thread until `stop` is set.
    let handle = std::thread::spawn(move || {
        let _debouncer = debouncer;
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
    });
    Ok(handle)
}

/// Non-desktop fallback: no watcher, the eye still logs heartbeats and
/// process snapshots where supported.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn start_watcher(
    _dirs: Vec<PathBuf>,
    tx: SyncSender<EyeEvent>,
    _paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    _debounce: Duration,
) -> Result<JoinHandle<()>, String> {
    let _ = tx.send(EyeEvent::Warning {
        message: "file watcher unsupported on this platform".to_string(),
    });
    Ok(std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{Event, EventKind, ModifyKind};
    use notify_debouncer_full::DebouncedEvent;

    fn debounced(kind: EventKind, path: &Path) -> DebouncedEvent {
        DebouncedEvent::new(
            Event::new(kind).add_path(path.to_path_buf()),
            std::time::Instant::now(),
        )
    }

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bimo-eye-watch-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(name);
        std::fs::write(&path, b"test content").unwrap();
        path
    }

    fn is_completion_for(events: &[EyeEvent], path: &Path) -> bool {
        events.iter().any(|e| match e {
            EyeEvent::FileCompleted { path: p, .. } => p == path,
            _ => false,
        })
    }

    #[test]
    fn windows_modify_any_maps_to_completion() {
        // Regression test for cycle 15: notify's Windows backend maps
        // FILE_ACTION_MODIFIED to Modify(Any) — the old explicit match
        // (Data/Metadata/Other) dropped it, so Windows never reported
        // a later change to an existing file.
        let path = temp_file("setup.exe");
        let ev = debounced(
            EventKind::Modify(ModifyKind::Any),
            &path,
        );
        let out = map_event(&ev);
        assert!(
            is_completion_for(&out, &path),
            "Modify(Any) must map to file.completed, got {out:?}"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn modify_data_still_maps_to_completion() {
        let path = temp_file("notes.txt");
        let ev = debounced(
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Any)),
            &path,
        );
        let out = map_event(&ev);
        assert!(is_completion_for(&out, &path));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
