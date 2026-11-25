//! Periodic folder reconciliation (cycle-31 close-out, council condition 1):
//! re-scan the watched folders every N seconds and compare with the
//! previous scan, so a file the `notify` watcher missed (a silent
//! install, a gap in the debouncer) still shows up in the log.
//!
//! The first scan is a baseline (no file events, only the summary).
//! A scan that follows a paused period re-baselines silently — a file
//! created while the eye was stopped must NOT be logged (the stop
//! guarantee in the self-test), so the reconciler never reports
//! files that appeared during a pause.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use crate::watch::is_temp_name;
use crate::EyeEvent;

/// Default reconcile interval (seconds). The self-test uses 3 s.
pub const RECONCILE_INTERVAL_SECS: u64 = 300;

/// One scanned file: (size, mtime).
pub type FileState = (u64, SystemTime);

/// Recursive scan of one directory: files only. Temp names are
/// skipped (same rule as the watcher); unreadable entries are
/// skipped silently — a file vanishing mid-scan is normal.
pub fn scan_dir(dir: &Path) -> HashMap<PathBuf, FileState> {
    let mut out = HashMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                if is_temp_name(&path) {
                    continue;
                }
                if let Ok(m) = entry.metadata() {
                    let mtime = m.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    out.insert(path, (m.len(), mtime));
                }
            }
        }
    }
    out
}

/// Pure diff: previous scan vs current scan → file events +
/// (scanned, new, changed, gone). Unit-tested on Linux.
pub fn reconcile(
    prev: &HashMap<PathBuf, FileState>,
    cur: &HashMap<PathBuf, FileState>,
) -> (Vec<EyeEvent>, (u64, u64, u64)) {
    let mut events = Vec::new();
    let mut new = 0u64;
    let mut changed = 0u64;
    let mut gone = 0u64;
    for (path, state) in cur {
        match prev.get(path) {
            None => {
                new += 1;
                events.push(EyeEvent::FileCreated { path: path.clone() });
                events.push(EyeEvent::FileCompleted {
                    path: path.clone(),
                    size: state.0,
                });
            }
            Some(old) if old != state => {
                changed += 1;
                events.push(EyeEvent::FileCompleted {
                    path: path.clone(),
                    size: state.0,
                });
            }
            _ => {}
        }
    }
    for path in prev.keys() {
        if !cur.contains_key(path) {
            gone += 1;
            events.push(EyeEvent::FileDeleted { path: path.clone() });
        }
    }
    (events, (cur.len() as u64, new, changed, gone))
}

/// Start the reconciler thread. Emits `eye.reconciled` after every
/// scan (even a baseline-only one) so the log proves the thread ran.
pub fn start_reconciler(
    dirs: Vec<PathBuf>,
    tx: SyncSender<EyeEvent>,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    interval: Duration,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut previous: HashMap<PathBuf, FileState> = HashMap::new();
        let mut first = true;
        loop {
            // Sleep in small slices so `stop` reacts fast.
            let mut slept = Duration::ZERO;
            while slept < interval && !stop.load(Ordering::Relaxed) {
                let step = Duration::from_millis(200).min(interval - slept);
                std::thread::sleep(step);
                slept += step;
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if paused.load(Ordering::Relaxed) {
                // Paused: skip this scan AND re-baseline on the next
                // one, so files created while stopped are never logged.
                first = true;
                continue;
            }
            let mut current = HashMap::new();
            for d in &dirs {
                current.extend(scan_dir(d));
            }
            if first {
                first = false;
                previous = current;
                let scanned = previous.len() as u64;
                let _ = tx.send(EyeEvent::EyeReconciled {
                    scanned,
                    new: 0,
                    changed: 0,
                    gone: 0,
                });
                continue;
            }
            let (events, (scanned, new, changed, gone)) = reconcile(&previous, &current);
            for ev in events {
                // Reconciled file events are critical (condition 12):
                // block rather than drop when the queue is full.
                if tx.send(ev).is_err() {
                    break;
                }
            }
            let _ = tx.send(EyeEvent::EyeReconciled {
                scanned,
                new,
                changed,
                gone,
            });
            previous = current;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(size: u64, secs: u64) -> FileState {
        (size, SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
    }

    #[test]
    fn reconcile_reports_new_changed_and_gone() {
        let mut prev = HashMap::new();
        prev.insert(PathBuf::from("/w/keep.txt"), state(10, 100));
        prev.insert(PathBuf::from("/w/change.txt"), state(10, 100));
        prev.insert(PathBuf::from("/w/gone.txt"), state(10, 100));
        let mut cur = HashMap::new();
        cur.insert(PathBuf::from("/w/keep.txt"), state(10, 100));
        cur.insert(PathBuf::from("/w/change.txt"), state(20, 100));
        cur.insert(PathBuf::from("/w/new.txt"), state(5, 200));
        let (events, (scanned, new, changed, gone)) = reconcile(&prev, &cur);
        assert_eq!((scanned, new, changed, gone), (3, 1, 1, 1));
        assert!(events.iter().any(|e| matches!(e, EyeEvent::FileCreated { path } if path == &PathBuf::from("/w/new.txt"))));
        assert!(events.iter().any(|e| matches!(e, EyeEvent::FileCompleted { path, size: 20 } if path == &PathBuf::from("/w/change.txt"))));
        assert!(events.iter().any(|e| matches!(e, EyeEvent::FileDeleted { path } if path == &PathBuf::from("/w/gone.txt"))));
        assert!(!events.iter().any(|e| matches!(e, EyeEvent::FileCompleted { path, .. } if path == &PathBuf::from("/w/keep.txt"))));
    }
}
