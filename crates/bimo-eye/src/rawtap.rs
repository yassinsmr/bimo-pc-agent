//! Raw file-event tap (council 23, diagnostic S4, cycle 66).
//!
//! A SECOND, independent `notify` watcher on the same folders as the
//! debounced monitor — it records EVERY raw event the OS delivers,
//! in its own file, on its own thread. It never touches the debounced
//! pipeline (no change to the notify store, the debounce, or the
//! re-arming — D3): it is instrumentation only, built so the S4
//! diagnostic can tell WHERE the eye goes blind (h1/h2/h3/h4).
//!
//! What it writes (`eye-raw-events.jsonl` in the data dir, plain JSON):
//! - `raw.tap-started` — one line at arming (dirs + debounce window);
//!   its presence proves the tap was alive (D2).
//! - `raw.event` — one line per raw notify event (kind + paths).
//! - `raw.flood` — one line per watcher ERROR delivered by notify.
//!   SOURCE FINDING (cycle 66, read from notify 7.0.0 windows.rs):
//!   the Windows backend NEVER emits an overflow error —
//!   `handle_event` only special-cases ERROR_OPERATION_ABORTED and
//!   otherwise parses the (possibly stale/zeroed) 16 KiB buffer
//!   (`BUF_SIZE = 16384`) as if it held valid entries, emitting
//!   nothing. So a buffer overflow during a burst is SILENT by
//!   construction and no flood line can appear from notify itself.
//!   Flood evidence in the S4 diagnostic is therefore COVERAGE:
//!   the raw tap records exactly which expected files it saw, and
//!   missing files ARE the flood signature. A `raw.flood` line, if
//!   one ever appears, would contradict this reading — record it.
//! - `shadow.decision` — the debounce window (same seconds as the
//!   real debouncer) simulated over the raw stream in parallel: a
//!   path quiet for the window "would-complete" (Create/Modify) or
//!   "would-delete" (Remove). The shadow never feeds the real
//!   debouncer; it only says what the debouncer SHOULD have emitted,
//!   so the diagnostic can separate "debouncer swallowed it" (h2)
//!   from "notify never delivered it" (h1).
//! - `raw.heartbeat` — every 2 s: counts of raw events, flood lines,
//!   shadow decisions pending/decided. Independent of the eye's
//!   general heartbeat: if the eye heartbeat lives while the raw
//!   heartbeat stops, the file path died alone (h4).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::utc_now_rfc3339;

/// What the shadow debounce would do for one path, mirroring the
/// real debouncer's quiet-window rule over the raw stream only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShadowKind {
    WouldComplete,
    WouldDelete,
    Ignore,
}

fn shadow_kind(kind: &notify::EventKind) -> ShadowKind {
    use notify::EventKind;
    match kind {
        EventKind::Create(_) => ShadowKind::WouldComplete,
        EventKind::Modify(_) => ShadowKind::WouldComplete,
        EventKind::Remove(_) => ShadowKind::WouldDelete,
        _ => ShadowKind::Ignore,
    }
}

struct PathState {
    last_seen: Instant,
    count: u64,
    kind: ShadowKind,
    decided: bool,
}

/// The shadow debounce: pure state machine over raw events, so the
/// decision rule is unit-testable without a live watcher.
struct ShadowTracker {
    debounce: Duration,
    states: HashMap<PathBuf, PathState>,
    decided_total: u64,
}

impl ShadowTracker {
    fn new(debounce: Duration) -> Self {
        ShadowTracker {
            debounce,
            states: HashMap::new(),
            decided_total: 0,
        }
    }

    /// Record one raw event (kind + paths) at `now`.
    /// A rename with two paths tracks only the To path (paths[1]),
    /// like `map_event`; a single-path rename half is ignored.
    fn note(&mut self, kind: &notify::EventKind, paths: &[PathBuf], now: Instant) {
        use notify::event::ModifyKind;
        use notify::EventKind;
        let tracked: &[PathBuf] = match kind {
            EventKind::Modify(ModifyKind::Name(_)) if paths.len() == 2 => &paths[1..],
            EventKind::Modify(ModifyKind::Name(_)) => return,
            _ => paths,
        };
        let sk = shadow_kind(kind);
        for p in tracked {
            let st = self.states.entry(p.clone()).or_insert(PathState {
                last_seen: now,
                count: 0,
                kind: sk,
                decided: false,
            });
            st.last_seen = now;
            st.count += 1;
            st.kind = sk;
            st.decided = false; // a new event re-arms the decision
        }
    }

    /// Emit decisions for paths quiet for the debounce window.
    /// Returns (path, decision, raw event count for the path).
    fn sweep(&mut self, now: Instant) -> Vec<(PathBuf, ShadowKind, u64)> {
        let mut out = Vec::new();
        for (p, st) in self.states.iter_mut() {
            if !st.decided && st.kind != ShadowKind::Ignore && now.duration_since(st.last_seen) >= self.debounce {
                st.decided = true;
                self.decided_total += 1;
                out.push((p.clone(), st.kind, st.count));
            }
        }
        out
    }

    fn pending(&self) -> usize {
        self.states
            .values()
            .filter(|s| !s.decided && s.kind != ShadowKind::Ignore)
            .count()
    }

    fn decided_total(&self) -> u64 {
        self.decided_total
    }
}

/// Start the raw tap thread. Returns the join handle. The thread ends
/// when the `stop` flag is set (checked at every 2 s heartbeat tick;
/// a burst of events cannot starve the check for longer than the
/// receive timeout). The file is flushed after every line, so the
/// workflow can read it live with the same FileShare.ReadWrite open
/// the eye log needs (spike-log.ps1 sharing rule).
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
pub fn start_raw_tap(
    dirs: Vec<PathBuf>,
    data_dir: PathBuf,
    stop: Arc<AtomicBool>,
    debounce: Duration,
) -> Result<JoinHandle<()>, String> {
    use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};

    let path = data_dir.join("eye-raw-events.jsonl");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("cannot open raw tap log {}: {e}", path.display()))?;
    let mut writer = BufWriter::new(file);
    let started = serde_json::json!({
        "type": "raw.tap-started",
        "ts": utc_now_rfc3339(),
        "dirs": dirs.iter().map(|d| d.display().to_string()).collect::<Vec<_>>(),
        "debounce_secs": debounce.as_secs(),
    });
    writeln!(writer, "{started}")
        .map_err(|e| format!("cannot write raw tap log: {e}"))?;
    writer
        .flush()
        .map_err(|e| format!("cannot flush raw tap log: {e}"))?;

    let (tx, rx) = std::sync::mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = RecommendedWatcher::new(tx, Config::default())
        .map_err(|e| format!("cannot create raw tap watcher: {e}"))?;
    let mut watched = 0usize;
    for dir in &dirs {
        if dir.exists() {
            watcher
                .watch(dir, RecursiveMode::Recursive)
                .map_err(|e| format!("cannot raw-watch {}: {e}", dir.display()))?;
            watched += 1;
        }
    }

    let handle = std::thread::spawn(move || {
        let _watcher = watcher; // keep alive until the thread ends
        let mut tracker = ShadowTracker::new(debounce);
        let mut raw_events: u64 = 0;
        let mut flood_lines: u64 = 0;
        loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(Ok(ev)) => {
                    raw_events += 1;
                    let line = serde_json::json!({
                        "type": "raw.event",
                        "ts": utc_now_rfc3339(),
                        "kind": format!("{:?}", ev.kind),
                        "paths": ev.paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                    });
                    let _ = writeln!(writer, "{line}");
                    let _ = writer.flush();
                    tracker.note(&ev.kind, &ev.paths, Instant::now());
                }
                Ok(Err(e)) => {
                    // THE flood signal — expected ABSENT on Windows
                    // (notify 7 windows.rs never emits an overflow
                    // error); if one ever appears, it contradicts the
                    // source reading, so record it verbatim.
                    flood_lines += 1;
                    let line = serde_json::json!({
                        "type": "raw.flood",
                        "ts": utc_now_rfc3339(),
                        "error": format!("{e}"),
                    });
                    let _ = writeln!(writer, "{line}");
                    let _ = writer.flush();
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let now = Instant::now();
                    for (p, kind, count) in tracker.sweep(now) {
                        let decision = match kind {
                            ShadowKind::WouldComplete => "would-complete",
                            ShadowKind::WouldDelete => "would-delete",
                            ShadowKind::Ignore => continue,
                        };
                        let line = serde_json::json!({
                            "type": "shadow.decision",
                            "ts": utc_now_rfc3339(),
                            "path": p.display().to_string(),
                            "decision": decision,
                            "raw_events": count,
                        });
                        let _ = writeln!(writer, "{line}");
                    }
                    let hb = serde_json::json!({
                        "type": "raw.heartbeat",
                        "ts": utc_now_rfc3339(),
                        "raw_events_seen": raw_events,
                        "flood_lines": flood_lines,
                        "shadow_pending": tracker.pending(),
                        "shadow_decided": tracker.decided_total(),
                        "watched_dirs": watched,
                    });
                    let _ = writeln!(writer, "{hb}");
                    let _ = writer.flush();
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        // Final sweep so decisions pending at stop are not lost; then
        // one last heartbeat marking the tap's end.
        let now = Instant::now();
        for (p, kind, count) in tracker.sweep(now) {
            let decision = match kind {
                ShadowKind::WouldComplete => "would-complete",
                ShadowKind::WouldDelete => "would-delete",
                ShadowKind::Ignore => continue,
            };
            let line = serde_json::json!({
                "type": "shadow.decision",
                "ts": utc_now_rfc3339(),
                "path": p.display().to_string(),
                "decision": decision,
                "raw_events": count,
            });
            let _ = writeln!(writer, "{line}");
        }
        let hb = serde_json::json!({
            "type": "raw.heartbeat",
            "ts": utc_now_rfc3339(),
            "raw_events_seen": raw_events,
            "flood_lines": flood_lines,
            "shadow_pending": tracker.pending(),
            "shadow_decided": tracker.decided_total(),
            "watched_dirs": watched,
        });
        let _ = writeln!(writer, "{hb}");
        let _ = writer.flush();
    });
    Ok(handle)
}

/// Non-desktop fallback: no watcher, but the tap-started line still
/// records that the platform has no raw tap — absence as data (D2).
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn start_raw_tap(
    _dirs: Vec<PathBuf>,
    data_dir: PathBuf,
    stop: Arc<AtomicBool>,
    _debounce: Duration,
) -> Result<JoinHandle<()>, String> {
    let path = data_dir.join("eye-raw-events.jsonl");
    let mut writer = BufWriter::new(
        std::fs::File::create(&path)
            .map_err(|e| format!("cannot open raw tap log {}: {e}", path.display()))?,
    );
    let line = serde_json::json!({
        "type": "raw.tap-unsupported",
        "ts": utc_now_rfc3339(),
    });
    let _ = writeln!(writer, "{line}");
    let _ = writer.flush();
    Ok(std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, Event, EventKind, ModifyKind, RemoveKind};
    use std::time::Instant;

    fn now_plus(secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(secs)
    }

    #[test]
    fn shadow_kind_mapping() {
        assert_eq!(
            shadow_kind(&EventKind::Create(CreateKind::Any)),
            ShadowKind::WouldComplete
        );
        assert_eq!(
            shadow_kind(&EventKind::Modify(ModifyKind::Any)),
            ShadowKind::WouldComplete
        );
        assert_eq!(
            shadow_kind(&EventKind::Remove(RemoveKind::Any)),
            ShadowKind::WouldDelete
        );
        assert_eq!(
            shadow_kind(&EventKind::Access(notify::event::AccessKind::Any)),
            ShadowKind::Ignore
        );
    }

    #[test]
    fn shadow_decision_after_quiet_window() {
        let mut t = ShadowTracker::new(Duration::from_secs(2));
        let p = PathBuf::from("/tmp/burst-a-0001.bin");
        let t0 = Instant::now();
        t.note(
            &EventKind::Create(CreateKind::Any),
            std::slice::from_ref(&p),
            t0,
        );
        // Still inside the window: no decision.
        assert!(t.sweep(t0 + Duration::from_secs(1)).is_empty());
        assert_eq!(t.pending(), 1);
        // Quiet for the full window: one decision.
        let out = t.sweep(t0 + Duration::from_secs(2));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, p);
        assert_eq!(out[0].1, ShadowKind::WouldComplete);
        assert_eq!(out[0].2, 1);
        assert_eq!(t.pending(), 0);
        assert_eq!(t.decided_total(), 1);
        // A second sweep decides nothing twice.
        assert!(t.sweep(t0 + Duration::from_secs(5)).is_empty());
        // A new event on the same path re-arms the decision.
        t.note(
            &EventKind::Modify(ModifyKind::Any),
            std::slice::from_ref(&p),
            t0 + Duration::from_secs(6),
        );
        assert_eq!(t.pending(), 1);
        let out = t.sweep(t0 + Duration::from_secs(8));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].2, 2); // two raw events seen for the path
    }

    #[test]
    fn shadow_rename_tracks_to_path_only() {
        let mut t = ShadowTracker::new(Duration::from_secs(2));
        let from = PathBuf::from("/tmp/old.tmp");
        let to = PathBuf::from("/tmp/new.bin");
        let t0 = Instant::now();
        let ev = Event::new(EventKind::Modify(ModifyKind::Name(
            notify::event::RenameMode::Both,
        )))
        .add_path(from.clone())
        .add_path(to.clone());
        t.note(&ev.kind, &ev.paths, t0);
        let out = t.sweep(now_plus(5));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, to);
        // The From path was never tracked: no decision for it.
        assert!(!t.states.contains_key(&from));
    }

    #[test]
    fn shadow_remove_decides_would_delete() {
        let mut t = ShadowTracker::new(Duration::from_secs(2));
        let p = PathBuf::from("/tmp/gone.bin");
        let t0 = Instant::now();
        t.note(
            &EventKind::Remove(RemoveKind::Any),
            std::slice::from_ref(&p),
            t0,
        );
        let out = t.sweep(t0 + Duration::from_secs(3));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].1, ShadowKind::WouldDelete);
    }
}
