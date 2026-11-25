//! The Eye — Track A Unit 2 safe core.
//!
//! Scope (spec `track-a-unit2-eye-core-build.md`, council condition 10):
//! the local JSONL event log + file watcher + background hash worker +
//! periodic process snapshot + stop file + heartbeat + window events
//! (merged cycle 21 from the `bimo-wintrack` spike — council-approved,
//! see `track-a-unit2-eye-merge-wintrack.md`). No window titles, no
//! screenshots: this crate never calls `GetWindowText`, and window
//! events carry exe + PID + hwnd only.
//!
//! Honest scope declaration (council condition 7): v1 watches ONLY the
//! configured folders. Anything outside them is NOT covered, and this
//! file says so instead of staying silent about it.

pub mod control;
pub mod crypto;
pub mod eye;
pub mod hash_worker;
pub mod log;
pub mod snapshot;
pub mod watch;

use serde_json::{json, Value};
use std::path::PathBuf;

/// Frozen log schema version (cycle 18 freeze, council condition 1
/// on the window spike; emitted by the writer on every line since
/// the cycle-21 merge — see spec §3). Any rename/redefinition raises
/// this version, with a council note and a doc update.
pub const LOG_SCHEMA: u64 = 1;

/// One event flowing from the producers to the single log writer.
#[derive(Debug, Clone)]
pub enum EyeEvent {
    AgentStart { scope_note: String, crypto: String },
    AgentStop { reason: String },
    Heartbeat,
    Warning { message: String },
    FileCreated { path: PathBuf },
    FileCompleted { path: PathBuf, size: u64 },
    FileDeleted { path: PathBuf },
    FileRenamed { from: PathBuf, to: PathBuf },
    FileHash { path: PathBuf, sha256: String },
    ProcSeen { pid: u32, exe: String },
    ProcGone { pid: u32, exe: String },
    /// Inference only — always `confidence: "low"`, never a trigger for
    /// any alert or quarantine on its own (council condition 4).
    InstallDetected { path: PathBuf },
    /// Log honesty (eye-core council condition 4): the eye records its
    /// own gaps. When the bounded event queue overflows and routine
    /// events are dropped, the writer writes one `log.gap` event
    /// naming how many were dropped and from where — a gap is data,
    /// never silence.
    LogGap { dropped: u64, reason: String },
    /// Window events from the merged `bimo-wintrack` hook (cycle 21).
    /// Frozen naming (spec §12): `app.open` counts ONE top-level
    /// window creation — NOT one app launch (the 47-count rule: a
    /// single launch may produce many `app.open` events). Never a
    /// trigger for any guard decision on its own.
    AppOpen { pid: u32, exe: String, hwnd: u64 },
    AppClose { pid: u32, exe: String, hwnd: u64 },
    AppFocus { pid: u32, exe: String, hwnd: u64 },
    /// The hook died and the watchdog brought it back.
    HookRecovered { after_ms: Option<u64>, reason: Option<String> },
    /// The hook died and the watchdog did NOT bring it back within
    /// the 10 s budget (council condition 3: an explicit failure
    /// event, not silence).
    HookRecoveryFailed { after_ms: Option<u64>, reason: Option<String> },
}

impl EyeEvent {
    /// The `type` string written into the JSONL log.
    pub fn type_str(&self) -> &'static str {
        match self {
            EyeEvent::AgentStart { .. } => "agent.start",
            EyeEvent::AgentStop { .. } => "agent.stop",
            EyeEvent::Heartbeat => "eye.heartbeat",
            EyeEvent::Warning { .. } => "eye.warning",
            EyeEvent::FileCreated { .. } => "file.created",
            EyeEvent::FileCompleted { .. } => "file.completed",
            EyeEvent::FileDeleted { .. } => "file.deleted",
            EyeEvent::FileRenamed { .. } => "file.renamed",
            EyeEvent::FileHash { .. } => "file.hash",
            EyeEvent::ProcSeen { .. } => "proc.seen",
            EyeEvent::ProcGone { .. } => "proc.gone",
            EyeEvent::InstallDetected { .. } => "install.detected",
            EyeEvent::LogGap { .. } => "log.gap",
            EyeEvent::AppOpen { .. } => "app.open",
            EyeEvent::AppClose { .. } => "app.close",
            EyeEvent::AppFocus { .. } => "app.focus",
            EyeEvent::HookRecovered { .. } => "hook.recovered",
            EyeEvent::HookRecoveryFailed { .. } => "hook.recovery_failed",
        }
    }

    /// JSON object for this event, WITHOUT `seq`, `ts` or `hash`
    /// (the writer adds those). Field order does not matter: the writer
    /// canonicalises through `serde_json::Value` (sorted keys) before
    /// hashing, so verification recomputes the same bytes.
    pub fn to_json(&self) -> Value {
        match self {
            EyeEvent::AgentStart { scope_note, crypto } => json!({
                "type": "agent.start",
                "scope_note": scope_note,
                "crypto": crypto,
            }),
            EyeEvent::AgentStop { reason } => json!({
                "type": "agent.stop",
                "reason": reason,
            }),
            EyeEvent::Heartbeat => json!({ "type": "eye.heartbeat" }),
            EyeEvent::Warning { message } => json!({
                "type": "eye.warning",
                "message": message,
            }),
            EyeEvent::FileCreated { path } => json!({
                "type": "file.created",
                "path": path.display().to_string(),
            }),
            EyeEvent::FileCompleted { path, size } => json!({
                "type": "file.completed",
                "path": path.display().to_string(),
                "size": size,
            }),
            EyeEvent::FileDeleted { path } => json!({
                "type": "file.deleted",
                "path": path.display().to_string(),
            }),
            EyeEvent::FileRenamed { from, to } => json!({
                "type": "file.renamed",
                "from": from.display().to_string(),
                "to": to.display().to_string(),
            }),
            EyeEvent::FileHash { path, sha256 } => json!({
                "type": "file.hash",
                "path": path.display().to_string(),
                "sha256": sha256,
            }),
            EyeEvent::ProcSeen { pid, exe } => json!({
                "type": "proc.seen",
                "pid": pid,
                "exe": exe,
            }),
            EyeEvent::ProcGone { pid, exe } => json!({
                "type": "proc.gone",
                "pid": pid,
                "exe": exe,
            }),
            EyeEvent::InstallDetected { path } => json!({
                "type": "install.detected",
                "path": path.display().to_string(),
                "confidence": "low",
            }),
            EyeEvent::LogGap { dropped, reason } => json!({
                "type": "log.gap",
                "dropped": dropped,
                "reason": reason,
            }),
            EyeEvent::AppOpen { pid, exe, hwnd } => json!({
                "type": "app.open",
                "pid": pid,
                "exe": exe,
                "hwnd": hwnd,
            }),
            EyeEvent::AppClose { pid, exe, hwnd } => json!({
                "type": "app.close",
                "pid": pid,
                "exe": exe,
                "hwnd": hwnd,
            }),
            EyeEvent::AppFocus { pid, exe, hwnd } => json!({
                "type": "app.focus",
                "pid": pid,
                "exe": exe,
                "hwnd": hwnd,
            }),
            EyeEvent::HookRecovered { after_ms, reason } => {
                let mut v = json!({
                    "type": "hook.recovered",
                    "pid": 0,
                    "exe": "",
                    "hwnd": 0,
                });
                if let Some(ms) = after_ms {
                    v["after_ms"] = json!(ms);
                }
                if let Some(r) = reason {
                    v["reason"] = json!(r);
                }
                v
            }
            EyeEvent::HookRecoveryFailed { after_ms, reason } => {
                let mut v = json!({
                    "type": "hook.recovery_failed",
                    "pid": 0,
                    "exe": "",
                    "hwnd": 0,
                });
                if let Some(ms) = after_ms {
                    v["after_ms"] = json!(ms);
                }
                if let Some(r) = reason {
                    v["reason"] = json!(r);
                }
                v
            }
        }
    }
}

impl From<bimo_wintrack::WinEvent> for EyeEvent {
    /// Window-event conversion (cycle-21 merge). Pure and total:
    /// every `WinEvent` maps to exactly one `EyeEvent` with the same
    /// frozen type string and the same fields — the hook's `WinEvent`
    /// JSON and the eye log line for it differ only in `seq`/`ts`/
    /// `hash` (added by the writer) and `schema` (added by the
    /// writer since the merge).
    fn from(ev: bimo_wintrack::WinEvent) -> EyeEvent {
        use bimo_wintrack::WinEventKind;
        match ev.kind {
            WinEventKind::AppOpen => EyeEvent::AppOpen {
                pid: ev.pid,
                exe: ev.exe,
                hwnd: ev.hwnd,
            },
            WinEventKind::AppClose => EyeEvent::AppClose {
                pid: ev.pid,
                exe: ev.exe,
                hwnd: ev.hwnd,
            },
            WinEventKind::AppFocus => EyeEvent::AppFocus {
                pid: ev.pid,
                exe: ev.exe,
                hwnd: ev.hwnd,
            },
            WinEventKind::HookRecovered => EyeEvent::HookRecovered {
                after_ms: ev.after_ms,
                reason: ev.reason,
            },
            WinEventKind::HookRecoveryFailed => EyeEvent::HookRecoveryFailed {
                after_ms: ev.after_ms,
                reason: ev.reason,
            },
        }
    }
}

/// UTC timestamp in RFC3339 (`2026-11-24T13:00:00Z`), formatted by hand
/// from `SystemTime` so the crate needs no date dependency.
pub fn utc_now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let tod = secs % 86400;
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mo <= 2 { y + 1 } else { y };
    format!("{yr:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Lowercase hex SHA-256 of `data`.
pub fn hex_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bimo_wintrack::{WinEvent, WinEventKind};

    fn win_event(kind: WinEventKind) -> WinEvent {
        WinEvent {
            kind,
            pid: 1234,
            exe: "notepad.exe".to_string(),
            hwnd: 99,
            after_ms: None,
            reason: None,
        }
    }

    #[test]
    fn window_event_type_strings_are_frozen() {
        assert_eq!(EyeEvent::AppOpen { pid: 1, exe: "x".into(), hwnd: 2 }.type_str(), "app.open");
        assert_eq!(EyeEvent::AppClose { pid: 1, exe: "x".into(), hwnd: 2 }.type_str(), "app.close");
        assert_eq!(EyeEvent::AppFocus { pid: 1, exe: "x".into(), hwnd: 2 }.type_str(), "app.focus");
        assert_eq!(EyeEvent::HookRecovered { after_ms: None, reason: None }.type_str(), "hook.recovered");
        assert_eq!(EyeEvent::HookRecoveryFailed { after_ms: None, reason: None }.type_str(), "hook.recovery_failed");
        // And they are NOT the snapshotter names.
        assert_ne!(EyeEvent::AppOpen { pid: 1, exe: "x".into(), hwnd: 2 }.type_str(), "proc.seen");
    }

    #[test]
    fn win_event_converts_with_same_fields() {
        for (kind, ty) in [
            (WinEventKind::AppOpen, "app.open"),
            (WinEventKind::AppClose, "app.close"),
            (WinEventKind::AppFocus, "app.focus"),
        ] {
            let ev = EyeEvent::from(win_event(kind));
            assert_eq!(ev.type_str(), ty);
            let v = ev.to_json();
            assert_eq!(v["pid"], 1234);
            assert_eq!(v["exe"], "notepad.exe");
            assert_eq!(v["hwnd"], 99);
            // No title ever leaves this crate.
            assert!(v.get("title").is_none(), "{}", v);
        }
    }

    #[test]
    fn hook_events_convert_with_reason() {
        let mut ev = win_event(WinEventKind::HookRecovered);
        ev.after_ms = Some(5023);
        ev.reason = Some("silence-10s-procs-changed".to_string());
        let v = EyeEvent::from(ev).to_json();
        assert_eq!(v["type"], "hook.recovered");
        assert_eq!(v["after_ms"], 5023);
        assert_eq!(v["reason"], "silence-10s-procs-changed");
        assert_eq!(v["pid"], 0);
    }

    #[test]
    fn log_schema_is_one() {
        assert_eq!(LOG_SCHEMA, 1);
    }
}
