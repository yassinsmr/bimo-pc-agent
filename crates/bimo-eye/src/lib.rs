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
/// Shot wiring (feature `eye-shots`, Windows only): the request flag
/// file + the shot producer thread that owns the `bimo-shot` service.
/// Without the feature the module does not exist and the eye runs
/// exactly as before.
#[cfg(all(feature = "eye-shots", windows))]
pub mod shot;
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
    /// A screen shot was taken (cycle 28, feature `eye-shots`).
    /// The event carries the file NAME and cost numbers only — never
    /// screen content, never a window title. The JPEG itself lives in
    /// `data_dir/shots/` (local only; no transfer in v1). `quality`
    /// is `"80"` when the WIC path set it, `"wic-default-fallback"`
    /// when the encoder fell back to the default. `cold` marks the
    /// first frame of a (fresh) session — it carries the setup cost.
    ShotTaken {
        file: PathBuf,
        width: u32,
        height: u32,
        bytes: u64,
        quality: String,
        cold: bool,
        wait_ms: u64,
        encode_ms: u64,
    },
    /// A shot request was REFUSED by the §6 rate limiter (cycle 28).
    /// Explicit refusal, never a silent queue — the guard can see
    /// when something asks for shots too often. `rejected` is the
    /// running total of refusals from this service.
    ShotRateLimited { reason: String, rejected: u64 },
    /// A shot request FAILED (no frame, session error — cycle 28).
    /// A failure is data, never silence (same doctrine as
    /// `hook.recovery_failed`).
    ShotFailed { reason: String },
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
            EyeEvent::ShotTaken { .. } => "shot.taken",
            EyeEvent::ShotRateLimited { .. } => "shot.rate_limited",
            EyeEvent::ShotFailed { .. } => "shot.failed",
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
            EyeEvent::ShotTaken {
                file,
                width,
                height,
                bytes,
                quality,
                cold,
                wait_ms,
                encode_ms,
            } => json!({
                "type": "shot.taken",
                "file": file.display().to_string(),
                "width": width,
                "height": height,
                "bytes": bytes,
                "quality": quality,
                "cold": cold,
                "wait_ms": wait_ms,
                "encode_ms": encode_ms,
            }),
            EyeEvent::ShotRateLimited { reason, rejected } => json!({
                "type": "shot.rate_limited",
                "reason": reason,
                "rejected": rejected,
            }),
            EyeEvent::ShotFailed { reason } => json!({
                "type": "shot.failed",
                "reason": reason,
            }),
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

    #[test]
    fn shot_event_type_strings_are_frozen() {
        let taken = EyeEvent::ShotTaken {
            file: PathBuf::from("shots/shot-000001.jpg"),
            width: 1920,
            height: 1080,
            bytes: 123456,
            quality: "80".to_string(),
            cold: false,
            wait_ms: 300,
            encode_ms: 11,
        };
        assert_eq!(taken.type_str(), "shot.taken");
        assert_eq!(
            EyeEvent::ShotRateLimited {
                reason: "burst".into(),
                rejected: 2
            }
            .type_str(),
            "shot.rate_limited"
        );
        assert_eq!(
            EyeEvent::ShotFailed {
                reason: "x".into()
            }
            .type_str(),
            "shot.failed"
        );
    }

    #[test]
    fn shot_taken_json_carries_cost_not_content() {
        let ev = EyeEvent::ShotTaken {
            file: PathBuf::from("shots/shot-000001.jpg"),
            width: 1920,
            height: 1080,
            bytes: 123456,
            quality: "80".to_string(),
            cold: true,
            wait_ms: 150,
            encode_ms: 12,
        };
        let v = ev.to_json();
        assert_eq!(v["type"], "shot.taken");
        assert_eq!(v["width"], 1920);
        assert_eq!(v["height"], 1080);
        assert_eq!(v["bytes"], 123456);
        assert_eq!(v["quality"], "80");
        assert_eq!(v["cold"], true);
        assert_eq!(v["wait_ms"], 150);
        assert_eq!(v["encode_ms"], 12);
        // No title, no pixels, no screen content of any kind.
        assert!(v.get("title").is_none(), "{}", v);
        assert!(v.get("pixels").is_none(), "{}", v);
        assert!(v.get("image").is_none(), "{}", v);
    }

    #[test]
    fn shot_rate_limited_json_carries_rejected_total() {
        let v = EyeEvent::ShotRateLimited {
            reason: "burst 5/10s".into(),
            rejected: 3,
        }
        .to_json();
        assert_eq!(v["type"], "shot.rate_limited");
        assert_eq!(v["rejected"], 3);
    }
}
