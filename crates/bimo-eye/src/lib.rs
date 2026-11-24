//! The Eye — Track A Unit 2 safe core.
//!
//! Scope (spec `track-a-unit2-eye-core-build.md`, council condition 10):
//! the local JSONL event log + file watcher + background hash worker +
//! periodic process snapshot + stop file + heartbeat. No window titles,
//! no screenshots, no window events in this core — those come with their
//! own spikes afterwards.
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
