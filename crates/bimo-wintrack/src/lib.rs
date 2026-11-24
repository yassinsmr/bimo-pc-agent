//! The window tracker — Track A Unit 2 spike (`bimo-wintrack`).
//!
//! Proves `SetWinEventHook` delivers real window events on real
//! Windows before the eye unit is built on it (spec
//! `track-a-unit2-eye-window-spike.md`).
//!
//! Frozen naming (cycle 16 — council improvement on the eye core):
//! two layers, never mixed. `proc.seen` / `proc.gone` come from the
//! process snapshotter only; `app.open` / `app.close` / `app.focus`
//! come from this hook only. `hook.recovered` is emitted by the
//! internal watchdog when the hook is re-registered. No full window
//! title is ever written to the routine log while `eye.full-titles`
//! is off (the default) — this crate never calls `GetWindowText`.

pub mod wintrack;

pub use wintrack::{tracker_supported, verify_proc_link, WinTrack};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// One window event. Window-level only — never process-level.
#[derive(Debug, Clone)]
pub enum WinEventKind {
    AppOpen,
    AppClose,
    AppFocus,
    HookRecovered,
}

impl WinEventKind {
    /// The frozen `type` string written into the JSONL log.
    pub fn type_str(&self) -> &'static str {
        match self {
            WinEventKind::AppOpen => "app.open",
            WinEventKind::AppClose => "app.close",
            WinEventKind::AppFocus => "app.focus",
            WinEventKind::HookRecovered => "hook.recovered",
        }
    }
}

/// One window event flowing from the hook to the trial log.
#[derive(Debug, Clone)]
pub struct WinEvent {
    pub kind: WinEventKind,
    /// Owning process id (from `GetWindowThreadProcessId`).
    pub pid: u32,
    /// Owning executable basename, e.g. `notepad.exe`.
    pub exe: String,
    /// Window handle as an integer. 0 only for `hook.recovered`.
    pub hwnd: u64,
    /// Milliseconds since the hook died, for `hook.recovered` only.
    pub after_ms: Option<u64>,
    /// Why the hook was re-registered, for `hook.recovered` only.
    pub reason: Option<String>,
}

impl WinEvent {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "type": self.kind.type_str(),
            "pid": self.pid,
            "exe": self.exe,
            "hwnd": self.hwnd,
        });
        if let Some(ms) = self.after_ms {
            v["after_ms"] = json!(ms);
        }
        if let Some(reason) = &self.reason {
            v["reason"] = json!(reason);
        }
        v
    }
}

/// UTC timestamp in RFC3339 (`2026-11-24T13:00:00Z`), formatted by hand
/// from `SystemTime` so the crate needs no date dependency.
pub fn utc_now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-from-days (Howard Hinnant's algorithm), proleptic Gregorian.
    let days = (secs / 86400) as i64;
    let secs_of_day = secs % 86400;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.update(b"\n");
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Append-only trial log in the eye format: every line carries `seq`,
/// `ts`, `prev_hash` and `hash` (hash = sha256 of the canonical line
/// bytes chained on the previous hash). Same format as the safe core,
/// so the same verifier can read both.
pub struct TrialLog {
    path: PathBuf,
    file: File,
    seq: u64,
    prev_hash: String,
}

impl TrialLog {
    pub fn open(path: PathBuf) -> std::io::Result<TrialLog> {
        // Continue the chain from the last line already in the file
        // (checks run as separate processes and share one trial log).
        let (mut seq, mut prev_hash) = (0u64, "GENESIS".to_string());
        if let Ok(f) = File::open(&path) {
            for line in BufReader::new(f).lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if let Some(s) = v.get("seq").and_then(|x| x.as_u64()) {
                        seq = s + 1;
                    }
                    if let Some(h) = v.get("hash").and_then(|x| x.as_str()) {
                        prev_hash = h.to_string();
                    }
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(TrialLog {
            path,
            file,
            seq,
            prev_hash,
        })
    }

    pub fn write(&mut self, event: &WinEvent) {
        let mut v = event.to_json();
        v["seq"] = json!(self.seq);
        v["ts"] = json!(utc_now_rfc3339());
        v["prev_hash"] = json!(self.prev_hash);
        // Canonical bytes: serde_json::Value sorts keys (BTreeMap)
        // when the `preserve_order` feature is off, which it is here.
        let body = serde_json::to_string(&v).unwrap_or_else(|_| "{}".to_string());
        let hash = sha256_hex(format!("{}{}", self.prev_hash, body).as_bytes());
        let mut v2: Value = serde_json::from_str(&body).unwrap_or(json!({}));
        v2["hash"] = json!(hash);
        let line = serde_json::to_string(&v2).unwrap_or_else(|_| "{}".to_string());
        if writeln!(self.file, "{}", line).is_ok() {
            let _ = self.file.flush();
            self.seq += 1;
            self.prev_hash = hash;
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_names_are_exact() {
        assert_eq!(WinEventKind::AppOpen.type_str(), "app.open");
        assert_eq!(WinEventKind::AppClose.type_str(), "app.close");
        assert_eq!(WinEventKind::AppFocus.type_str(), "app.focus");
        assert_eq!(WinEventKind::HookRecovered.type_str(), "hook.recovered");
        // And they are NOT the snapshotter names.
        assert_ne!(WinEventKind::AppOpen.type_str(), "proc.seen");
        assert_ne!(WinEventKind::AppClose.type_str(), "proc.gone");
    }

    #[test]
    fn trial_log_chains_across_reopens() {
        let dir = std::env::temp_dir().join("bimo-wintrack-test-log");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("trial.jsonl");
        let ev = WinEvent {
            kind: WinEventKind::AppFocus,
            pid: 1234,
            exe: "notepad.exe".to_string(),
            hwnd: 99,
            after_ms: None,
            reason: None,
        };
        {
            let mut log = TrialLog::open(path.clone()).unwrap();
            log.write(&ev);
        }
        {
            // Second open must continue seq + chain, not restart it.
            let mut log = TrialLog::open(path.clone()).unwrap();
            log.write(&ev);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["seq"], 0);
        assert_eq!(second["seq"], 1);
        assert_eq!(second["prev_hash"], first["hash"]);
        assert_eq!(first["prev_hash"], "GENESIS");
        assert_eq!(first["type"], "app.focus");
        assert_eq!(first["hwnd"], 99);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
