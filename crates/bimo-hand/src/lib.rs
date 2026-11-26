//! bimo-hand: the supervised hand of the BIMO PC agent (Unit 3 Part 4).
//!
//! The hand executes commands from the secure link only, through the local
//! queue, under an elevated supervisor that owns a Windows Job Object.
//! Execution is DISABLED by default (`HandConfig::exec_enabled == false`);
//! only the self-test binary enables it, until the council approves Part 4.
//!
//! Non-Windows logic (queue / control / revert / guardian / executor
//! decisions) has no `cfg(windows)`, so its unit tests also run on Linux.

pub mod control;
pub mod crypto;
pub mod executor;
pub mod guardian;
pub mod queue;
pub mod revert;
pub mod supervisor;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch (UTC). All timestamps in the hand are UTC.
pub fn utc_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Milliseconds since the Unix epoch (UTC).
pub fn utc_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

/// Hex-encode bytes (no extra dependency).
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Decode a lowercase/uppercase hex string. Returns `None` on bad input.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let digit = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    for i in (0..b.len()).step_by(2) {
        out.push((digit(b[i])? << 4) | digit(b[i + 1])?);
    }
    Some(out)
}

/// Canonical JSON: `serde_json::Value` serialises object keys in sorted
/// (BTreeMap) order, so the same value always hashes the same way.
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
}

/// SHA-256 of a file's contents.
pub fn file_sha256(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    Ok(sha256_hex(&data))
}

/// Write a JSON value to `path` (pretty, with a trailing newline).
pub fn write_json_file(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, format!("{}\n", text)).map_err(|e| e.to_string())
}

/// Read a JSON file. Returns `None` when the file is absent or unparsable.
pub fn read_json_file(path: &Path) -> Option<Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Append one JSON line to a `.jsonl` log file in `data_dir`.
pub fn append_log_line(data_dir: &Path, file_name: &str, value: &Value) {
    let path = data_dir.join(file_name);
    let mut line = canonical_json(value);
    line.push('\n');
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Write an alert event file `hand.alert-<ts>-<kind>.json` and return its path.
/// Alerts are files (the delivery route is on the arrival list).
pub fn alert_event(data_dir: &Path, kind: &str, detail: Value) -> PathBuf {
    let ts = utc_now_secs();
    let name = format!("hand.alert-{}-{}.json", ts, kind);
    let path = data_dir.join(name);
    let value = json!({"ts": ts, "kind": kind, "detail": detail});
    let _ = write_json_file(&path, &value);
    append_log_line(data_dir, "hand.log.jsonl", &value);
    path
}

/// Try to rename a directory to a sibling name and back. Used after a kill
/// to prove the installer's file handles were released.
pub fn try_rename_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.with_file_name(format!(
        "{}-rename-test",
        dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "dir".to_string())
    ));
    if fs::rename(dir, &probe).is_err() {
        return false;
    }
    fs::rename(&probe, dir).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_and_hex_round_trip() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v: Value = serde_json::from_str("{\"b\":1,\"a\":2}").unwrap();
        assert_eq!(canonical_json(&v), "{\"a\":2,\"b\":1}");
    }
}
