//! The single log writer: append-only JSONL + hash chain (condition 8).
//!
//! Chain rule: `hash = sha256(prev_hash_hex + canonical_json_without_hash)`
//! where `canonical_json` is the event object serialised with sorted keys
//! (`serde_json::Value`, BTreeMap). The first line of a fresh file chains
//! from the constant `GENESIS`. Any tampering breaks the chain at the
//! first altered line, and `verify_file` reports exactly where.
//!
//! Every line also carries `"schema": 1` (spec §3, frozen since cycle
//! 18, emitted by the writer since the cycle-21 merge). `verify_file`
//! rejects a line without it, or with an unknown version.

use serde_json::Value;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::crypto::{protect_line, unprotect_line, CryptoMode};
use crate::{hex_sha256, utc_now_rfc3339, EyeEvent, LOG_SCHEMA};

/// Previous-hash value for the first line of a fresh log file.
pub const GENESIS: &str = "GENESIS";

/// Rotation: new file at 50 MB (spec section 4). Retention: 30 days.
const ROTATE_BYTES: u64 = 50 * 1024 * 1024;
const RETENTION_DAYS: u64 = 30;

pub struct LogWriter {
    file: Option<BufWriter<File>>,
    path: PathBuf,
    data_dir: PathBuf,
    seq: u64,
    prev_hash: String,
    crypto: CryptoMode,
    writes_since_rotate_check: u32,
}

pub struct VerifyReport {
    pub lines: usize,
    pub valid: bool,
    /// 1-based line number where the chain first breaks, if any.
    pub broken_at: Option<usize>,
    pub reason: Option<String>,
    /// Parsed events in file order (decrypted where needed).
    pub events: Vec<Value>,
}

impl LogWriter {
    /// Open (or resume) the log in `data_dir`. If an existing log is
    /// present and its chain verifies, sequence and chain continue from
    /// its tail. If the chain is broken, the old file is archived as
    /// `.broken-<unix>.jsonl` and a fresh log starts — the break is
    /// recorded as a warning event in the new file, never hidden.
    ///
    /// Fail-closed (eye-core council condition 2): if DPAPI is
    /// unavailable and there is no explicit plaintext opt-in, opening
    /// refuses with a clear error — no log is written in plaintext.
    pub fn open(data_dir: &Path) -> Result<(LogWriter, Option<String>), String> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| format!("cannot create data dir {}: {e}", data_dir.display()))?;
        prune_old_logs(data_dir);
        let path = data_dir.join("eye-events.jsonl");
        let crypto = crate::crypto::detect_mode()?;

        let mut seq = 0u64;
        let mut prev_hash = GENESIS.to_string();
        let mut note: Option<String> = None;
        if path.exists() {
            match verify_file(&path) {
                Ok(rep) if rep.valid => {
                    seq = rep.events.len() as u64;
                    if let Some(last) = rep.events.last() {
                        if let Some(h) = last.get("hash").and_then(|h| h.as_str()) {
                            prev_hash = h.to_string();
                        }
                    }
                    note = Some(format!("resumed log: {} events, chain valid", rep.lines));
                }
                Ok(rep) => {
                    let broken = rep.broken_at.unwrap_or(0);
                    let stamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let archived = data_dir.join(format!("eye-events.broken-{stamp}.jsonl"));
                    let _ = std::fs::rename(&path, &archived);
                    note = Some(format!(
                        "old log chain broken at line {broken}; archived as {}",
                        archived.display()
                    ));
                }
                Err(e) => {
                    let stamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let archived = data_dir.join(format!("eye-events.unreadable-{stamp}.jsonl"));
                    let _ = std::fs::rename(&path, &archived);
                    note = Some(format!("old log unreadable ({e}); archived"));
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("cannot open log {}: {e}", path.display()))?;
        Ok((
            LogWriter {
                file: Some(BufWriter::new(file)),
                path,
                data_dir: data_dir.to_path_buf(),
                seq,
                prev_hash,
                crypto,
                writes_since_rotate_check: 0,
            },
            note,
        ))
    }

    pub fn crypto(&self) -> CryptoMode {
        self.crypto
    }

    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }

    /// Write one event: assigns `seq` + `ts`, chains the hash, protects
    /// the line (DPAPI or plain), appends and flushes.
    pub fn write(&mut self, ev: &EyeEvent) -> Result<(), String> {
        self.seq += 1;
        let mut obj = ev.to_json();
        obj["seq"] = Value::from(self.seq);
        obj["ts"] = Value::from(utc_now_rfc3339());
        // Frozen schema (spec §3, cycle-21 merge): every line carries
        // `"schema": 1`, covered by the hash like every other field.
        obj["schema"] = Value::from(LOG_SCHEMA);
        let canonical = serde_json::to_string(&obj)
            .map_err(|e| format!("cannot serialise event: {e}"))?;
        let hash = hex_sha256(format!("{}{}", self.prev_hash, canonical).as_bytes());
        obj["hash"] = Value::from(hash.clone());
        let line = serde_json::to_string(&obj)
            .map_err(|e| format!("cannot serialise event: {e}"))?;
        // Fail-closed (council condition 2): a protection failure is an
        // error, never a silent plaintext write.
        let disk = protect_line(&line, self.crypto)?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| "log writer is closed".to_string())?;
        writeln!(file, "{disk}").map_err(|e| format!("cannot write log: {e}"))?;
        file.flush()
            .map_err(|e| format!("cannot flush log: {e}"))?;
        self.prev_hash = hash;
        self.writes_since_rotate_check += 1;
        if self.writes_since_rotate_check >= 100 {
            self.writes_since_rotate_check = 0;
            self.maybe_rotate()?;
        }
        Ok(())
    }

    fn maybe_rotate(&mut self) -> Result<(), String> {
        let size = std::fs::metadata(&self.path)
            .map(|m| m.len())
            .unwrap_or(0);
        if size < ROTATE_BYTES {
            return Ok(());
        }
        if let Some(mut f) = self.file.take() {
            f.flush()
                .map_err(|e| format!("cannot flush log before rotation: {e}"))?;
        }
        let stamp = utc_now_rfc3339().replace([':', 'T', 'Z'], "-");
        let rotated = self.data_dir.join(format!("eye-events-{stamp}.jsonl"));
        let _ = std::fs::rename(&self.path, &rotated);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("cannot reopen log after rotation: {e}"))?;
        self.file = Some(BufWriter::new(file));
        self.seq = 0;
        self.prev_hash = GENESIS.to_string();
        Ok(())
    }

    /// Flush and close. After this the writer must not be used again.
    pub fn close(&mut self) {
        if let Some(mut f) = self.file.take() {
            let _ = f.flush();
        }
    }
}

/// Verify a log file: decrypt lines where needed, parse, recompute the
/// chain. Returns the parsed events in order plus validity.
pub fn verify_file(path: &Path) -> Result<VerifyReport, String> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let reader = BufReader::new(file);
    let mut events: Vec<Value> = Vec::new();
    let mut prev_hash = GENESIS.to_string();
    let mut lines = 0usize;
    for (idx, raw) in reader.lines().enumerate() {
        let raw = raw.map_err(|e| format!("cannot read line {}: {e}", idx + 1))?;
        if raw.trim().is_empty() {
            continue;
        }
        lines += 1;
        let plain = unprotect_line(&raw)
            .map_err(|e| format!("line {}: {e}", idx + 1))?;
        let mut obj: Value = serde_json::from_str(&plain)
            .map_err(|e| format!("line {}: bad json: {e}", idx + 1))?;
        // Frozen schema (spec §3, cycle-21 merge): a line without
        // `"schema": 1` is invalid — fail-closed, never silently
        // accepted. (Logs written before the merge carry no schema;
        // the writer's resume path archives them with a warning
        // event instead of losing them silently.)
        match obj.get("schema").and_then(|s| s.as_u64()) {
            Some(s) if s == LOG_SCHEMA => {}
            Some(s) => {
                return Ok(VerifyReport {
                    lines,
                    valid: false,
                    broken_at: Some(idx + 1),
                    reason: Some(format!(
                        "line {}: unknown schema version {} (expected {})",
                        idx + 1,
                        s,
                        LOG_SCHEMA
                    )),
                    events,
                });
            }
            None => {
                return Ok(VerifyReport {
                    lines,
                    valid: false,
                    broken_at: Some(idx + 1),
                    reason: Some(format!(
                        "line {}: missing \"schema\" field (expected {})",
                        idx + 1,
                        LOG_SCHEMA
                    )),
                    events,
                });
            }
        }
        let stored = obj
            .get("hash")
            .and_then(|h| h.as_str())
            .ok_or_else(|| format!("line {}: missing hash", idx + 1))?
            .to_string();
        if let Value::Object(map) = &mut obj {
            map.remove("hash");
        }
        let canonical = serde_json::to_string(&obj)
            .map_err(|e| format!("line {}: cannot reserialise: {e}", idx + 1))?;
        let expect = hex_sha256(format!("{prev_hash}{canonical}").as_bytes());
        if expect != stored {
            return Ok(VerifyReport {
                lines,
                valid: false,
                broken_at: Some(idx + 1),
                reason: Some(format!(
                    "hash mismatch at line {} (expected {expect}, stored {stored})",
                    idx + 1
                )),
                events,
            });
        }
        prev_hash = stored;
        // Re-attach the hash for callers that want the full event.
        if let Value::Object(map) = &mut obj {
            map.insert("hash".to_string(), Value::from(prev_hash.clone()));
        }
        events.push(obj);
    }
    // Sequence must be 1..=n with no gaps (fresh file) — a resumed file
    // also keeps its own 1..=n run, so the check holds per file.
    for (i, ev) in events.iter().enumerate() {
        let seq = ev.get("seq").and_then(|s| s.as_u64()).unwrap_or(0);
        if seq as usize != i + 1 {
            return Ok(VerifyReport {
                lines,
                valid: false,
                broken_at: Some(i + 1),
                reason: Some(format!(
                    "sequence gap at line {} (expected {}, got {seq})",
                    i + 1,
                    i + 1
                )),
                events,
            });
        }
    }
    Ok(VerifyReport {
        lines,
        valid: true,
        broken_at: None,
        reason: None,
        events,
    })
}

fn prune_old_logs(data_dir: &Path) {
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(RETENTION_DAYS * 86400))
        .unwrap_or(std::time::UNIX_EPOCH);
    if let Ok(entries) = std::fs::read_dir(data_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("eye-events-") || !name.ends_with(".jsonl") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    if mtime < cutoff {
                        let _ = std::fs::remove_file(&p);
                    }
                }
            }
        }
    }
}

