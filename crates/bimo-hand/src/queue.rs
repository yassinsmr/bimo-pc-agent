//! The hand queue (`hand.queue.jsonl`), mirroring bimo-eye `log.rs`.
//!
//! One JSON line per command, DPAPI-encrypted per line (see `crypto.rs`),
//! fail-closed. Hash chain: `sha256(prev_hash_hex + canonical_json(cmd
//! without the hash field))`, `GENESIS` for the first line. `"schema": 1`
//! is mandatory. 50 MB rotation, 30-day retention.
//!
//! Semantics (decided, and documented here):
//! - TTL is the total lifetime from `issued_ts` (waiting + execution).
//!   A command whose TTL expires before acceptance never executes
//!   (marked `expired`). A running command is NEVER killed by TTL
//!   expiry alone — no automatic TTL watchdog exists in v1; a TTL stop
//!   arrives only as an explicit `hand.stop` filing (reason "ttl"),
//!   and the supervisor's exec monitor consults
//!   `update::ttl_kill_exempt` before arming it, so a running `update`
//!   survives a TTL stop (council 28 cond. 1; wired council 34
//!   cond. 3, c80; proof 8.12). A non-exempt kind killed by a filed
//!   TTL stop is marked `stopped`, not `expired`.
//! - `dedup_key` is `v1:<kind>:<sha256(canonical args)>`. The same key while
//!   queued/running makes the second command `duplicate`, never executed.
//!   After completion the key stays in the persisted dedup window
//!   (`hand.dedup.json`, 24 h), so a replay after completion is still
//!   `duplicate` (replay protection). EXCEPTION: `update` commands use
//!   the design-form key `update:<package>:<frozen-version>`
//!   (`update::update_dedup_key`, council 28 condition 1).
//! - States: `queued -> running -> done | failed | expired | duplicate |
//!   reverted | stopped | revert_failed | needs_approval |
//!   blocked_guardian_absent | blocked_eicar | partial | needs_restart`.
//!   `partial` and `needs_restart` are `update` states (council 28
//!   condition 4): `partial` = killed mid-update, version neither old
//!   nor new; `needs_restart` = the installer asked for a restart
//!   (never `done`).
//! - `stopped` means killed by a stop. It is NEVER auto-resumed; it needs
//!   an explicit re-queue with a new id.
//! - Commands come only from the secure link (Unit 1); the local queue is
//!   the only entry point.

use crate::crypto::{detect_mode, protect_line, unprotect_line};
use crate::{canonical_json, read_json_file, sha256_hex, utc_now_secs, write_json_file};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const QUEUE_FILE: &str = "hand.queue.jsonl";
pub const DEDUP_FILE: &str = "hand.dedup.json";
pub const SCHEMA: u32 = 1;
pub const GENESIS: &str = "GENESIS";
pub const MAX_QUEUE_BYTES: u64 = 50 * 1024 * 1024;
pub const DEDUP_WINDOW_SECS: u64 = 24 * 3600;
pub const RETENTION_SECS: u64 = 30 * 24 * 3600;

/// A command in the queue. `hash` is the hash-chain link of this line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    pub kind: String,
    pub args: Value,
    pub ttl_secs: u64,
    pub dedup_key: String,
    pub nonce: String,
    pub issued_ts: u64,
    pub state: String,
    pub revert_plan: Value,
    pub needs_approval: bool,
    pub approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Outcome of [`Queue::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Enqueued,
    Duplicate,
}

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `v1:<kind>:<sha256(canonical args)>`.
pub fn dedup_key_for(kind: &str, args: &Value) -> String {
    format!("v1:{}:{}", kind, sha256_hex(canonical_json(args).as_bytes()))
}

/// System CSPRNG: 16 random bytes (128-bit nonce).
/// Windows: BCryptGenRandom with the system-preferred RNG (bcrypt.dll,
/// same raw-extern pattern as msi.rs — no new dependency).
/// Other platforms: /dev/urandom. Both are the OS CSPRNG; the old
/// time+pid+counter material survives only as a documented last-resort
/// fallback if the OS source itself fails (it never does in practice).
/// (c78 merge: restored from the update branch — main's new_nonce used
/// the predictable old material; §30.1 fix.)
#[cfg(windows)]
mod csprng {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            halgorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            size: u32,
            flags: u32,
        ) -> i32;
    }
    pub fn random_16() -> Option<[u8; 16]> {
        let mut buf = [0u8; 16];
        // hAlgorithm NULL + BCRYPT_USE_SYSTEM_PREFERRED_RNG (0x2).
        let rc = unsafe { BCryptGenRandom(std::ptr::null_mut(), buf.as_mut_ptr(), 16, 0x0000_0002) };
        if rc == 0 {
            Some(buf)
        } else {
            None
        }
    }
}
#[cfg(not(windows))]
mod csprng {
    pub fn random_16() -> Option<[u8; 16]> {
        use std::io::Read;
        let mut buf = [0u8; 16];
        std::fs::File::open("/dev/urandom")
            .ok()?
            .read_exact(&mut buf)
            .ok()?;
        Some(buf)
    }
}

/// A random 128-bit hex nonce from the system CSPRNG (§30.1 fix:
/// the old time+pid+counter material was predictable).
pub fn new_nonce() -> String {
    if let Some(bytes) = csprng::random_16() {
        return crate::hex_encode(&bytes);
    }
    // Last-resort fallback only (OS CSPRNG unavailable): the old
    // material, labelled here so no reader mistakes it for random.
    let n = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);
    let material = format!(
        "{}-{}-{}-{:?}",
        utc_now_secs(),
        std::process::id(),
        n,
        std::thread::current().id()
    );
    sha256_hex(material.as_bytes())
}

/// Build a new queued command. The revert plan is recorded at enqueue
/// time, before execution (see `revert.rs`).
pub fn new_command(
    id: &str,
    kind: &str,
    args: Value,
    ttl_secs: u64,
    revert_plan: Value,
) -> Command {
    Command {
        dedup_key: dedup_key_for(kind, &args),
        id: id.to_string(),
        kind: kind.to_string(),
        args,
        ttl_secs,
        nonce: new_nonce(),
        issued_ts: utc_now_secs(),
        state: "queued".to_string(),
        revert_plan,
        needs_approval: false,
        approved: false,
        reason: None,
        hash: None,
    }
}

/// True when the command's total lifetime (wait + execution) is over.
pub fn is_expired(cmd: &Command, now_secs: u64) -> bool {
    now_secs > cmd.issued_ts.saturating_add(cmd.ttl_secs)
}

/// True when the command is older than the 30-day retention window.
pub fn retention_expired(cmd: &Command, now_secs: u64) -> bool {
    now_secs > cmd.issued_ts.saturating_add(RETENTION_SECS)
}

fn chain_hash(prev_hash: &str, cmd: &Command) -> String {
    let mut bare = cmd.clone();
    bare.hash = None;
    let value = serde_json::to_value(&bare).unwrap_or(Value::Null);
    sha256_hex(format!("{}{}", prev_hash, canonical_json(&value)).as_bytes())
}

/// The queue file in `data_dir`, with its hash chain verified on open.
pub struct Queue {
    pub data_dir: PathBuf,
    prev_hash: String,
    count: usize,
}

impl Queue {
    pub fn queue_path(data_dir: &Path) -> PathBuf {
        data_dir.join(QUEUE_FILE)
    }

    pub fn dedup_path(data_dir: &Path) -> PathBuf {
        data_dir.join(DEDUP_FILE)
    }

    /// Open (creating if needed) and verify the whole hash chain.
    /// Fail-closed: refuses to open when encryption is unavailable.
    pub fn open(data_dir: &Path) -> Result<Queue, String> {
        detect_mode()?;
        fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
        let mut q = Queue {
            data_dir: data_dir.to_path_buf(),
            prev_hash: GENESIS.to_string(),
            count: 0,
        };
        if Self::queue_path(data_dir).exists() {
            let cmds = q.read_all()?;
            q.count = cmds.len();
            if let Some(last) = cmds.last() {
                q.prev_hash = last.hash.clone().unwrap_or_else(|| GENESIS.to_string());
            }
        }
        Ok(q)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Read and verify every line (schema + hash chain). Any mismatch is
    /// an error: the chain is tamper-EVIDENCE, and a broken chain is
    /// reported, never silently accepted.
    pub fn read_all(&self) -> Result<Vec<Command>, String> {
        let path = Self::queue_path(&self.data_dir);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let mut prev = GENESIS.to_string();
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let plain = unprotect_line(line)?;
            let value: Value =
                serde_json::from_str(&plain).map_err(|e| format!("queue line {}: {}", i, e))?;
            if value.get("schema").and_then(|v| v.as_u64()) != Some(SCHEMA as u64) {
                return Err(format!("queue line {}: missing or wrong schema", i));
            }
            let mut cmd: Command = serde_json::from_value(value.clone())
                .map_err(|e| format!("queue line {}: {}", i, e))?;
            let stored = cmd.hash.clone().ok_or(format!("queue line {}: no hash", i))?;
            let expected = chain_hash(&prev, &cmd);
            if expected != stored {
                return Err(format!(
                    "queue line {}: hash chain broken (tamper evidence)",
                    i
                ));
            }
            cmd.hash = Some(stored);
            prev = cmd.hash.clone().unwrap();
            out.push(cmd);
        }
        Ok(out)
    }

    fn rewrite_all(&self, cmds: &[Command]) -> Result<(), String> {
        let mut prev = GENESIS.to_string();
        let mut lines = String::new();
        for cmd in cmds {
            let mut c = cmd.clone();
            c.hash = Some(chain_hash(&prev, &c));
            prev = c.hash.clone().unwrap();
            let mut value = serde_json::to_value(&c).map_err(|e| e.to_string())?;
            value["schema"] = json!(SCHEMA);
            lines.push_str(&protect_line(&canonical_json(&value))?);
            lines.push('\n');
        }
        fs::write(Self::queue_path(&self.data_dir), lines).map_err(|e| e.to_string())
    }

    /// Append a command, or report `Duplicate` when its `dedup_key` is
    /// already queued/running, or inside the 24 h dedup window.
    pub fn append(&mut self, cmd: &mut Command) -> Result<EnqueueOutcome, String> {
        if self.is_duplicate(&cmd.dedup_key) {
            return Ok(EnqueueOutcome::Duplicate);
        }
        // 50 MB rotation: archive the full file and start a fresh chain.
        let path = Self::queue_path(&self.data_dir);
        if path.exists() {
            if let Ok(meta) = fs::metadata(&path) {
                if meta.len() > MAX_QUEUE_BYTES {
                    let _ = fs::rename(&path, self.data_dir.join("hand.queue.jsonl.1"));
                    self.prev_hash = GENESIS.to_string();
                    self.count = 0;
                }
            }
        }
        cmd.hash = Some(chain_hash(&self.prev_hash, cmd));
        self.prev_hash = cmd.hash.clone().unwrap();
        let mut value = serde_json::to_value(&cmd.clone()).map_err(|e| e.to_string())?;
        value["schema"] = json!(SCHEMA);
        let line = protect_line(&canonical_json(&value))?;
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        f.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        f.write_all(b"\n").map_err(|e| e.to_string())?;
        self.count += 1;
        Ok(EnqueueOutcome::Enqueued)
    }

    /// Set a command's state (and optional reason), re-chaining the file.
    /// Marking `done` also records the dedup key in the 24 h window.
    pub fn mark(&self, id: &str, state: &str, reason: Option<&str>) -> Result<(), String> {
        let mut cmds = self.read_all()?;
        let mut done_cmd: Option<Command> = None;
        let mut found = false;
        for cmd in cmds.iter_mut() {
            if cmd.id == id {
                cmd.state = state.to_string();
                cmd.reason = reason.map(|r| r.to_string());
                found = true;
                if state == "done" {
                    done_cmd = Some(cmd.clone());
                }
            }
        }
        if !found {
            return Err(format!("queue: no command {}", id));
        }
        self.rewrite_all(&cmds)?;
        if let Some(cmd) = done_cmd {
            self.record_completion(&cmd)?;
        }
        Ok(())
    }

    /// True when the key is queued/running now, or completed within 24 h.
    pub fn is_duplicate(&self, dedup_key: &str) -> bool {
        if let Ok(cmds) = self.read_all() {
            for cmd in &cmds {
                if cmd.dedup_key == dedup_key && (cmd.state == "queued" || cmd.state == "running") {
                    return true;
                }
            }
        }
        if let Some(window) = read_json_file(&Self::dedup_path(&self.data_dir)) {
            if let Some(keys) = window.get("keys").and_then(|v| v.as_object()) {
                if let Some(ts) = keys.get(dedup_key).and_then(|v| v.as_u64()) {
                    if utc_now_secs() < ts.saturating_add(DEDUP_WINDOW_SECS) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Record a completed command's dedup key (24 h window), pruning old keys.
    pub fn record_completion(&self, cmd: &Command) -> Result<(), String> {
        let path = Self::dedup_path(&self.data_dir);
        let mut keys: HashMap<String, u64> = HashMap::new();
        if let Some(window) = read_json_file(&path) {
            if let Some(obj) = window.get("keys").and_then(|v| v.as_object()) {
                for (k, v) in obj {
                    if let Some(ts) = v.as_u64() {
                        if utc_now_secs() < ts.saturating_add(DEDUP_WINDOW_SECS) {
                            keys.insert(k.clone(), ts);
                        }
                    }
                }
            }
        }
        keys.insert(cmd.dedup_key.clone(), utc_now_secs());
        let mut obj = serde_json::Map::new();
        for (k, v) in keys {
            obj.insert(k, json!(v));
        }
        write_json_file(&path, &json!({"keys": obj}))
    }

    /// Drop commands older than the 30-day retention window. Returns how
    /// many were dropped.
    pub fn purge_retention(&self) -> Result<usize, String> {
        let now = utc_now_secs();
        let cmds = self.read_all()?;
        let kept: Vec<Command> = cmds
            .iter()
            .filter(|c| !retention_expired(c, now))
            .cloned()
            .collect();
        let dropped = cmds.len() - kept.len();
        if dropped > 0 {
            self.rewrite_all(&kept)?;
        }
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        std::env::set_var("BIMO_HAND_PLAINTEXT_OK", "1");
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("bimo-hand-qtest-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample(id: &str) -> Command {
        new_command(
            id,
            "download",
            json!({"url": "https://example.invalid/f.bin", "size_bytes": 123}),
            3600,
            json!({"output": "f.bin"}),
        )
    }

    #[test]
    fn hash_chain_verifies_and_tamper_breaks_it() {
        let dir = test_dir();
        let mut q = Queue::open(&dir).unwrap();
        let mut a = sample("a");
        let mut b = sample("b");
        // Distinct args => distinct dedup key (identical args would be Duplicate).
        b.args = json!({"url": "https://example.invalid/g.bin", "size_bytes": 456});
        b.dedup_key = dedup_key_for("download", &b.args);
        assert_eq!(q.append(&mut a).unwrap(), EnqueueOutcome::Enqueued);
        assert_eq!(q.append(&mut b).unwrap(), EnqueueOutcome::Enqueued);
        let cmds = q.read_all().unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].hash, Some(chain_hash(GENESIS, &cmds[0])));
        // Tamper with one stored line: the chain must break.
        let path = Queue::queue_path(&dir);
        let text = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();
        lines[0].push('x');
        fs::write(&path, lines.join("\n")).unwrap();
        assert!(q.read_all().is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dedup_blocks_replay_within_24h() {
        let dir = test_dir();
        let mut q = Queue::open(&dir).unwrap();
        let mut a = sample("first");
        assert_eq!(q.append(&mut a).unwrap(), EnqueueOutcome::Enqueued);
        // Same kind + same args => same dedup key, while queued.
        let mut replay = sample("second");
        replay.dedup_key = a.dedup_key.clone();
        assert_eq!(q.append(&mut replay).unwrap(), EnqueueOutcome::Duplicate);
        // After completion the 24 h window still blocks the replay.
        q.mark("first", "done", None).unwrap();
        let mut replay2 = sample("third");
        replay2.dedup_key = a.dedup_key.clone();
        assert_eq!(q.append(&mut replay2).unwrap(), EnqueueOutcome::Duplicate);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ttl_is_total_lifetime() {
        let mut cmd = sample("t");
        cmd.issued_ts = 1000;
        cmd.ttl_secs = 60;
        assert!(!is_expired(&cmd, 1059));
        assert!(is_expired(&cmd, 1061));
    }

    #[test]
    fn dedup_key_is_stable_for_same_args() {
        let a = dedup_key_for("install", &json!({"id": "x", "v": 2}));
        let b = dedup_key_for("install", &json!({"v": 2, "id": "x"}));
        assert_eq!(a, b);
        assert!(a.starts_with("v1:install:"));
    }

    #[test]
    fn nonce_is_32_hex_and_unique() {
        // Sanity only: uniqueness + shape. A unit test cannot prove
        // CSPRNG quality; the source (BCrypt / /dev/urandom) is the claim.
        // (c78 merge: restored from the update branch.)
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let n = new_nonce();
            assert_eq!(n.len(), 32, "nonce must be 128-bit hex");
            assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(seen.insert(n), "duplicate nonce");
        }
    }
}
