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
#[cfg(windows)]
pub mod kill;
#[cfg(windows)]
pub mod msi;
#[cfg(windows)]
pub mod win32;

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

// ---------------------------------------------------------------------------
// Non-Windows stubs for the Windows-only modules (v2, cycle 41).
//
// `kill`, `msi` and `win32` are real on Windows only: `msi.dll` /
// `kernel32.dll` / `advapi32.dll` do not exist on other targets (their
// `#[link]` attributes would fail the link), and `win32.rs` uses
// `std::os::windows::ffi::OsStrExt`. The crate's unit tests are specified
// to also run on Linux (spec section 1), and both binaries must therefore
// compile on a Linux host. These inline modules expose exactly the public
// surface the two binaries use, with honest "unsupported on this
// platform" values: every MSI/Win32 call reports failure or absence,
// never a Windows result. The self-test and supervisor binaries only run
// their Windows paths on Windows; on other targets they fail fast through
// these stubs.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub mod kill {
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::time::SystemTime;

    pub const HARD_CAP_MS: u64 = 5000;
    pub const MSI_CANCEL_BUDGET_MS: u64 = 1000;
    pub const TREE_KILL_BUDGET_MS: u64 = 2000;
    pub const VERIFY_BUDGET_MS: u64 = 500;
    pub const POST_CAP_MONITOR_MS: u64 = 1500;
    pub const COOP_WINDOW_MS: u64 = 2000;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum InstallerKind {
        Msi,
        Command,
    }

    impl InstallerKind {
        pub fn as_str(&self) -> &'static str {
            match self {
                InstallerKind::Msi => "msi",
                InstallerKind::Command => "command",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum StopTrigger {
        HandStop,
        Ttl,
        DeadMan,
        Guardian,
    }

    impl StopTrigger {
        pub fn as_str(&self) -> &'static str {
            match self {
                StopTrigger::HandStop => "hand-stop",
                StopTrigger::Ttl => "ttl",
                StopTrigger::DeadMan => "dead-man",
                StopTrigger::Guardian => "guardian",
            }
        }
    }

    #[derive(Debug)]
    pub enum AbortTarget {
        Msi {
            cancel: Arc<AtomicBool>,
            outcome: Arc<Mutex<Option<crate::msi::CancelOutcome>>>,
            product_code: Option<String>,
            name_substring: String,
            target_dir: String,
            pre_msiexec_pids: Vec<u32>,
        },
        Command {
            root_pid: u32,
            exe_path: String,
            window_start: SystemTime,
            install_dir: Option<String>,
        },
    }

    #[derive(Debug, Clone)]
    pub struct AbortOutcome {
        pub status: String,
        pub trigger: String,
        pub installer_kind: String,
        pub stop_ms: u64,
        pub forced_ms: u64,
        pub cooperative_ms: u64,
        pub verify_ms: u64,
        pub return_code: Option<u32>,
        pub tree_dead: bool,
        pub survivors: Vec<Value>,
        pub remaining_pids: Vec<u32>,
        pub handles_released: bool,
        pub product_absent: Option<bool>,
        pub product_state: Option<i32>,
        pub mutex_free: Option<bool>,
        pub service_idle: Option<bool>,
        pub leftovers_empty: Option<bool>,
        pub stop_unconfirmed: bool,
        pub ui_calls: u64,
        pub note: String,
    }

    impl AbortOutcome {
        pub fn to_json(&self) -> Value {
            json!({
                "status": self.status,
                "trigger": self.trigger,
                "installer_kind": self.installer_kind,
                "stop_ms": self.stop_ms,
                "forced_ms": self.forced_ms,
                "cooperative_ms": self.cooperative_ms,
                "verify_ms": self.verify_ms,
                "return_code": self.return_code,
                "tree_dead": self.tree_dead,
                "survivors": self.survivors,
                "remaining_pids": self.remaining_pids,
                "handles_released": self.handles_released,
                "product_absent": self.product_absent,
                "product_state": self.product_state,
                "mutex_free": self.mutex_free,
                "service_idle": self.service_idle,
                "leftovers_empty": self.leftovers_empty,
                "stop_unconfirmed": self.stop_unconfirmed,
                "ui_calls": self.ui_calls,
                "note": self.note,
            })
        }
    }

    pub fn abort(target: AbortTarget, trigger: StopTrigger) -> AbortOutcome {
        let kind = match &target {
            AbortTarget::Msi { .. } => InstallerKind::Msi,
            AbortTarget::Command { .. } => InstallerKind::Command,
        };
        let _ = target;
        AbortOutcome {
            status: "unsupported-platform".to_string(),
            trigger: trigger.as_str().to_string(),
            installer_kind: kind.as_str().to_string(),
            stop_ms: 0,
            forced_ms: 0,
            cooperative_ms: 0,
            verify_ms: 0,
            return_code: None,
            tree_dead: false,
            survivors: Vec::new(),
            remaining_pids: Vec::new(),
            handles_released: false,
            product_absent: None,
            product_state: None,
            mutex_free: None,
            service_idle: None,
            leftovers_empty: None,
            stop_unconfirmed: false,
            ui_calls: 0,
            note: "abort() is windows-only; this stub never kills anything".to_string(),
        }
    }
}

#[cfg(not(windows))]
pub mod msi {
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    pub const ERROR_INSTALL_USEREXIT: u32 = 1602;
    pub const INSTALLSTATE_ABSENT: i32 = 2;

    #[derive(Debug, Clone)]
    pub struct CancelOutcome {
        pub return_code: u32,
        pub cancel_ms: u64,
        pub total_ms: u64,
        pub handler_calls: u64,
        pub cancelled: bool,
    }

    fn failed_outcome() -> CancelOutcome {
        CancelOutcome {
            return_code: 1603,
            cancel_ms: 0,
            total_ms: 0,
            handler_calls: 0,
            cancelled: false,
        }
    }

    pub fn install_with_cancel(msi_path: &str, cancel_after_ms: u64) -> CancelOutcome {
        let _ = (msi_path, cancel_after_ms);
        failed_outcome()
    }

    pub fn install_with_external_cancel(msi_path: &str, cancel: Arc<AtomicBool>) -> CancelOutcome {
        let _ = (msi_path, cancel);
        failed_outcome()
    }

    pub fn install_product(msi_path: &str) -> u32 {
        let _ = msi_path;
        1603
    }

    pub fn find_product_by_name(name_substring: &str) -> Option<(String, String)> {
        let _ = name_substring;
        None
    }

    pub fn product_version(code: &str) -> Option<String> {
        let _ = code;
        None
    }

    pub fn product_state(code: &str) -> i32 {
        let _ = code;
        -1
    }

    pub fn uninstall_product(code: &str) -> u32 {
        let _ = code;
        1603
    }

    pub fn product_presence_by_name(name_substring: &str) -> Value {
        json!({
            "present": false,
            "product_code": null,
            "product_name": null,
            "product_state": null,
            "name_substring": name_substring,
            "unsupported": "msi is windows-only",
        })
    }

    pub fn ensure_product_absent(
        product_code: Option<&str>,
        name_substring: &str,
        timeout_ms: u64,
    ) -> Value {
        let _ = (product_code, name_substring, timeout_ms);
        json!({
            "product_absent": false,
            "waited_ms": 0,
            "uninstall_return_code": null,
            "product_state": null,
            "unsupported": "msi is windows-only",
        })
    }

    pub fn pre_command_state(product_code: Option<&str>, target_dir: &str) -> Value {
        let _ = (product_code, target_dir);
        json!({
            "product_state": null,
            "msi_execute_mutex_free": true,
            "target_folder": {"exists": false, "entries": []},
            "unsupported": "msi is windows-only",
        })
    }

    pub fn target_folder_listing(path: &str) -> Value {
        let _ = path;
        json!({"exists": false, "entries": []})
    }
}

#[cfg(not(windows))]
pub mod win32 {
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::time::{Duration, SystemTime};

    pub type Handle = *mut std::ffi::c_void;

    pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: u32 = 9;
    pub const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002_000D;
    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_TIMEOUT: u32 = 0x0000_0102;

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn close_handle(_h: Handle) {}

    #[derive(Debug, Clone)]
    pub struct Proc {
        pub pid: u32,
        pub ppid: u32,
        pub exe: String,
        pub session: Option<u32>,
        pub user: Option<String>,
        pub sid: Option<String>,
        pub in_job: Option<bool>,
    }

    impl Proc {
        pub fn to_json(&self) -> Value {
            json!({
                "pid": self.pid,
                "ppid": self.ppid,
                "exe": self.exe,
                "session": self.session,
                "user": self.user,
                "sid": self.sid,
                "in_job": self.in_job,
            })
        }

        pub fn fn_looks_like_service_msiexec(&self, _services_pid: Option<u32>) -> bool {
            false
        }
    }

    pub fn user_label_for_sid(_sid: &str) -> &'static str {
        "unknown"
    }

    pub fn token_sid(_pid: u32) -> Option<String> {
        None
    }

    pub fn process_elevated(_pid: u32) -> Option<bool> {
        None
    }

    pub fn is_elevated() -> bool {
        false
    }

    pub fn session_id(_pid: u32) -> Option<u32> {
        None
    }

    pub fn exe_path(_pid: u32) -> Option<String> {
        None
    }

    pub fn snapshot() -> Vec<(u32, u32, String)> {
        Vec::new()
    }

    pub fn alive(_pid: u32) -> bool {
        false
    }

    pub fn wait_for_exit(_pid: u32, _timeout: Duration) -> bool {
        false
    }

    pub fn identify(pid: u32, ppid: u32, exe_name: &str, _job: Option<Handle>) -> Proc {
        Proc {
            pid,
            ppid,
            exe: exe_name.to_string(),
            session: None,
            user: None,
            sid: None,
            in_job: None,
        }
    }

    pub fn descendants(_root: u32) -> Vec<u32> {
        Vec::new()
    }

    pub fn depths(_root: u32, _pids: &[u32]) -> HashMap<u32, usize> {
        HashMap::new()
    }

    pub fn msiexec_processes() -> Vec<Proc> {
        Vec::new()
    }

    pub fn services_pid() -> Option<u32> {
        None
    }

    pub fn terminate_pid(_pid: u32) -> bool {
        false
    }

    pub fn terminate_job(_job: Handle) -> (bool, u32) {
        (false, 0)
    }

    pub fn cooperative_phase(_root_pid: u32, _coop_ms: u64) -> (u64, bool) {
        (0, false)
    }

    pub fn msi_execute_mutex_free() -> bool {
        true
    }

    pub fn sc_query_msiserver() -> Value {
        json!({"running": false, "unsupported": "windows-only"})
    }

    #[derive(Debug)]
    pub struct Launched {
        pub pid: u32,
        pub handle: Handle,
        pub job: Handle,
    }

    impl Launched {
        pub fn close(&mut self) {}
    }

    pub fn launch_in_job(_cmdline: &str) -> Result<Launched, String> {
        Err("launch_in_job is windows-only".to_string())
    }

    #[derive(Debug, Clone, Copy)]
    pub struct FileTime {
        pub dw_low_date_time: u32,
        pub dw_high_date_time: u32,
    }

    pub fn process_creation_time(_pid: u32) -> Option<SystemTime> {
        None
    }

    pub fn processes_by_exe_and_window(
        _exe_path: &str,
        _window_start: SystemTime,
        _window_end: SystemTime,
    ) -> Vec<Proc> {
        Vec::new()
    }
}
