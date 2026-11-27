//! The executor: the decision layer between the queue and the supervisor.
//!
//! Execution is DISABLED by default: the library executor refuses unless
//! `HandConfig { exec_enabled: true }`; default false; ONLY the self-test
//! binary passes true. Production execution stays off until the council
//! approves Part 4.
//!
//! `prepare_execution` runs every gate in order and either returns an
//! `ExecRequest` for the supervisor (which alone launches processes, in
//! the job) or an error naming the reason: `exec_disabled`,
//! `deadman_active`, `expired`, `needs_approval`, `disk-space`,
//! `blocked_eicar`, `guardian_unavailable`, `already_done`,
//! `sha256-required`, `sha256-mismatch`, `sha256-unreadable`.
//!
//! Gate order (the 8.12 negative tests prove it): exec flag, deadman,
//! TTL, approval/organize (line 213), disk space, guardian (line 236),
//! MSI class (line 240), then the file-hash gate (§25.2, §39.3 —
//! inserted AFTER the class gate, so an unapproved command fails at
//! the class gate before any hash is computed).
//!
//! Disk-space rule (checked before execution and re-checked at start):
//! free bytes must be >= size + max(512 MB, 10% of size), else the command
//! fails with reason `disk-space` and nothing is written.
//! Download cap: 2 GB per file — above it needs approval.
//! Idempotency: when the result already exists (e.g. the app is installed
//! at the same version), the command is `done` without reinstalling.
//!
//! Organize in v1 is PROPOSE-ONLY: without approval no file moves, ever.
//! Download throttling while game mode is on and the partial-cleanup rule
//! live in the transfer loop / supervisor stop path (see README).

use crate::control::HandControl;
use crate::guardian::Guardian;
use crate::queue::{is_expired, Command};
use crate::{read_json_file, utc_now_secs, write_json_file};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Per-file download cap: 2 GB.
pub const MAX_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Minimum free-space margin: 512 MB.
pub const DISK_MARGIN_BYTES: u64 = 512 * 1024 * 1024;

/// Execution configuration. `exec_enabled` is false by default.
#[derive(Debug, Clone)]
pub struct HandConfig {
    pub exec_enabled: bool,
    pub data_dir: PathBuf,
    pub heartbeat_secs: u64,
    pub guardian_base: Option<PathBuf>,
}

impl Default for HandConfig {
    fn default() -> Self {
        HandConfig {
            exec_enabled: false,
            data_dir: PathBuf::from("."),
            heartbeat_secs: 30,
            guardian_base: None,
        }
    }
}

/// A launch request from the worker to the supervisor. The supervisor is
/// the only process launcher; it launches the request in the job and
/// writes `hand.exec-result-<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub id: String,
    pub kind: String,
    pub program: String,
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grandchild_out: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installer_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_substring: Option<String>,
    /// Expected SHA-256 (lowercase hex) of the MSI file (§25.2).
    /// `Option` structurally so old request files still deserialize;
    /// semantically REQUIRED for install commands (§25.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    /// Custom install root for the slice (§28.2 ruling (a)): when set,
    /// the supervisor passes `TARGETDIR=<this>` to the installer and the
    /// msiexec argument line carries it too. Set only when the command
    /// opts in with `args.targetdir == true`; `None` = MSI default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targetdir: Option<String>,
}

pub fn exec_request_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join(format!("hand.exec-request-{}.json", id))
}

pub fn exec_started_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join(format!("hand.exec-started-{}.json", id))
}

pub fn exec_result_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join(format!("hand.exec-result-{}.json", id))
}

pub fn write_exec_request(data_dir: &Path, req: &ExecRequest) -> Result<PathBuf, String> {
    let path = exec_request_path(data_dir, &req.id);
    let value = serde_json::to_value(req).map_err(|e| e.to_string())?;
    write_json_file(&path, &value)?;
    Ok(path)
}

pub fn read_exec_result(data_dir: &Path, id: &str) -> Option<Value> {
    read_json_file(&exec_result_path(data_dir, id))
}

/// Poll for an exec result until `timeout`. Returns `None` on timeout.
pub fn wait_exec_result(data_dir: &Path, id: &str, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = read_exec_result(data_dir, id) {
            return Some(v);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Free bytes required to download/install `size` bytes:
/// size + max(512 MB, 10% of size).
pub fn required_bytes(size_bytes: u64) -> u64 {
    size_bytes + DISK_MARGIN_BYTES.max(size_bytes / 10)
}

/// True when `free_bytes` covers `size_bytes` plus the margin.
pub fn disk_space_ok(free_bytes: u64, size_bytes: u64) -> bool {
    free_bytes >= required_bytes(size_bytes)
}

/// The download limits: 2 GB cap (needs approval above it) and the
/// free-space rule. `free_bytes == None` means the free space is unknown
/// on this platform; the caller must then supply a value.
pub fn check_download_limits(
    size_bytes: u64,
    free_bytes: Option<u64>,
) -> Result<(), String> {
    if let Some(free) = free_bytes {
        if !disk_space_ok(free, size_bytes) {
            return Err("disk-space".to_string());
        }
    }
    if size_bytes > MAX_DOWNLOAD_BYTES {
        return Err("needs_approval:over-2gb".to_string());
    }
    Ok(())
}

/// Free bytes available on the volume holding `path`.
/// On Windows this is the real value (GetDiskFreeSpaceExW); on other
/// platforms it is `None` (the pure `disk_space_ok` check is unit-tested).
#[cfg(windows)]
pub fn free_space_bytes(path: &Path) -> Option<u64> {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::PCWSTR;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut free: u64 = 0;
    let ok = unsafe { GetDiskFreeSpaceExW(
            PCWSTR(wide.as_ptr()),
            Some(&mut free as *mut u64),
            None,
            None,
        ).is_ok()
    };
    if ok {
        Some(free)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn free_space_bytes(_path: &Path) -> Option<u64> {
    None
}
// SHA-256 (lowercase hex) of the lowercased name_substring of the single allowed installer class.
// The class itself is named in the crate README; the code keeps only its fingerprint, so no product name is a constant in this file.
const ALLOWED_MSI_CLASS_NAME_SHA256: &str = "3f34571192c231cbc2c9dbe88985a3acef53540929b05a247c4352fb9128832f";

fn msi_class_allowed(cmd: &Command) -> bool {
    let Some(name) = cmd.args.get("name_substring").and_then(|v| v.as_str()) else {
        return false;
    };
    crate::sha256_hex(name.trim().to_lowercase().as_bytes()) == ALLOWED_MSI_CLASS_NAME_SHA256
}


/// Run every gate for `cmd` and build the supervisor request.
/// Errors name the reason (see the module docs); the caller maps the
/// reason to the queue state.
pub fn prepare_execution(
    cmd: &Command,
    config: &HandConfig,
    guardian: &Guardian,
) -> Result<ExecRequest, String> {
    if !config.exec_enabled {
        return Err("exec_disabled".to_string());
    }
    let ctl = HandControl::new(&config.data_dir, config.heartbeat_secs);
    if ctl.is_deadman() {
        return Err("deadman_active".to_string());
    }
    if is_expired(cmd, utc_now_secs()) {
        return Err("expired".to_string());
    }
    // Organize is propose-only: without approval no file moves, ever.
    if (cmd.needs_approval || cmd.kind == "organize") && !cmd.approved {
        return Err("needs_approval".to_string());
    }
    // Disk-space check before any download/install (re-checked at start
    // by the supervisor, which sees the same rule).
    if let Some(size) = cmd.args.get("size_bytes").and_then(|v| v.as_u64()) {
        let free = free_space_bytes(&config.data_dir);
        if let Some(free) = free {
            if !disk_space_ok(free, size) {
                return Err("disk-space".to_string());
            }
        }
        if size > MAX_DOWNLOAD_BYTES {
            return Err("needs_approval:over-2gb".to_string());
        }
    }
    // Guardian gate on the file that would be executed / installed.
    let target = cmd
        .args
        .get("target")
        .and_then(|v| v.as_str())
        .or_else(|| cmd.args.get("msi").and_then(|v| v.as_str()));
    if let Some(target) = target {
        guardian.gate(Path::new(target))?;
    }
    // Installers are narrowed to the single allowed class (see the crate README for the class and its fingerprint).
    // Any other install/msi command needs approval first; an approved command still passes.
    if cmd.kind == "install" && cmd.args.get("msi").is_some() && !cmd.approved && !msi_class_allowed(cmd) {
        return Err("needs_approval".to_string());
    }
    // File-hash gate (§25.2, §39.3): AFTER the class gate, so 8.12e
    // (unapproved) fails at line 240 before any hash is computed.
    // Applies to installs only, never to uninstalls (no hash to check
    // for a removal). Absent field => sha256-required; present but
    // empty/malformed (not 64 hex chars) => sha256-mismatch (§45.9.5);
    // unreadable file => sha256-unreadable. No request file is written
    // on any of these failures.
    if cmd.kind == "install" && !cmd.args.get("uninstall").and_then(|v| v.as_bool()).unwrap_or(false) {
        if let Some(msi) = cmd.args.get("msi").and_then(|v| v.as_str()) {
            match cmd.args.get("expected_sha256").and_then(|v| v.as_str()) {
                None => return Err("sha256-required".to_string()),
                Some(expected) => {
                    let expected = expected.trim().to_lowercase();
                    let well_formed = expected.len() == 64
                        && expected.chars().all(|c| c.is_ascii_hexdigit());
                    if !well_formed {
                        return Err("sha256-mismatch".to_string());
                    }
                    match crate::file_sha256(Path::new(msi)) {
                        Ok(computed) => {
                            if computed != expected {
                                return Err("sha256-mismatch".to_string());
                            }
                        }
                        Err(_) => return Err("sha256-unreadable".to_string()),
                    }
                }
            }
        }
    }
    // Idempotency: the result already exists — done, without executing.
    if let Some(marker) = cmd.args.get("idempotency_path").and_then(|v| v.as_str()) {
        if Path::new(marker).exists() {
            return Err("already_done".to_string());
        }
    }
    let req = match cmd.kind.as_str() {
        "install" => {
            let msi = cmd
                .args
                .get("msi")
                .and_then(|v| v.as_str())
                .ok_or("install command has no msi path")?;
            let uninstall = cmd
                .args
                .get("uninstall")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let verb = if uninstall { "/x" } else { "/i" };
            // Slice opt-in (§28.2 (a)): TARGETDIR is appended ONLY when
            // the command sets args.targetdir=true. Never by default:
            // 8.1's VLC command carries install_dir too, and silently
            // redirecting it would change a proven proof.
            let targetdir = if cmd.args.get("targetdir").and_then(|v| v.as_bool()).unwrap_or(false) {
                cmd.args.get("install_dir").and_then(|v| v.as_str()).map(|s| s.to_string())
            } else {
                None
            };
            let mut install_args = vec![
                verb.to_string(),
                msi.to_string(),
                "/qn".to_string(),
                "/norestart".to_string(),
            ];
            if let Some(td) = &targetdir {
                install_args.push(format!("TARGETDIR={}", td));
            }
            ExecRequest {
                id: cmd.id.clone(),
                kind: "install".to_string(),
                program: "msiexec.exe".to_string(),
                args: install_args,
                working_dir: None,
                cleanup_path: None,
                install_dir: cmd
                    .args
                    .get("install_dir")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                grandchild_out: None,
                installer_kind: if uninstall { None } else { Some("msi".to_string()) },
                product_code: cmd.args.get("product_code").and_then(|v| v.as_str()).map(|s| s.to_string()),
                name_substring: cmd.args.get("name_substring").and_then(|v| v.as_str()).map(|s| s.to_string()),
                expected_sha256: cmd.args.get("expected_sha256").and_then(|v| v.as_str()).map(|s| s.to_string()),
                targetdir,
            }
        }
        "transfer" => {
            // The supervisor runs its own --slow-copy helper for
            // transfers, so progress can be polled and the copy killed
            // mid-transfer (proof 8.2). `program` is unused for this kind.
            ExecRequest {
                id: cmd.id.clone(),
                kind: "transfer".to_string(),
                program: String::new(),
                args: vec![
                    cmd.args
                        .get("source")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    cmd.args
                        .get("destination")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                ],
                working_dir: None,
                cleanup_path: cmd
                    .args
                    .get("destination")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                install_dir: None,
                grandchild_out: None,
                installer_kind: None,
                product_code: None,
                name_substring: None,
                expected_sha256: None,
                targetdir: None,
            }
        }
        "probe-grandchild" => ExecRequest {
            id: cmd.id.clone(),
            kind: "probe-grandchild".to_string(),
            program: String::new(),
            args: vec![],
            working_dir: None,
            cleanup_path: None,
            install_dir: None,
            grandchild_out: cmd
                .args
                .get("grandchild_out")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            installer_kind: None,
            product_code: None,
            name_substring: None,
            expected_sha256: None,
            targetdir: None,
        },
        other => return Err(format!("exec_not_live:{}", other)),
    };
    Ok(req)
}

/// Map a supervisor exec result to the queue state for the command.
pub fn result_state(result: &Value) -> &'static str {
    match result.get("status").and_then(|v| v.as_str()) {
        Some("done") => "done",
        Some("failed") => "failed",
        Some("stopped") => "stopped",
        Some("expired") => "expired",
        _ => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::new_command;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Unique per call: parallel tests share one process, so a fixed
    // temp directory name collides and one test deletes another's
    // directory mid-test (run 34: install_outside_allowed_msi_class_
    // needs_approval failed with file_not_found at the guardian check).
    // Same pattern as control.rs / queue.rs.
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("bimo-hand-exec-test-{}-{}", std::process::id(), n));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn disk_space_rule_adds_the_margin() {
        // 1 GB needs 1 GB + 512 MB (512 MB > 10% of 1 GB).
        let one_gb = 1024 * 1024 * 1024;
        assert_eq!(required_bytes(one_gb), one_gb + DISK_MARGIN_BYTES);
        assert!(!disk_space_ok(one_gb + DISK_MARGIN_BYTES - 1, one_gb));
        assert!(disk_space_ok(one_gb + DISK_MARGIN_BYTES, one_gb));
        // 10 GB needs 10 GB + 1 GB (10% > 512 MB).
        let ten_gb = 10 * one_gb;
        assert_eq!(required_bytes(ten_gb), ten_gb + ten_gb / 10);
    }

    #[test]
    fn download_limits_cap_at_2gb_and_fail_on_disk_space() {
        assert!(check_download_limits(1024, Some(10 * 1024 * 1024 * 1024)).is_ok());
        assert_eq!(
            check_download_limits(MAX_DOWNLOAD_BYTES + 1, Some(u64::MAX)),
            Err("needs_approval:over-2gb".to_string())
        );
        assert_eq!(
            check_download_limits(1024 * 1024 * 1024, Some(1024 * 1024 * 1024)),
            Err("disk-space".to_string())
        );
    }

    #[test]
    fn execution_is_disabled_by_default() {
        let config = HandConfig::default();
        assert!(!config.exec_enabled);
        let cmd = new_command("x", "install", json!({}), 3600, json!({}));
        let err = prepare_execution(&cmd, &config, &Guardian::default()).unwrap_err();
        assert_eq!(err, "exec_disabled");
    }

    #[test]
    fn organize_without_approval_needs_approval() {
        let dir = test_dir();
        let mut config = HandConfig::default();
        config.exec_enabled = true;
        config.data_dir = dir.clone();
        let mut cmd = new_command("o1", "organize", json!({}), 3600, json!({"moves": []}));
        cmd.needs_approval = true;
        let err = prepare_execution(&cmd, &config, &Guardian::default()).unwrap_err();
        assert_eq!(err, "needs_approval");
        let _ = fs::remove_dir_all(&dir);
    }
    #[test]
fn install_outside_allowed_msi_class_needs_approval() {
    let dir = test_dir();
    let msi_path = dir.join("example.msi");
    let _ = fs::write(&msi_path, b"dummy");
    let mut config = HandConfig::default();
    config.exec_enabled = true;
    config.data_dir = dir.clone();
    let cmd = new_command("m1", "install", json!({"msi": msi_path.to_string_lossy().to_string(), "name_substring": "Example Installer"}), 3600, json!({}));
    let err = prepare_execution(&cmd, &config, &Guardian::default()).unwrap_err();
    assert_eq!(err, "needs_approval");
    let _ = fs::remove_dir_all(&dir);
}
    
}
