//! The supervisor (council condition 1, RED LINE).
//!
//! The supervisor is the ONLY process launcher. It creates a Windows Job
//! Object, launches the hand worker inside it (via
//! `PROC_THREAD_ATTRIBUTE_JOB_LIST` — assigned before the first thread
//! runs, the Raymond Chen pattern; never create-suspended-then-assign),
//! and launches command children inside the same job directly. The worker
//! never launches elevated processes itself. This sidesteps the unresolved
//! question of whether a UAC-elevated child inherits its medium-integrity
//! parent's job: we never rely on it.
//!
//! Job limits: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` +
//! `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 32`. NO BREAKAWAY flags ever.
//!
//! Stop, in two levels: (1) cooperative, immediate — `CTRL_BREAK_EVENT`
//! to the console process group, target <= 1-2 s; (2) forced — if still
//! alive after the cooperative window, or the total stop exceeds 5 s:
//! `TerminateJobObject` + verify death. MAX stop 5 s. Every wait has an
//! explicit timeout; the supervisor is the final backstop (lesson from the
//! eye, cycle 33: no circular wait without a timeout anywhere in stop()).
//!
//! Death verification: Toolhelp snapshot — no process of the installer
//! tree remains; `IsProcessInJob` false for all of them; the installer PID
//! is gone; file handles are released (proven by successfully renaming the
//! install dir after the kill).
//!
//! This module is Windows-only in its implementation; on other platforms
//! every function reports that the supervisor requires Windows, so the
//! crate still builds (and its non-Windows unit tests still run) on Linux.

use crate::try_rename_dir;
use std::path::Path;
use std::time::{Duration, Instant};

/// Active-process limit of the job.
pub const MAX_JOB_PROCESSES: u32 = 32;
/// Maximum total stop time.
pub const MAX_STOP_MS: u64 = 5000;
/// Cooperative stop window before forcing the kill.
pub const COOP_WINDOW_MS: u64 = 2000;

/// The outcome of a stop, with the measured stop time.
#[derive(Debug, Clone)]
pub struct StopOutcome {
    /// "cooperative" | "forced" | "already-dead" | "unsupported".
    pub method: String,
    /// Measured stop time in milliseconds (must be <= 5000).
    pub stop_ms: u64,
    /// True when no process of the tree remains.
    pub tree_dead: bool,
    /// PIDs that still survived, if any.
    pub remaining_pids: Vec<u32>,
    /// True when the install dir could be renamed after the kill
    /// (file handles released).
    pub handles_released: bool,
}

/// A launched process in the job.
#[derive(Debug)]
pub struct LaunchedProcess {
    pub pid: u32,
    #[cfg(windows)]
    pub handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for LaunchedProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

/// The supervisor's job object.
pub struct Job {
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
    #[cfg(not(windows))]
    _private: (),
}

#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        // Closing the job handle kills the job (KILL_ON_JOB_CLOSE).
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    // Win32 ABI constants (windows 0.62 does not export these).
    const STILL_ACTIVE: u32 = 259;
    const WAIT_OBJECT_0: WAIT_EVENT = WAIT_EVENT(0);
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_EVENT};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
        InitializeProcThreadAttributeList, OpenProcess, UpdateProcThreadAttribute,
        WaitForSingleObject, CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTUPINFOEXW, STARTUPINFOW,
    };
        use windows::Win32::System::Threading::{LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken};
    use windows::core::{BOOL, PCWSTR, PWSTR};

    pub fn create_job() -> Result<Job, String> {
        unsafe {
            let handle = CreateJobObjectW(None, PCWSTR::null())
                .map_err(|e| format!("CreateJobObjectW failed: {}", e))?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = MAX_JOB_PROCESSES;
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| format!("SetInformationJobObject failed: {}", e))?;
            Ok(Job { handle })
        }
    }

    fn quote_arg(arg: &str) -> String {
        if arg.contains(' ') || arg.contains('"') || arg.is_empty() {
            format!("\"{}\"", arg.replace('"', "\"\""))
        } else {
            arg.to_string()
        }
    }

    pub fn launch_in_job(
        job: &Job,
        program: &str,
        args: &[String],
        working_dir: Option<&str>,
    ) -> Result<LaunchedProcess, String> {
        unsafe {
            // Build the attribute list carrying the job handle, so the
            // process is assigned to the job BEFORE its first thread runs.
            let mut size: usize = 0;
            let _ = InitializeProcThreadAttributeList(None, 1, Some(0), &mut size);
            let mut attr_storage = vec![0u8; size];
            let attr_list = attr_storage.as_mut_ptr() as *mut core::ffi::c_void;
        InitializeProcThreadAttributeList(Some(LPPROC_THREAD_ATTRIBUTE_LIST(attr_list)), 1, Some(0), &mut size)
                .map_err(|e| format!("InitializeProcThreadAttributeList failed: {}", e))?;
            let job_handle = job.handle;
            UpdateProcThreadAttribute(
                LPPROC_THREAD_ATTRIBUTE_LIST(attr_list),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some(&job_handle as *const _ as *const core::ffi::c_void),
                std::mem::size_of::<HANDLE>(),
                None,
                None,
            )
            .map_err(|e| format!("UpdateProcThreadAttribute failed: {}", e))?;
            let si_ex = STARTUPINFOEXW {
                StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                    ..Default::default()
                },
                lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST(attr_list),
            };
            let mut command_line: Vec<u16> = {
                let mut parts = vec![quote_arg(program)];
                parts.extend(args.iter().map(|a| quote_arg(a)));
                parts
                    .join(" ")
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect()
            };
            let dir_wide: Option<Vec<u16>> = working_dir.map(|d| {
                d.encode_utf16().chain(std::iter::once(0)).collect()
            });
            let mut pi = PROCESS_INFORMATION::default();
            let result = CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
                None,
                match &dir_wide {
                    Some(d) => PCWSTR(d.as_ptr()),
                    None => PCWSTR::null(),
                },
                &si_ex.StartupInfo as *const STARTUPINFOW,
                &mut pi,
            );
            let _ = DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST(attr_list));
            let _ = CloseHandle(pi.hThread);
            result.map_err(|e| format!("CreateProcessW failed for {}: {}", program, e))?;
            Ok(LaunchedProcess {
                pid: pi.dwProcessId,
                handle: pi.hProcess,
            })
        }
    }

    pub fn is_process_in_job(pid: u32, job: &Job) -> bool {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };
            let mut in_job = BOOL(0);
        let ok = IsProcessInJob(handle, Some(job.handle), &mut in_job).is_ok();
            let _ = CloseHandle(handle);
            ok && in_job.as_bool()
        }
    }

    pub fn job_process_count(job: &Job) -> usize {
        snapshot_pids()
            .iter()
            .filter(|pid| is_process_in_job(**pid, job))
            .count()
    }

    pub fn terminate_job(job: &Job) -> Result<(), String> {
        unsafe {
            TerminateJobObject(job.handle, 1)
                .map_err(|e| format!("TerminateJobObject failed: {}", e))
        }
    }

    pub fn process_alive(pid: u32) -> bool {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(handle, &mut code).is_ok();
            let _ = CloseHandle(handle);
            ok && code == STILL_ACTIVE
        }
    }

    pub fn process_exit_code(pid: u32) -> Option<u32> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut code: u32 = 0;
            let ok = GetExitCodeProcess(handle, &mut code).is_ok();
            let _ = CloseHandle(handle);
            if ok && code != STILL_ACTIVE {
                Some(code)
            } else {
                None
            }
        }
    }

    pub fn wait_process(pid: u32, timeout_ms: u32) -> bool {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return true,
            };
            let waited = WaitForSingleObject(handle, timeout_ms) == WAIT_OBJECT_0;
            let _ = CloseHandle(handle);
            waited
        }
    }

    fn snapshot_pids() -> Vec<u32> {
        snapshot_processes()
            .into_iter()
            .map(|(pid, _)| pid)
            .collect()
    }

    fn snapshot_processes() -> Vec<(u32, u32)> {
        unsafe {
            let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(h) => h,
                Err(_) => return Vec::new(),
            };
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut out = Vec::new();
            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    out.push((entry.th32ProcessID, entry.th32ParentProcessID));
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
            out
        }
    }

    pub fn descendants(root_pid: u32) -> Vec<u32> {
        let procs = snapshot_processes();
        let mut children: std::collections::HashMap<u32, Vec<u32>> =
            std::collections::HashMap::new();
        for (pid, ppid) in procs {
            children.entry(ppid).or_default().push(pid);
        }
        let mut out = Vec::new();
        let mut stack = vec![root_pid];
        while let Some(pid) = stack.pop() {
            if let Some(kids) = children.get(&pid) {
                for kid in kids {
                    out.push(*kid);
                    stack.push(*kid);
                }
            }
        }
        out
    }

    pub fn verify_tree_dead(root_pid: u32, job: &Job) -> (bool, Vec<u32>) {
        let mut tree = vec![root_pid];
        tree.extend(descendants(root_pid));
        let remaining: Vec<u32> = tree
            .into_iter()
            .filter(|pid| process_alive(*pid) || is_process_in_job(*pid, job))
            .collect();
        (remaining.is_empty(), remaining)
    }

    fn token_elevated(handle: HANDLE) -> bool {
        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(handle, TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
            .is_ok();
            let _ = CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }

    pub fn is_elevated() -> bool {
        unsafe { token_elevated(GetCurrentProcess()) }
    }

    pub fn is_process_elevated(pid: u32) -> bool {
        unsafe {
            let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };
            let elevated = token_elevated(handle);
            let _ = CloseHandle(handle);
            elevated
        }
    }

    pub fn system_memory_mb() -> Option<(u64, u64)> {
        unsafe {
            let mut status = MEMORYSTATUSEX::default();
            status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut status).is_err() {
                return None;
            }
            Some((
                status.ullTotalPhys / (1024 * 1024),
                status.ullAvailPhys / (1024 * 1024),
            ))
        }
    }

    pub fn stop_process_group(
        pid: u32,
        job: &Job,
        install_dir: Option<&Path>,
    ) -> StopOutcome {
        let start = Instant::now();
        if !process_alive(pid) {
            let (tree_dead, remaining) = verify_tree_dead(pid, job);
            return StopOutcome {
                method: "already-dead".to_string(),
                stop_ms: start.elapsed().as_millis() as u64,
                tree_dead,
                remaining_pids: remaining,
                handles_released: install_dir.map(try_rename_dir).unwrap_or(true),
            };
        }
        // (1) Cooperative: CTRL_BREAK_EVENT to the console process group.
        let _ = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid) };
        let mut method = "cooperative";
        while start.elapsed() < Duration::from_millis(COOP_WINDOW_MS) {
            if !process_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // (2) Forced: TerminateJobObject, then verify death. Total <= 5 s.
        if process_alive(pid) {
            method = "forced";
            let _ = terminate_job(job);
        }
        while start.elapsed() < Duration::from_millis(MAX_STOP_MS) {
            let (dead, _) = verify_tree_dead(pid, job);
            if dead && !process_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (tree_dead, remaining) = verify_tree_dead(pid, job);
        StopOutcome {
            method: method.to_string(),
            stop_ms: start.elapsed().as_millis() as u64,
            tree_dead,
            remaining_pids: remaining,
            handles_released: install_dir.map(try_rename_dir).unwrap_or(true),
        }
    }
}

// ---------------------------------------------------------------------------
// Public API (delegates to the Windows implementation)
// ---------------------------------------------------------------------------

pub fn create_job() -> Result<Job, String> {
    #[cfg(windows)]
    {
        imp::create_job()
    }
    #[cfg(not(windows))]
    {
        Err("supervisor requires Windows".to_string())
    }
}

pub fn launch_in_job(
    job: &Job,
    program: &str,
    args: &[String],
    working_dir: Option<&str>,
) -> Result<LaunchedProcess, String> {
    #[cfg(windows)]
    {
        imp::launch_in_job(job, program, args, working_dir)
    }
    #[cfg(not(windows))]
    {
        let _ = (job, program, args, working_dir);
        Err("supervisor requires Windows".to_string())
    }
}

pub fn is_process_in_job(pid: u32, job: &Job) -> bool {
    #[cfg(windows)]
    {
        imp::is_process_in_job(pid, job)
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, job);
        false
    }
}

pub fn job_process_count(job: &Job) -> usize {
    #[cfg(windows)]
    {
        imp::job_process_count(job)
    }
    #[cfg(not(windows))]
    {
        let _ = job;
        0
    }
}

pub fn terminate_job(job: &Job) -> Result<(), String> {
    #[cfg(windows)]
    {
        imp::terminate_job(job)
    }
    #[cfg(not(windows))]
    {
        let _ = job;
        Err("supervisor requires Windows".to_string())
    }
}

pub fn process_alive(pid: u32) -> bool {
    #[cfg(windows)]
    {
        imp::process_alive(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        false
    }
}

pub fn process_exit_code(pid: u32) -> Option<u32> {
    #[cfg(windows)]
    {
        imp::process_exit_code(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        None
    }
}

pub fn wait_process(pid: u32, timeout_ms: u32) -> bool {
    #[cfg(windows)]
    {
        imp::wait_process(pid, timeout_ms)
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, timeout_ms);
        false
    }
}

pub fn descendants(root_pid: u32) -> Vec<u32> {
    #[cfg(windows)]
    {
        imp::descendants(root_pid)
    }
    #[cfg(not(windows))]
    {
        let _ = root_pid;
        Vec::new()
    }
}

pub fn verify_tree_dead(root_pid: u32, job: &Job) -> (bool, Vec<u32>) {
    #[cfg(windows)]
    {
        imp::verify_tree_dead(root_pid, job)
    }
    #[cfg(not(windows))]
    {
        let _ = job;
        (false, vec![root_pid])
    }
}

pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        imp::is_elevated()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn is_process_elevated(pid: u32) -> bool {
    #[cfg(windows)]
    {
        imp::is_process_elevated(pid)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        false
    }
}

/// (total RAM MB, available RAM MB), Windows only.
pub fn system_memory_mb() -> Option<(u64, u64)> {
    #[cfg(windows)]
    {
        imp::system_memory_mb()
    }
    #[cfg(not(windows))]
    {
        None
    }
}

pub fn stop_process_group(pid: u32, job: &Job, install_dir: Option<&Path>) -> StopOutcome {
    #[cfg(windows)]
    {
        // v2 (cycle 41): the only kill path is kill::abort. This wrapper is
        // a compatibility shim for existing callers; it does not kill
        // anything itself. The job handle is kept for launch-time limits
        // only; stopping goes through abort (PPID tree + alternative
        // naming), never through a second TerminateJobObject path here.
        let _ = job;
        let exe_path = crate::win32::exe_path(pid).unwrap_or_default();
        let window_start = crate::win32::process_creation_time(pid).unwrap_or(std::time::UNIX_EPOCH);
        let outcome = crate::kill::abort(
            crate::kill::AbortTarget::Command {
                root_pid: pid,
                exe_path,
                window_start,
                install_dir: install_dir.map(|p| p.to_string_lossy().to_string()),
            },
            crate::kill::StopTrigger::HandStop,
        );
        StopOutcome {
            method: outcome.status,
            stop_ms: outcome.stop_ms,
            tree_dead: outcome.tree_dead,
            remaining_pids: outcome.remaining_pids,
            handles_released: outcome.handles_released,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, job, install_dir);
        StopOutcome {
            method: "unsupported".to_string(),
            stop_ms: 0,
            tree_dead: false,
            remaining_pids: vec![pid],
            handles_released: false,
        }
    }
}

/// v2 (cycle 41, condition 5): MSI topology. Run `MsiInstallProduct` in a
/// dedicated thread inside the supervisor and return the shared cancel
/// flag plus the outcome slot. The supervisor keeps monitoring the
/// heartbeat and hand.stop from a separate (monitor) thread while the
/// install thread is blocked inside MsiInstallProduct, and stops it by
/// calling `kill::abort` with the cancel flag -- never by killing
/// msiexec.exe. The install thread fills `outcome` when it returns;
/// `kill::abort` waits for it (up to the 5000 ms hard cap) and records
/// `forced_ms` as the rollback wait.
/// Non-Windows stub: MSI installation only exists on Windows, so on other
/// targets the install "finishes" immediately with a failure return code
/// (1603 = ERROR_INSTALL_FAILURE). The supervisor binary never runs a real
/// MSI install here; the stub exists only so `cargo test` compiles the
/// crate (including both binaries) on Linux (spec section 1: the
/// non-Windows logic's unit tests also run on Linux).
#[cfg(not(windows))]
pub fn run_msi_install_in_thread(
    msi_path: String,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::Mutex<Option<crate::msi::CancelOutcome>>>,
) {
    run_msi_install_in_thread_cmdline(msi_path, "REBOOT=ReallySuppress".to_string())
}

/// Same as `run_msi_install_in_thread` but with an explicit installer
/// command line (public properties, e.g. TARGETDIR for the slice,
/// §28.2 (a)). The cmdline is ignored by the non-Windows stub.
#[cfg(not(windows))]
pub fn run_msi_install_in_thread_cmdline(
    msi_path: String,
    _cmdline: String,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::Mutex<Option<crate::msi::CancelOutcome>>>,
) {
    let _ = msi_path;
    (
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        std::sync::Arc::new(std::sync::Mutex::new(Some(crate::msi::CancelOutcome {
            return_code: 1603,
            cancel_ms: 0,
            total_ms: 0,
            handler_calls: 0,
            handler_first_ms: 0,
            internal_ui_prev: 0,
            external_ui_prev_non_null: false,
            cancelled: false,
        }))),
    )
}

#[cfg(windows)]
pub fn run_msi_install_in_thread(
    msi_path: String,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::Mutex<Option<crate::msi::CancelOutcome>>>,
) {
    run_msi_install_in_thread_cmdline(msi_path, "REBOOT=ReallySuppress".to_string())
}

/// Same as `run_msi_install_in_thread` but with an explicit installer
/// command line (public properties, e.g. TARGETDIR for the slice,
/// §28.2 (a)).
#[cfg(windows)]
pub fn run_msi_install_in_thread_cmdline(
    msi_path: String,
    cmdline: String,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    std::sync::Arc<std::sync::Mutex<Option<crate::msi::CancelOutcome>>>,
) {
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let outcome = std::sync::Arc::new(std::sync::Mutex::new(None));
    let cancel2 = std::sync::Arc::clone(&cancel);
    let outcome2 = std::sync::Arc::clone(&outcome);
    std::thread::spawn(move || {
        let result = crate::msi::install_with_external_cancel_cmdline(&msi_path, &cmdline, cancel2);
        if let Ok(mut slot) = outcome2.lock() {
            *slot = Some(result);
        }
    });
    (cancel, outcome)
}
