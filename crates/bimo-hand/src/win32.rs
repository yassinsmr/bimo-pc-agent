//! Raw Win32 helpers for the kill spike (Windows only).
//!
//! Deliberately no `windows` crate: every API used here is declared
//! with its classic C signature, so the build does not depend on
//! windows-rs feature names or on Result-vs-BOOL changes between
//! crate versions. Only kernel32 / advapi32 functions are used.
//!
//! What this module provides:
//! * a Job Object with KILL_ON_JOB_CLOSE + 32 active processes, no
//!   breakaway, and launching a child inside it before its first
//!   thread runs (PROC_THREAD_ATTRIBUTE_JOB_LIST, Raymond Chen
//!   pattern, as in crates/bimo-hand/src/supervisor.rs);
//! * Toolhelp snapshots (PID / PPID / exe name) and, for every
//!   process, its full exe path, session id, token user (SID) and
//!   whether it is in a given job (IsProcessInJob);
//! * TerminateProcess by PID, GenerateConsoleCtrlEvent for the
//!   cooperative phase, OpenMutexW for Global_MSI_Execute, and
//!   `sc.exe query` for the msiserver service state.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

pub type Handle = *mut std::ffi::c_void;
pub const INVALID_HANDLE: Handle = -1isize as Handle;
pub const NULL_HANDLE: Handle = null_mut();

pub const TH32CS_SNAPPROCESS: u32 = 0x00000002;
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const SYNCHRONIZE: u32 = 0x00100000;
pub const TOKEN_QUERY: u32 = 0x0008;
pub const TOKEN_USER_CLASS: u32 = 1;
pub const TOKEN_ELEVATION_CLASS: u32 = 20;
pub const CTRL_BREAK_EVENT: u32 = 1;
pub const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
pub const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
pub const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x00000008;
pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
pub const PROC_THREAD_ATTRIBUTE_JOB_LIST: usize = 0x0002000D;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 0x00000102;

pub fn wide(s: &str) -> Vec<u16> {
  OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

pub fn close_handle(h: Handle) {
  if !h.is_null() && h != INVALID_HANDLE {
    unsafe { CloseHandle(h); }
  }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct IoCounters {
  read_op: u64,
  write_op: u64,
  other_op: u64,
  read_xfer: u64,
  write_xfer: u64,
  other_xfer: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BasicLimit {
  per_process_user_time: i64,
  per_job_user_time: i64,
  limit_flags: u32,
  min_ws: usize,
  max_ws: usize,
  active_process_limit: u32,
  affinity: usize,
  scheduling_class: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ExtLimit {
  basic: BasicLimit,
  io: IoCounters,
  process_memory_limit: usize,
  job_memory_limit: usize,
  peak_process_memory: usize,
  peak_job_memory: usize,
}

#[repr(C)]
#[derive(Default)]
struct StartupInfo {
  cb: u32,
  reserved: *mut u16,
  desktop: *mut u16,
  title: *mut u16,
  x: u32,
  y: u32,
  x_size: u32,
  y_size: u32,
  x_count_chars: u32,
  y_count_chars: u32,
  fill_attribute: u32,
  flags: u32,
  show_window: u16,
  reserved2: u16,
  reserved2_ptr: *mut u8,
  stdin: Handle,
  stdout: Handle,
  stderr: Handle,
}

#[repr(C)]
struct StartupInfoEx {
  startup: StartupInfo,
  attr_list: *mut std::ffi::c_void,
}

#[repr(C)]
#[derive(Default)]
struct ProcInfoRaw {
  process: Handle,
  thread: Handle,
  pid: u32,
  tid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessEntry {
  size: u32,
  usage: u32,
  pid: u32,
  default_heap: usize,
  module_id: u32,
  threads: u32,
  ppid: u32,
  pri_base: i32,
  flags: u32,
  exe_file: [u16; 260],
}

impl Default for ProcessEntry {
  fn default() -> Self {
    unsafe { std::mem::zeroed() }
  }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SidAndAttributes {
  sid: *mut std::ffi::c_void,
  attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TokenUser {
  user: SidAndAttributes,
}

#[link(name = "kernel32")]
extern "system" {
  fn CreateJobObjectW(attrs: *const std::ffi::c_void, name: *const u16) -> Handle;
  fn SetInformationJobObject(job: Handle, cls: i32, info: *const std::ffi::c_void, len: u32) -> i32;
  fn TerminateJobObject(job: Handle, code: u32) -> i32;
  fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
  fn CreateProcessW(app: *const u16, cmdline: *mut u16, proc_attrs: *const std::ffi::c_void, thread_attrs: *const std::ffi::c_void, inherit: i32, flags: u32, env: *const std::ffi::c_void, dir: *const u16, startup: *const StartupInfo, proc_info: *mut ProcInfoRaw) -> i32;
  fn InitializeProcThreadAttributeList(list: *mut std::ffi::c_void, count: u32, flags: u32, size: *mut usize) -> i32;
  fn UpdateProcThreadAttribute(list: *mut std::ffi::c_void, flags: u32, attribute: usize, value: *const std::ffi::c_void, size: usize, prev: *const std::ffi::c_void, prev_size: *mut usize) -> i32;
  fn DeleteProcThreadAttributeList(list: *mut std::ffi::c_void);
  fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> Handle;
  fn Process32FirstW(snap: Handle, entry: *mut ProcessEntry) -> i32;
  fn Process32NextW(snap: Handle, entry: *mut ProcessEntry) -> i32;
  fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
  fn TerminateProcess(process: Handle, code: u32) -> i32;
  fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
  fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
  fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
  fn CloseHandle(handle: Handle) -> i32;
  fn GetLastError() -> u32;
  fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
  fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> Handle;
  fn LocalFree(mem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[link(name = "advapi32")]
extern "system" {
  fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
  fn GetTokenInformation(token: Handle, cls: u32, info: *mut std::ffi::c_void, len: u32, ret_len: *mut u32) -> i32;
  fn ConvertSidToStringSidW(sid: *const std::ffi::c_void, out: *mut *mut u16) -> i32;
}

fn last_error() -> u32 {
  unsafe { GetLastError() }
}

fn wide_to_string(buf: &[u16]) -> String {
  let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
  String::from_utf16_lossy(&buf[..end])
}

/// One process, with the identity fields the spike must record.
#[derive(Clone, Debug)]
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
      "exe_path": self.exe,
      "session_id": self.session,
      "user": self.user,
      "sid": self.sid,
      "in_job": self.in_job,
    })
  }
  /// True for the Windows Installer service process: msiexec.exe
  /// running as SYSTEM in session 0 whose parent is services.exe.
  pub fn looks_like_service_msiexec(&self, services_pid: Option<u32>) -> bool {
    let name = self.exe.rsplit('\\').next().unwrap_or(&self.exe).to_ascii_lowercase();
    name == "msiexec.exe"
      && self.session == Some(0)
      && self.user.as_deref() == Some("SYSTEM")
      && services_pid.map(|s| self.ppid == s).unwrap_or(true)
  }
}

pub fn user_label_for_sid(sid: &str) -> &'static str {
  match sid {
    "S-1-5-18" => "SYSTEM",
    "S-1-5-19" => "LOCAL SERVICE",
    "S-1-5-20" => "NETWORK SERVICE",
    _ => "user",
  }
}

/// SID string of a process token, if the token can be opened.
pub fn token_sid(pid: u32) -> Option<String> {
  unsafe {
    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if proc.is_null() {
      return None;
    }
    let mut token: Handle = NULL_HANDLE;
    let sid = if OpenProcessToken(proc, TOKEN_QUERY, &mut token) == 0 || token.is_null() {
      None
    } else {
      let mut need: u32 = 0;
      GetTokenInformation(token, TOKEN_USER_CLASS, null_mut(), 0, &mut need);
      let mut buf = vec![0u8; need.max(1) as usize];
      let mut got: u32 = 0;
      let out = if GetTokenInformation(token, TOKEN_USER_CLASS, buf.as_mut_ptr() as *mut std::ffi::c_void, need, &mut got) == 0 {
        None
      } else {
        let tu = &*(buf.as_ptr() as *const TokenUser);
        let mut wstr: *mut u16 = null_mut();
        if ConvertSidToStringSidW(tu.user.sid, &mut wstr) == 0 || wstr.is_null() {
          None
        } else {
          let mut len = 0usize;
          while *wstr.add(len) != 0 {
            len += 1;
          }
          let s = String::from_utf16_lossy(std::slice::from_raw_parts(wstr, len));
          LocalFree(wstr as *mut std::ffi::c_void);
          Some(s)
        }
      };
      CloseHandle(token);
      out
    };
    CloseHandle(proc);
    sid
  }
}

pub fn process_elevated(pid: u32) -> Option<bool> {
  unsafe {
    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if proc.is_null() {
      return None;
    }
    let mut token: Handle = NULL_HANDLE;
    let out = if OpenProcessToken(proc, TOKEN_QUERY, &mut token) == 0 || token.is_null() {
      None
    } else {
      let mut elev: u32 = 0;
      let mut got: u32 = 0;
      let ok = GetTokenInformation(token, TOKEN_ELEVATION_CLASS, &mut elev as *mut u32 as *mut std::ffi::c_void, 4, &mut got) != 0;
      CloseHandle(token);
      if ok { Some(elev != 0) } else { None }
    };
    CloseHandle(proc);
    out
  }
}

pub fn is_elevated() -> bool {
  process_elevated(std::process::id()).unwrap_or(false)
}

pub fn session_id(pid: u32) -> Option<u32> {
  unsafe {
    let mut s: u32 = 0;
    if ProcessIdToSessionId(pid, &mut s) != 0 { Some(s) } else { None }
  }
}

pub fn exe_path(pid: u32) -> Option<String> {
  unsafe {
    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if proc.is_null() {
      return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut size: u32 = 1024;
    let out = if QueryFullProcessImageNameW(proc, 0, buf.as_mut_ptr(), &mut size) != 0 {
      Some(String::from_utf16_lossy(&buf[..size as usize]))
    } else {
      None
    };
    CloseHandle(proc);
    out
  }
}

fn in_job(pid: u32, job: Handle) -> Option<bool> {
  unsafe {
    let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if proc.is_null() {
      return None;
    }
    let mut r: i32 = 0;
    let ok = IsProcessInJob(proc, job, &mut r) != 0;
    CloseHandle(proc);
    if ok { Some(r != 0) } else { None }
  }
}

/// (pid, ppid, exe file name) for every process, via Toolhelp.
pub fn snapshot() -> Vec<(u32, u32, String)> {
  unsafe {
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == INVALID_HANDLE || snap.is_null() {
      return Vec::new();
    }
    let mut out = Vec::new();
    let mut e = ProcessEntry::default();
    e.size = std::mem::size_of::<ProcessEntry>() as u32;
    if Process32FirstW(snap, &mut e) != 0 {
      loop {
        out.push((e.pid, e.ppid, wide_to_string(&e.exe_file)));
        if Process32NextW(snap, &mut e) == 0 {
          break;
        }
      }
    }
    CloseHandle(snap);
    out
  }
}

pub fn alive(pid: u32) -> bool {
  snapshot().iter().any(|(p, _, _)| *p == pid)
}

pub fn wait_for_exit(pid: u32, timeout: Duration) -> bool {
  let start = Instant::now();
  loop {
    if !alive(pid) {
      return true;
    }
    if start.elapsed() >= timeout {
      return false;
    }
    std::thread::sleep(Duration::from_millis(50));
  }
}

/// Full identity for one snapshot row.
pub fn identify(pid: u32, ppid: u32, exe_name: &str, job: Option<Handle>) -> Proc {
  let exe = exe_path(pid).unwrap_or_else(|| exe_name.to_string());
  let sid = token_sid(pid);
  let user = sid.as_deref().map(user_label_for_sid).map(|s| s.to_string());
  Proc {
    pid,
    ppid,
    exe,
    session: session_id(pid),
    user,
    sid,
    in_job: job.and_then(|j| in_job(pid, j)),
  }
}

/// All descendants of `root` (any depth) via PPID tracing.
pub fn descendants(root: u32) -> Vec<u32> {
  let snap = snapshot();
  let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
  for (pid, ppid, _) in &snap {
    children.entry(*ppid).or_default().push(*pid);
  }
  let mut out = Vec::new();
  let mut stack = vec![root];
  while let Some(p) = stack.pop() {
    if let Some(kids) = children.get(&p) {
      for k in kids {
        out.push(*k);
        stack.push(*k);
      }
    }
  }
  out
}

/// Depth of each pid in the tree rooted at `root` (root = 0).
pub fn depths(root: u32, pids: &[u32]) -> HashMap<u32, usize> {
  let snap = snapshot();
  let mut parent: HashMap<u32, u32> = HashMap::new();
  for (pid, ppid, _) in &snap {
    parent.insert(*pid, *ppid);
  }
  let mut out = HashMap::new();
  for pid in pids {
    let mut d = 0usize;
    let mut cur = *pid;
    for _ in 0..100 {
      if cur == root {
        break;
      }
      match parent.get(&cur) {
        Some(p) => {
          d += 1;
          cur = *p;
        }
        None => break,
      }
    }
    out.insert(*pid, d);
  }
  out
}

/// Every live msiexec.exe process, with identity (job = None).
pub fn msiexec_processes() -> Vec<Proc> {
  snapshot()
    .into_iter()
    .filter(|(_, _, n)| n.eq_ignore_ascii_case("msiexec.exe"))
    .map(|(pid, ppid, name)| identify(pid, ppid, &name, None))
    .collect()
}

pub fn services_pid() -> Option<u32> {
  snapshot()
    .into_iter()
    .find(|(_, _, n)| n.eq_ignore_ascii_case("services.exe"))
    .map(|(pid, _, _)| pid)
}

pub fn terminate_pid(pid: u32) -> bool {
  unsafe {
    let proc = OpenProcess(PROCESS_TERMINATE, 0, pid);
    if proc.is_null() {
      return false;
    }
    let ok = TerminateProcess(proc, 1) != 0;
    CloseHandle(proc);
    ok
  }
}

pub fn terminate_job(job: Handle) -> (bool, u32) {
  unsafe {
    let ok = TerminateJobObject(job, 1) != 0;
    (ok, if ok { 0 } else { last_error() })
  }
}

/// Cooperative phase: CTRL_BREAK_EVENT to the process group, then
/// wait up to `coop_ms` for the root to exit. Returns elapsed ms
/// and whether the root died during this phase.
pub fn cooperative_phase(root_pid: u32, coop_ms: u64) -> (u64, bool) {
  let start = Instant::now();
  let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, root_pid) };
  let _ = sent;
  loop {
    if !alive(root_pid) {
      return (start.elapsed().as_millis() as u64, true);
    }
    if start.elapsed().as_millis() as u64 >= coop_ms {
      return (start.elapsed().as_millis() as u64, false);
    }
    std::thread::sleep(Duration::from_millis(50));
  }
}

/// True when the Global_MSI_Execute mutex can be opened by nobody
/// else: opening it fails because it does not exist.
pub fn msi_execute_mutex_free() -> bool {
  unsafe {
    let name = wide("Global\\MSI_Execute");
    let h = OpenMutexW(SYNCHRONIZE, 0, name.as_ptr());
    if h.is_null() {
      true
    } else {
      CloseHandle(h);
      false
    }
  }
}

/// `sc.exe query msiserver` (+ queryex for the service PID).
pub fn sc_query_msiserver() -> Value {
  let run = |args: &[&str]| -> String {
    std::process::Command::new("sc.exe")
      .args(args)
      .output()
      .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
      .unwrap_or_default()
  };
  let q = run(&["query", "msiserver"]);
  let qx = run(&["queryex", "msiserver"]);
  let state = q
    .lines()
    .find(|l| l.trim_start().starts_with("STATE"))
    .map(|l| l.trim().to_string());
  let pid = qx
    .lines()
    .find(|l| l.trim_start().starts_with("PID"))
    .and_then(|l| l.split(':').nth(1))
    .and_then(|v| v.trim().parse::<u32>().ok());
  json!({ "state_line": state, "service_pid": pid, "query": q, "queryex": qx })
}

pub struct Launched {
  pub pid: u32,
  pub handle: Handle,
  pub job: Handle,
}

impl Launched {
  pub fn close(&mut self) {
    close_handle(self.handle);
    self.handle = NULL_HANDLE;
    // Closing the job handle kills remaining job members
    // (KILL_ON_JOB_CLOSE) — only after the measurement is done.
    close_handle(self.job);
    self.job = NULL_HANDLE;
  }
}

/// Launch `cmdline` inside a fresh job (no breakaway, limit 32,
/// KILL_ON_JOB_CLOSE), assigned before its first thread runs.
pub fn launch_in_job(cmdline: &str) -> Result<Launched, String> {
  unsafe {
    let job = CreateJobObjectW(null_mut(), null_mut());
    if job.is_null() {
      return Err(format!("CreateJobObjectW failed, last_error={}", last_error()));
    }
    let mut limits = ExtLimit::default();
    limits.basic.limit_flags =
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    limits.basic.active_process_limit = 32;
    if SetInformationJobObject(
      job,
      JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
      &limits as *const ExtLimit as *const std::ffi::c_void,
      std::mem::size_of::<ExtLimit>() as u32,
    ) == 0
    {
      let e = last_error();
      CloseHandle(job);
      return Err(format!("SetInformationJobObject failed, last_error={}", e));
    }
    let mut size: usize = 0;
    InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
    let mut attr_buf = vec![0u8; size.max(1)];
    let attr_list = attr_buf.as_mut_ptr() as *mut std::ffi::c_void;
    if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) == 0 {
      let e = last_error();
      CloseHandle(job);
      return Err(format!("InitializeProcThreadAttributeList failed, last_error={}", e));
    }
    let job_val: Handle = job;
    let ok_attr = UpdateProcThreadAttribute(
      attr_list,
      0,
      PROC_THREAD_ATTRIBUTE_JOB_LIST,
      &job_val as *const Handle as *const std::ffi::c_void,
      std::mem::size_of::<Handle>(),
      null_mut(),
      null_mut(),
    );
    if ok_attr == 0 {
      let e = last_error();
      DeleteProcThreadAttributeList(attr_list);
      CloseHandle(job);
      return Err(format!("UpdateProcThreadAttribute failed, last_error={}", e));
    }
    let mut si = StartupInfoEx {
      startup: StartupInfo::default(),
      attr_list,
    };
    si.startup.cb = std::mem::size_of::<StartupInfoEx>() as u32;
    let mut cmd = wide(cmdline);
    let mut pi = ProcInfoRaw::default();
    let ok = CreateProcessW(
      null_mut(),
      cmd.as_mut_ptr(),
      null_mut(),
      null_mut(),
      0,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP,
      null_mut(),
      null_mut(),
      &si.startup,
      &mut pi,
    );
    DeleteProcThreadAttributeList(attr_list);
    if ok == 0 {
      let e = last_error();
      CloseHandle(job);
      return Err(format!("CreateProcessW failed, last_error={}", e));
    }
    close_handle(pi.thread);
    Ok(Launched { pid: pi.pid, handle: pi.process, job })
  }
}

// --- v2 (cycle 41): creation-time based alternative naming -----------------
// PPID enumeration does not cover processes born via Win32_Process.Create
// (COM/WMI): their parent is wmiprvse, not the command's tree. Such an
// orphan is therefore identified by (creation-time window + exe path)
// instead of by PPID. This is an explicit acknowledgement, not a claim
// that PPID enumeration covers COM-created processes.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileTime {
    pub dw_low_date_time: u32,
    pub dw_high_date_time: u32,
}

extern "system" {
    fn GetProcessTimes(
        h_process: *mut std::ffi::c_void,
        lp_creation_time: *mut FileTime,
        lp_exit_time: *mut FileTime,
        lp_kernel_time: *mut FileTime,
        lp_user_time: *mut FileTime,
    ) -> i32;
}

/// Creation time of a process, or None if it cannot be opened / has exited.
pub fn process_creation_time(pid: u32) -> Option<std::time::SystemTime> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() { return None; }
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        let ok = GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user);
        CloseHandle(h);
        if ok == 0 { return None; }
        let ft = ((creation.dw_high_date_time as u64) << 32) | (creation.dw_low_date_time as u64);
        const EPOCH_DIFF_100NS: u64 = 116444736000000000;
        if ft < EPOCH_DIFF_100NS { return None; }
        let since_unix = ft - EPOCH_DIFF_100NS;
        Some(std::time::UNIX_EPOCH + std::time::Duration::from_nanos(since_unix * 100))
    }
}

/// Processes whose full exe path equals `exe_path` (case-insensitive) and
/// whose creation time lies inside [window_start, window_end]. Used by
/// kill::abort for orphans that PPID enumeration cannot see.
pub fn processes_by_exe_and_window(
    exe_path: &str,
    window_start: std::time::SystemTime,
    window_end: std::time::SystemTime,
) -> Vec<Proc> {
    let needle = exe_path.to_ascii_lowercase();
    let mut out: Vec<Proc> = Vec::new();
    for (pid, ppid, _name) in snapshot() {
        let path = match exe_path_of(pid) { Some(p) => p, None => continue };
        if path.to_ascii_lowercase() != needle { continue; }
        match process_creation_time(pid) {
            Some(t) if t >= window_start && t <= window_end => {}
            _ => continue,
        }
        let proc = identify(pid, ppid, &path, None);
        out.push(proc);
    }
    out
}

/// Full exe path of a process (wrapper over the existing exe_path helper
/// name used elsewhere in this module, if present; otherwise via snapshot).
fn exe_path_of(pid: u32) -> Option<String> {
    exe_path(pid)
}
