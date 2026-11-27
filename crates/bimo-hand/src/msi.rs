//! Windows Installer API (msi.dll) via raw extern "system".
//!
//! Stage 2 of the spike does NOT kill msiexec.exe. It installs via
//! MsiInstallProduct with an external UI handler that returns
//! IDCANCEL (2) once the stop signal is set — the transactional
//! cancel path for MSI. The service process itself is never
//! terminated (Microsoft warns that killing it risks corruption,
//! and `net stop msiserver` is refused with error 2191 while an
//! install runs).
//!
//! Product presence is checked by enumerating installed products
//! (MsiEnumProductsW + MsiGetProductInfoW "ProductName") for the named product,
//! and removal uses MsiConfigureProductW(..., INSTALLSTATE_ABSENT).
//! v2 / section 8.1 (corrected, cycle 41): cancellation is MsiInstallProduct +
//! an external UI handler returning IDCANCEL; removal in phase A is a full
//! install via MsiInstallProduct followed by removal via MsiConfigureProductW
//! (INSTALLSTATE_ABSENT) and verification that the product is gone.
//! MsiConfigureProductW is used for removal only, never for cancellation.

use crate::win32::wide;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub type UiHandler = extern "system" fn(*mut std::ffi::c_void, u32, *const u16, *const u16) -> i32;

static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static HANDLER_CALLS: AtomicU64 = AtomicU64::new(0);
static HANDLER_FIRST_MS: AtomicU64 = AtomicU64::new(0);
static INSTALL_STARTED_MS: AtomicU64 = AtomicU64::new(0);
static LAST_ACTION: Mutex<Option<String>> = Mutex::new(None);
static REGISTER_PRODUCT_SEEN: AtomicBool = AtomicBool::new(false);
static CANCEL_DEPTH_RECORDED: AtomicBool = AtomicBool::new(false);
static ACTION_AT_CANCEL: Mutex<Option<String>> = Mutex::new(None);
static REACHED_REGISTER_PRODUCT_AT_CANCEL: AtomicBool = AtomicBool::new(false);
static HANDLER_CALLS_AT_CANCEL: AtomicU64 = AtomicU64::new(0);

// INSTALLMESSAGE_* return values: IDOK = 1 (continue), IDCANCEL = 2.
extern "system" fn ui_handler(
  _ctx: *mut std::ffi::c_void,
  _msg_type: u32,
  _msg: *const u16,
  _extra: *const u16,
) -> i32 {
  if HANDLER_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
    HANDLER_FIRST_MS.store(now_ms(), Ordering::SeqCst);
                          }
    if !_msg.is_null() {
        record_msi_message(&read_message_text(_msg));
    }
  if CANCEL_REQUESTED.load(Ordering::SeqCst) {
      if !CANCEL_DEPTH_RECORDED.swap(true, Ordering::SeqCst) {
          let last = LAST_ACTION.lock().ok().and_then(|g| g.clone());
          if let Ok(mut slot) = ACTION_AT_CANCEL.lock() {
              *slot = last;
          }
          REACHED_REGISTER_PRODUCT_AT_CANCEL.store(REGISTER_PRODUCT_SEEN.load(Ordering::SeqCst), Ordering::SeqCst);
          HANDLER_CALLS_AT_CANCEL.store(HANDLER_CALLS.load(Ordering::SeqCst), Ordering::SeqCst);
      }
    2
  } else {
    1
  }
}
fn read_message_text(msg: *const u16) -> String {
    if msg.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while len < 8192 && *msg.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(msg, len);
        String::from_utf16_lossy(slice)
    }
}
fn parse_action_start(text: &str) -> Option<String> {
    if !text.contains("Action start") {
        return None;
    }
    let after = text.splitn(2, "Action start").nth(1)?;
    let parts: Vec<&str> = after.split(": ").collect();
    if parts.len() < 4 {
        return None;
    }
    let name = parts[3].trim().trim_end_matches('.').trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some(name.to_string())
}
fn known_action_in(text: &str) -> Option<String> {
    for name in ["InstallValidate", "InstallInitialize", "ProcessComponents", "UnpublishComponents", "UnpublishFeatures", "InstallExecute", "AllocateSideBySide", "InstallFiles", "RegisterUser", "RegisterProduct", "PublishFeatures", "PublishProduct", "InstallFinalize"] {
        if text.contains(name) {
            return Some(name.to_string());
        }
    }
    None
}
fn record_msi_message(text: &str) {
    if text.is_empty() {
        return;
    }
    if text.contains("RegisterProduct") {
        REGISTER_PRODUCT_SEEN.store(true, Ordering::SeqCst);
    }
    let action = parse_action_start(text).or_else(|| known_action_in(text));
    if let Some(action) = action {
        if let Ok(mut last) = LAST_ACTION.lock() {
            *last = Some(action);
        }
    }
}
fn reset_cancel_depth() {
    if let Ok(mut last) = LAST_ACTION.lock() {
        *last = None;
    }
    REGISTER_PRODUCT_SEEN.store(false, Ordering::SeqCst);
    CANCEL_DEPTH_RECORDED.store(false, Ordering::SeqCst);
    if let Ok(mut slot) = ACTION_AT_CANCEL.lock() {
        *slot = None;
    }
    REACHED_REGISTER_PRODUCT_AT_CANCEL.store(false, Ordering::SeqCst);
    HANDLER_CALLS_AT_CANCEL.store(0, Ordering::SeqCst);
}

pub fn cancel_depth() -> Value {
    let (last_action, reached, calls) = if CANCEL_DEPTH_RECORDED.load(Ordering::SeqCst) {
        (
            ACTION_AT_CANCEL.lock().ok().and_then(|g| g.clone()),
            REACHED_REGISTER_PRODUCT_AT_CANCEL.load(Ordering::SeqCst),
            HANDLER_CALLS_AT_CANCEL.load(Ordering::SeqCst),
            )
    } else {
        (
            LAST_ACTION.lock().ok().and_then(|g| g.clone()),
            REGISTER_PRODUCT_SEEN.load(Ordering::SeqCst),
            HANDLER_CALLS.load(Ordering::SeqCst),
            )
    };
    json!({
        "last_action": last_action,
        "reached_register_product": reached,
        "handler_calls_at_cancel": calls,
    })
}
#[link(name = "msi")]
extern "system" {
  fn MsiInstallProductW(pkg: *const u16, cmdline: *const u16) -> u32;
  fn MsiSetExternalUIW(handler: Option<UiHandler>, filter: u32, ctx: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
  fn MsiSetInternalUI(level: u32, hwnd: *mut *mut std::ffi::c_void) -> u32;
  fn MsiEnumProductsW(index: u32, buf: *mut u16) -> u32;
  fn MsiGetProductInfoW(product: *const u16, property: *const u16, value: *mut u16, len: *mut u32) -> u32;
  fn MsiQueryProductStateW(product: *const u16) -> i32;
  fn MsiConfigureProductW(product: *const u16, level: i32, state: i32) -> u32;
  fn MsiEnableLogW(log_mode: u32, log_file: *const u16, attributes: u32) -> u32;
}

pub const ERROR_INSTALL_USEREXIT: u32 = 1602;
pub const INSTALLSTATE_ABSENT: i32 = 2;
// INSTALLLOGMODE_VERBOSE (0x400): the /L*v log. INSTALLLOGATTRIBUTES_FLUSHEACHLINE (0x2).
pub const INSTALLLOGMODE_VERBOSE: u32 = 0x400;
pub const INSTALLLOGATTRIBUTES_FLUSHEACHLINE: u32 = 0x2;

/// Enable the verbose MSI log for installs performed by THIS process
/// (cycle 64, council 21 D1(3) — capture-only). MsiEnableLog does NOT
/// change the install invocation: MsiInstallProductW and its command
/// line (REBOOT=ReallySuppress TARGETDIR=...) stay byte-identical; it
/// only records the installer's own log to `log_path`. Returns the MSI
/// return code (0 = logging enabled). The log file is written by the
/// installer engine as the install runs; the caller copies it out
/// before any later phase can touch it.
pub fn enable_install_log(log_path: &std::path::Path) -> u32 {
    let path = wide(&log_path.to_string_lossy());
    unsafe { MsiEnableLogW(INSTALLLOGMODE_VERBOSE, path.as_ptr(), INSTALLLOGATTRIBUTES_FLUSHEACHLINE) }
}

fn wide_string(buf: &[u16]) -> String {
  let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
  String::from_utf16_lossy(&buf[..end])
}
/// Milliseconds since the Unix epoch (probe: first UI-handler call time).
pub fn now_ms() -> u64 {
  std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
  .map(|d| d.as_millis() as u64)
  .unwrap_or(0)
}

pub struct CancelOutcome {
  pub return_code: u32,
  pub cancel_ms: u64,
  pub total_ms: u64,
  pub handler_calls: u64,
  pub handler_first_ms: u64,
  pub internal_ui_prev: u32,
  pub external_ui_prev_non_null: bool,
  pub cancelled: bool,
}

/// Install `msi_path` via the API; a timer thread sets the cancel
/// flag after `cancel_after_ms`, and the UI handler then returns
/// IDCANCEL. `cancel_ms` is the time from the flag being set until
/// MsiInstallProduct returns.
pub fn install_with_cancel(msi_path: &str, cancel_after_ms: u64) -> CancelOutcome {
  CANCEL_REQUESTED.store(false, Ordering::SeqCst);
  HANDLER_CALLS.store(0, Ordering::SeqCst);
    reset_cancel_depth();
  unsafe {
    // INSTALLUILEVEL_NONE = 2: no dialogs on the runner.
    MsiSetInternalUI(2, std::ptr::null_mut());
    MsiSetExternalUIW(Some(ui_handler), 0xFFFF_FFFF, std::ptr::null_mut());
  }
  let (tx, rx) = std::sync::mpsc::channel::<()>();
  std::thread::spawn(move || {
    std::thread::sleep(Duration::from_millis(cancel_after_ms));
    CANCEL_REQUESTED.store(true, Ordering::SeqCst);
    let _ = tx.send(());
  });
  let start = Instant::now();
  let pkg = wide(msi_path);
  let cmd = wide("REBOOT=ReallySuppress");
  let rc = unsafe { MsiInstallProductW(pkg.as_ptr(), cmd.as_ptr()) };
  let total = start.elapsed().as_millis() as u64;
  let _ = rx.recv_timeout(Duration::from_millis(200));
  unsafe {
    MsiSetExternalUIW(None, 0, std::ptr::null_mut());
    MsiSetInternalUI(1, std::ptr::null_mut());
  }
  CancelOutcome {
    return_code: rc,
    cancel_ms: total.saturating_sub(cancel_after_ms),
    total_ms: total,
    handler_calls: HANDLER_CALLS.load(Ordering::SeqCst), handler_first_ms: 0, internal_ui_prev: 0, external_ui_prev_non_null: false,
    cancelled: CANCEL_REQUESTED.load(Ordering::SeqCst),
  }
}

fn product_name(code: &str) -> Option<String> {
  let c = wide(code);
  let p = wide("ProductName");
  let mut buf = vec![0u16; 256];
  let mut len: u32 = 256;
  let rc = unsafe { MsiGetProductInfoW(c.as_ptr(), p.as_ptr(), buf.as_mut_ptr(), &mut len) };
  if rc != 0 {
    return None;
  }
  Some(wide_string(&buf))
}

/// (product code, product name) of the installed product whose name contains
/// `name_substring` (case-insensitive). No product name is hard-coded here:
/// the caller (self-test only) supplies the name to look for.
pub fn find_product_by_name(name_substring: &str) -> Option<(String, String)> {
    let needle = name_substring.to_ascii_lowercase();
    for i in 0..1024u32 {
        let mut buf = vec![0u16; 39];
        let rc = unsafe { MsiEnumProductsW(i, buf.as_mut_ptr()) };
        if rc != 0 { break; }
        let code = wide_string(&buf);
        if let Some(name) = product_name(&code) {
            if name.to_ascii_lowercase().contains(&needle) {
                return Some((code, name));
            }
        }
    }
    None
}

pub fn product_version(code: &str) -> Option<String> {
    let c = wide(code);
    let p = wide("ProductVersion");
    let mut buf = vec![0u16; 64];
    let mut len: u32 = 64;
    let rc = unsafe { MsiGetProductInfoW(c.as_ptr(), p.as_ptr(), buf.as_mut_ptr(), &mut len) };
    if rc != 0 { return None; }
    Some(wide_string(&buf))
}

pub fn product_state(code: &str) -> i32 {
  let c = wide(code);
  unsafe { MsiQueryProductStateW(c.as_ptr()) }
}

pub fn uninstall_product(code: &str) -> u32 {
  let c = wide(code);
  unsafe { MsiConfigureProductW(c.as_ptr(), 0, INSTALLSTATE_ABSENT) }
}

/// Current product presence (by name substring): {"present": bool, "product_code", "product_name", "product_state"}.
pub fn product_presence_by_name(name_substring: &str) -> Value {
    match find_product_by_name(name_substring) {
        None => json!({ "present": false, "product_code": null, "product_name": null, "product_state": null }),
        Some((code, name)) => {
            let state = product_state(&code);
            let version = product_version(&code);
            json!({ "present": true, "product_code": code, "product_name": name, "product_state": state, "product_version": version })
        }
    }
}

/// Poll until the product is absent (uninstalling it if present), up to
/// `timeout_ms`. `product_code` may be given directly; otherwise the product
/// is found by `name_substring`. Returns {product_absent, waited_ms,
/// uninstall_return_code, product_state, ...}.
pub fn ensure_product_absent(product_code: Option<&str>, name_substring: &str, timeout_ms: u64) -> Value {
    let start = Instant::now();
    let mut uninstall_rc: Option<u32> = None;
    loop {
        let found: Option<(String, String)> = match product_code {
            Some(code) => match product_name(code) {
                Some(name) => Some((code.to_string(), name)),
                None => None,
            },
            None => find_product_by_name(name_substring),
        };
        match found {
            None => {
                return json!({
                    "product_absent": true,
                    "waited_ms": start.elapsed().as_millis() as u64,
                    "uninstall_return_code": uninstall_rc,
                    "product_state": null,
                });
            }
            Some((code, name)) => {
                let state = product_state(&code);
                uninstall_rc = Some(uninstall_product(&code));
                if start.elapsed().as_millis() as u64 >= timeout_ms {
                    return json!({
                        "product_absent": false,
                        "waited_ms": start.elapsed().as_millis() as u64,
                        "uninstall_return_code": uninstall_rc,
                        "product_state": state,
                        "product_code": code,
                        "product_name": name,
                    });
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
    }
}

/// Full install via MsiInstallProductW, with no cancel flag set (phase A).
/// Returns the MSI return code (0 on success).
pub fn install_product(msi_path: &str) -> u32 {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    HANDLER_CALLS.store(0, Ordering::SeqCst);
    unsafe {
        MsiSetInternalUI(2, std::ptr::null_mut());
        MsiSetExternalUIW(None, 0, std::ptr::null_mut());
    }
    let pkg = wide(msi_path);
    let cmd = wide("REBOOT=ReallySuppress");
    let rc = unsafe { MsiInstallProductW(pkg.as_ptr(), cmd.as_ptr()) };
    unsafe { MsiSetInternalUI(1, std::ptr::null_mut()); }
    rc
}

/// Install via MsiInstallProductW, cancelling (IDCANCEL) as soon as the
/// caller sets `cancel` (shared with the supervisor's monitor thread).
/// This is the v2 topology: MsiInstallProduct runs in a dedicated thread
/// inside the supervisor, while the supervisor keeps monitoring the
/// heartbeat and hand.stop from a separate thread and sets `cancel`.
/// `cancel_ms` is the rollback wait: the time from `cancel` being set
/// until MsiInstallProductW returns (the `forced_ms` of the abort outcome).
/// `cmdline` is the installer command line (public properties): the
/// default is "REBOOT=ReallySuppress"; the slice passes
/// "REBOOT=ReallySuppress TARGETDIR=<custom dir>" (§28.2 (a)) so the
/// installer roots the install under the watched parent instead of the
/// MSI default. NOTE: the msiexec.exe argument line is NEVER used on
/// this path — the install goes through the API, so TARGETDIR must
/// travel in this cmdline, not in ExecRequest.args.
pub fn install_with_external_cancel(msi_path: &str, cancel: Arc<AtomicBool>) -> CancelOutcome {
    install_with_external_cancel_cmdline(msi_path, "REBOOT=ReallySuppress", cancel)
}

pub fn install_with_external_cancel_cmdline(msi_path: &str, cmdline: &str, cancel: Arc<AtomicBool>) -> CancelOutcome {
    CANCEL_REQUESTED.store(false, Ordering::SeqCst);
    HANDLER_CALLS.store(0, Ordering::SeqCst);
  HANDLER_FIRST_MS.store(0, Ordering::SeqCst);
  INSTALL_STARTED_MS.store(now_ms(), Ordering::SeqCst);
    reset_cancel_depth();
    let cancel_at: Arc<std::sync::Mutex<Option<Instant>>> = Arc::new(std::sync::Mutex::new(None));
    let done = Arc::new(AtomicBool::new(false));
    let watcher_cancel = Arc::clone(&cancel);
    let watcher_at = Arc::clone(&cancel_at);
    let watcher_done = Arc::clone(&done);
    let watcher = std::thread::spawn(move || {
        loop {
            if watcher_cancel.load(Ordering::SeqCst) {
                *watcher_at.lock().unwrap() = Some(Instant::now());
                CANCEL_REQUESTED.store(true, Ordering::SeqCst);
                break;
            }
            if watcher_done.load(Ordering::SeqCst) { break; }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let internal_ui_prev = unsafe { MsiSetInternalUI(2, std::ptr::null_mut()) };
    let external_ui_prev = unsafe { MsiSetExternalUIW(Some(ui_handler), 0xFFFF_FFFF, std::ptr::null_mut()) };
    let start = Instant::now();
    let pkg = wide(msi_path);
    let cmd = wide(cmdline);
    let rc = unsafe { MsiInstallProductW(pkg.as_ptr(), cmd.as_ptr()) };
    let returned_at = Instant::now();
    done.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    unsafe {
        MsiSetExternalUIW(None, 0, std::ptr::null_mut());
        MsiSetInternalUI(1, std::ptr::null_mut());
    }
    let cancelled = cancel.load(Ordering::SeqCst);
    let cancel_ms = match *cancel_at.lock().unwrap() {
        Some(t) => returned_at.duration_since(t).as_millis() as u64,
        None => 0,
    };
    CancelOutcome {
        return_code: rc,
        cancel_ms,
        total_ms: start.elapsed().as_millis() as u64,
        handler_calls: HANDLER_CALLS.load(Ordering::SeqCst), handler_first_ms: HANDLER_FIRST_MS.load(Ordering::SeqCst).saturating_sub(INSTALL_STARTED_MS.load(Ordering::SeqCst)), internal_ui_prev, external_ui_prev_non_null: !external_ui_prev.is_null(),
        cancelled,
    }
}

/// Pre-command state record (v2 condition 1): MsiGetProductState for
/// `product_code` (if known), the Global_MSI_Execute mutex state, and a
/// listing of the target folder. Recorded before each phase in JSON.
pub fn pre_command_state(product_code: Option<&str>, target_dir: &str) -> Value {
    let state = product_code.map(product_state);
    let mutex_free = crate::win32::msi_execute_mutex_free();
    let listing = target_folder_listing(target_dir);
    json!({
        "product_state": state,
        "msi_execute_mutex_free": mutex_free,
        "target_dir": target_dir,
        "target_folder_listing": listing,
    })
}

/// Listing of a target folder: exists, is_empty, entries (names only).
pub fn target_folder_listing(path: &str) -> Value {
    let dir = std::path::Path::new(path);
    if !dir.exists() {
        return json!({ "exists": false, "is_empty": true, "entries": [] });
    }
    let mut entries: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            entries.push(e.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    let is_empty = entries.is_empty();
    json!({ "exists": true, "is_empty": is_empty, "entries": entries })
}
