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
//! (MsiEnumProductsW + MsiGetProductInfoW "ProductName") for VLC,
//! and removal uses MsiConfigureProductW(..., INSTALLSTATE_ABSENT).

use crate::win32::wide;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub type UiHandler = extern "system" fn(*mut std::ffi::c_void, u32, *const u16, *const u16) -> i32;

static CANCEL_REQUESTED: AtomicBool = AtomicBool::new(false);
static HANDLER_CALLS: AtomicU64 = AtomicU64::new(0);

// INSTALLMESSAGE_* return values: IDOK = 1 (continue), IDCANCEL = 2.
extern "system" fn ui_handler(
  _ctx: *mut std::ffi::c_void,
  _msg_type: u32,
  _msg: *const u16,
  _extra: *const u16,
) -> i32 {
  HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
  if CANCEL_REQUESTED.load(Ordering::SeqCst) {
    2
  } else {
    1
  }
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
}

pub const ERROR_INSTALL_USEREXIT: u32 = 1602;
pub const INSTALLSTATE_ABSENT: i32 = 2;

fn wide_string(buf: &[u16]) -> String {
  let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
  String::from_utf16_lossy(&buf[..end])
}

pub struct CancelOutcome {
  pub return_code: u32,
  pub cancel_ms: u64,
  pub total_ms: u64,
  pub handler_calls: u64,
  pub cancelled: bool,
}

/// Install `msi_path` via the API; a timer thread sets the cancel
/// flag after `cancel_after_ms`, and the UI handler then returns
/// IDCANCEL. `cancel_ms` is the time from the flag being set until
/// MsiInstallProduct returns.
pub fn install_with_cancel(msi_path: &str, cancel_after_ms: u64) -> CancelOutcome {
  CANCEL_REQUESTED.store(false, Ordering::SeqCst);
  HANDLER_CALLS.store(0, Ordering::SeqCst);
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
    handler_calls: HANDLER_CALLS.load(Ordering::SeqCst),
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

/// (product code, product name) of the installed VLC product, if any.
pub fn find_vlc_product() -> Option<(String, String)> {
  for i in 0..1024u32 {
    let mut buf = vec![0u16; 39];
    let rc = unsafe { MsiEnumProductsW(i, buf.as_mut_ptr()) };
    if rc != 0 {
      break;
    }
    let code = wide_string(&buf);
    if let Some(name) = product_name(&code) {
      if name.to_ascii_lowercase().contains("vlc") {
        return Some((code, name));
      }
    }
  }
  None
}

pub fn product_state(code: &str) -> i32 {
  let c = wide(code);
  unsafe { MsiQueryProductStateW(c.as_ptr()) }
}

pub fn uninstall_product(code: &str) -> u32 {
  let c = wide(code);
  unsafe { MsiConfigureProductW(c.as_ptr(), 0, INSTALLSTATE_ABSENT) }
}

/// Current VLC presence: {"present": bool, "product_code", "product_name", "product_state"}.
pub fn vlc_presence() -> Value {
  match find_vlc_product() {
    None => json!({ "present": false, "product_code": null, "product_name": null, "product_state": null }),
    Some((code, name)) => {
      let state = product_state(&code);
      json!({ "present": true, "product_code": code, "product_name": name, "product_state": state })
    }
  }
}

/// Poll until VLC is absent (uninstalling it if present), up to
/// `timeout_ms`. Returns {product_absent, waited_ms,
/// uninstall_return_code, product_state, ...}.
pub fn ensure_vlc_absent(timeout_ms: u64) -> Value {
  let start = Instant::now();
  let mut uninstall_rc: Option<u32> = None;
  loop {
    match find_vlc_product() {
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
