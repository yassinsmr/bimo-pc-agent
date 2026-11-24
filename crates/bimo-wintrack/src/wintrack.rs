//! Window-event tracker: `SetWinEventHook` + an internal watchdog
//! that re-registers the hook if it dies or goes silent.
//!
//! Design (spec `track-a-unit2-eye-window-spike.md` §2):
//! - one hook thread (Windows message pump) + one watchdog thread
//!   (5 s tick: no event for 10 s while the process list changed,
//!   or the hook killed outright → re-register + `hook.recovered`).
//! - the hook callback runs on the installing thread (out-of-context)
//!   and forwards events through a static channel sender —
//!   `SetWinEventHook` callbacks carry no user data.
//! - proc-link: every event carries exe + PID from
//!   `GetWindowThreadProcessId` + `Toolhelp32Snapshot`.
//! - no window titles anywhere: this crate never calls
//!   `GetWindowText`, so Check 4 can prove it from the log alone.

use crate::WinEvent;
#[cfg(windows)]
use crate::WinEventKind;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
#[cfg(windows)]
use std::time::Duration;
use std::time::Instant;

/// True on platforms where the tracker can actually hook windows.
pub fn tracker_supported() -> bool {
    cfg!(windows)
}

/// The tracker handle. Dropping it does NOT stop the threads — call
/// `stop()` explicitly so the watchdog + pump join cleanly.
pub struct WinTrack {
    shared: Arc<Shared>,
    pump: Option<JoinHandle<()>>,
    watchdog: Option<JoinHandle<()>>,
}

struct Shared {
    tx: Sender<WinEvent>,
    stop: AtomicBool,
    hook: Mutex<HookHandle>,
    reinstall_requested: AtomicBool,
    reinstall_reason: Mutex<String>,
    dead_since: Mutex<Option<Instant>>,
    hook_dead: AtomicBool,
    last_event: Mutex<Instant>,
    last_pids: Mutex<HashSet<u32>>,
}

/// The hook handle, kept as a raw integer so the struct stays `Send`
/// on every target (the `windows` handle types are not guaranteed
/// `Send` on non-Windows builds, and this field is only used under
/// `cfg(windows)` anyway).
#[derive(Clone, Copy, Default)]
struct HookHandle(usize);

static CALLBACK_SHARED: OnceLock<Arc<Shared>> = OnceLock::new();

impl WinTrack {
    /// Start the hook + watchdog threads. Events flow to `tx`.
    /// On non-Windows this returns `Err` (the binary turns that into
    /// a "skipped" fragment, not a failure).
    pub fn start(tx: Sender<WinEvent>) -> Result<WinTrack, String> {
        #[cfg(not(windows))]
        {
            let _ = tx;
            return Err("window tracking is Windows-only".to_string());
        }
        #[cfg(windows)]
        {
            let shared = Arc::new(Shared {
                tx,
                stop: AtomicBool::new(false),
                hook: Mutex::new(HookHandle::default()),
                reinstall_requested: AtomicBool::new(false),
                reinstall_reason: Mutex::new(String::new()),
                dead_since: Mutex::new(None),
                hook_dead: AtomicBool::new(false),
                last_event: Mutex::new(Instant::now()),
                last_pids: Mutex::new(list_pids()),
            });
            let _ = CALLBACK_SHARED.set(shared.clone());
            let pump_shared = shared.clone();
            let pump = std::thread::spawn(move || pump_loop(pump_shared));
            let wd_shared = shared.clone();
            let watchdog = std::thread::spawn(move || watchdog_loop(wd_shared));
            Ok(WinTrack {
                shared,
                pump: Some(pump),
                watchdog: Some(watchdog),
            })
        }
    }

    /// Test seam for Check 3: kill the hook outright (unhook + mark
    /// dead). The watchdog must notice within one 5 s tick and the
    /// pump thread must re-register it; events must flow again in
    /// under 10 s. Returns the instant the hook died.
    pub fn kill_hook_for_test(&self) -> Instant {
        let now = Instant::now();
        *self.shared.dead_since.lock().unwrap() = Some(now);
        self.shared.hook_dead.store(true, Ordering::SeqCst);
        #[cfg(windows)]
        {
            let handle = self.shared.hook.lock().unwrap().0;
            if handle != 0 {
                unsafe {
                    use windows::Win32::UI::Accessibility::UnhookWinEvent;
                    let _ = UnhookWinEvent(windows::Win32::UI::Accessibility::HWINEVENTHOOK(
                        handle as *mut core::ffi::c_void,
                    ));
                }
                self.shared.hook.lock().unwrap().0 = 0;
            }
        }
        now
    }

    /// Stop the pump + watchdog threads and join them.
    pub fn stop(mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.pump.take() {
            let _ = h.join();
        }
        if let Some(h) = self.watchdog.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------- Windows
#[cfg(windows)]
mod win {
    use super::*;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::UI::Accessibility::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    pub unsafe extern "system" fn hook_callback(
        _hook: HWINEVENTHOOK,
        event: u32,
        hwnd: HWND,
        id_object: i32,
        id_child: i32,
        _thread: u32,
        _time: u32,
    ) {
        // Top-level windows only (not child controls).
        if id_object != 0 || id_child != 0 {
            return;
        }
        let kind = match event {
            EVENT_OBJECT_CREATE => WinEventKind::AppOpen,
            EVENT_OBJECT_DESTROY => WinEventKind::AppClose,
            EVENT_SYSTEM_FOREGROUND => WinEventKind::AppFocus,
            _ => return,
        };
        let Some(shared) = CALLBACK_SHARED.get() else {
            return;
        };
        if shared.hook_dead.load(Ordering::SeqCst) {
            return;
        }
        let mut pid: u32 = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut u32));
        }
        if pid == 0 {
            return;
        }
        let exe = exe_for_pid(pid).unwrap_or_else(|| "unknown.exe".to_string());
        *shared.last_event.lock().unwrap() = Instant::now();
        let ev = WinEvent {
            kind,
            pid,
            exe,
            hwnd: hwnd.0 as u64,
            after_ms: None,
            reason: None,
        };
        let _ = shared.tx.send(ev);
    }

    pub fn install_hook() -> Result<HookHandle, String> {
        unsafe {
            let hook = SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND,
                EVENT_OBJECT_DESTROY,
                None,
                Some(hook_callback),
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            );
            if hook.is_invalid() {
                return Err("SetWinEventHook returned an invalid hook".to_string());
            }
            Ok(HookHandle(hook.0 as usize))
        }
    }

    pub fn unhook(handle: HookHandle) {
        if handle.0 == 0 {
            return;
        }
        unsafe {
            let _ = UnhookWinEvent(HWINEVENTHOOK(handle.0 as *mut core::ffi::c_void));
        }
    }

    pub fn pump_messages(shared: &Arc<Shared>) {
        unsafe {
            let mut msg = MSG::default();
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        let _ = shared;
    }

    /// Look up an exe basename for a pid. Retries once after 100 ms:
    /// a window event can arrive in the same instant its process is
    /// still registering, and a single failed lookup must not turn a
    /// real event into "unknown.exe".
    pub fn exe_for_pid(pid: u32) -> Option<String> {
        for _ in 0..2 {
            if let Some(exe) = lookup_exe(pid) {
                return Some(exe);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }

    fn lookup_exe(pid: u32) -> Option<String> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let mut entry = PROCESSENTRY32W::default();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found = None;
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let end = entry
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExeFile.len());
                        found = Some(String::from_utf16_lossy(&entry.szExeFile[..end]));
                        break;
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snapshot);
            found
        }
    }
}

#[cfg(windows)]
fn pump_loop(shared: Arc<Shared>) {
    // Install on this thread: out-of-context callbacks are delivered
    // to the installing thread's message queue.
    match win::install_hook() {
        Ok(h) => *shared.hook.lock().unwrap() = h,
        Err(e) => {
            eprintln!("[wintrack] hook install failed: {}", e);
            return;
        }
    }
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        if shared.reinstall_requested.load(Ordering::SeqCst) {
            shared.reinstall_requested.store(false, Ordering::SeqCst);
            let reason = shared.reinstall_reason.lock().unwrap().clone();
            let since = *shared.dead_since.lock().unwrap();
            win::unhook(*shared.hook.lock().unwrap());
            match win::install_hook() {
                Ok(h) => {
                    *shared.hook.lock().unwrap() = h;
                    shared.hook_dead.store(false, Ordering::SeqCst);
                    *shared.last_event.lock().unwrap() = Instant::now();
                    let after_ms = since.map(|t| t.elapsed().as_millis() as u64);
                    *shared.dead_since.lock().unwrap() = None;
                    let ev = WinEvent {
                        kind: WinEventKind::HookRecovered,
                        pid: 0,
                        exe: String::new(),
                        hwnd: 0,
                        after_ms,
                        reason: Some(reason),
                    };
                    let _ = shared.tx.send(ev);
                }
                Err(e) => {
                    eprintln!("[wintrack] hook re-install failed: {}", e);
                    // Leave the flag set: the watchdog asks again next tick.
                    shared.reinstall_requested.store(true, Ordering::SeqCst);
                }
            }
        }
        win::pump_messages(&shared);
        std::thread::sleep(Duration::from_millis(50));
    }
    win::unhook(*shared.hook.lock().unwrap());
}

#[cfg(windows)]
fn watchdog_loop(shared: Arc<Shared>) {
    loop {
        for _ in 0..25 {
            if shared.stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        // One 5 s tick.
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        if shared.hook_dead.load(Ordering::SeqCst) {
            *shared.reinstall_reason.lock().unwrap() = "hook-killed".to_string();
            shared.reinstall_requested.store(true, Ordering::SeqCst);
            continue;
        }
        let current = list_pids();
        let mut last = shared.last_pids.lock().unwrap();
        let changed = *last != current;
        *last = current;
        drop(last);
        let silent_for = shared.last_event.lock().unwrap().elapsed();
        if changed && silent_for >= Duration::from_secs(10) {
            if shared.dead_since.lock().unwrap().is_none() {
                *shared.dead_since.lock().unwrap() = Some(Instant::now() - silent_for);
            }
            *shared.reinstall_reason.lock().unwrap() =
                "silence-10s-procs-changed".to_string();
            shared.reinstall_requested.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(windows)]
fn list_pids() -> HashSet<u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = HashSet::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                out.insert(entry.th32ProcessID);
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

// ---------------------------------------------------------------- non-Windows
#[cfg(not(windows))]
fn pump_loop(_shared: Arc<Shared>) {}

#[cfg(not(windows))]
fn watchdog_loop(_shared: Arc<Shared>) {}

#[cfg(not(windows))]
fn list_pids() -> HashSet<u32> {
    HashSet::new()
}

/// Re-verify one event's proc-link from outside the tracker
/// (Check 2): does this pid still resolve to this exe?
pub fn verify_proc_link(pid: u32, exe: &str) -> bool {
    #[cfg(windows)]
    {
        match win::exe_for_pid(pid) {
            Some(found) => found.eq_ignore_ascii_case(exe),
            None => false,
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (pid, exe);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_reports_unsupported_off_windows() {
        // On this Linux dev machine the tracker must say so plainly
        // instead of pretending to work.
        assert_eq!(tracker_supported(), cfg!(windows));
    }
}
