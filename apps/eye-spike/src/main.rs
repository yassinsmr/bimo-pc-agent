//! eye-spike — proof spike for Track A Unit 2 (the Eye), council condition 2.
//!
//! Four independent checks, one process invocation each, so a hang or
//! failure in one cannot block the others. Each invocation writes one
//! fragment `spike-<check>.json`; `--merge` combines the fragments plus
//! the Defender before/after files into `spike-results.json`.
//!
//! Usage (on real Windows):
//!   eye-spike --check gcap        # Graphics Capture, primary monitor, no picker
//!   eye-spike --check dxgi        # DXGI Desktop Duplication fallback, one frame
//!   eye-spike --check fullscreen  # borderless fullscreen window, then capture it
//!   eye-spike --check hook        # SetWinEventHook while Notepad opens/closes
//!   eye-spike --merge             # combine fragments -> spike-results.json
//!
//! Honest limits (recorded in the JSON, not hidden):
//! - The "fullscreen" check uses a borderless fullscreen window, NOT a real
//!   exclusive-fullscreen game: no game exists on the CI runner. The real
//!   fullscreen-game capture is decided on the Legion (second gate).
//! - Graphics Capture / DXGI may fail on a headless runner with no real
//!   display. A failure there is recorded as such, not as a design failure.
//! - Defender comparison is done by the workflow (PowerShell before/after);
//!   this binary only proves the hook itself installs and fires.

use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn write_fragment(name: &str, status: &str, details: &str) {
    let path = format!("spike-{}.json", name);
    let body = format!(
        "{{\"check\":\"{}\",\"status\":\"{}\",\"ts_unix\":{},\"details\":{}}}",
        json_escape(name),
        status,
        now_unix(),
        details
    );
    match fs::write(&path, &body) {
        Ok(()) => eprintln!("[spike] wrote {}", path),
        Err(e) => eprintln!("[spike] FAILED to write {}: {}", path, e),
    }
}

fn fail(name: &str, err: &str) -> i32 {
    eprintln!("[spike] check {} FAILED: {}", name, err);
    write_fragment(
        name,
        "fail",
        &format!("{{\"error\":\"{}\"}}", json_escape(err)),
    );
    1
}

#[cfg(not(windows))]
fn main() {
    eprintln!("[spike] eye-spike only runs on Windows (this is a non-Windows build)");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    std::process::exit(real_main());
}

#[cfg(windows)]
fn real_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();
    let get = |flag: &str| -> Option<String> {
        args.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].clone())
    };
    if args.iter().any(|a| a == "--merge") {
        return merge();
    }
    let check = match get("--check") {
        Some(c) => c,
        None => {
            eprintln!("usage: eye-spike --check <gcap|dxgi|fullscreen|hook> | --merge");
            return 2;
        }
    };
    match check.as_str() {
        "gcap" => check_gcap("spike-gcap.png"),
        "dxgi" => check_dxgi("spike-dxgi.png"),
        "fullscreen" => check_fullscreen("spike-fullscreen.png"),
        "hook" => check_hook(),
        other => {
            eprintln!("[spike] unknown check: {}", other);
            2
        }
    }
}

// ---------------------------------------------------------------- Graphics Capture
#[cfg(windows)]
mod gcap {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_capture::capture::{Context, GraphicsCaptureApiHandler};
    use windows_capture::encoder::ImageFormat;
    use windows_capture::frame::Frame;
    use windows_capture::graphics_capture_api::InternalCaptureControl;
    use windows_capture::monitor::Monitor;
    use windows_capture::settings::{
        ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
        MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
    };

    pub static FRAME_SAVED: AtomicBool = AtomicBool::new(false);

    pub struct OneShot {
        out_path: String,
        start: Instant,
        width: u32,
        height: u32,
    }

    impl GraphicsCaptureApiHandler for OneShot {
        type Flags = String;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
            Ok(Self {
                out_path: ctx.flags,
                start: Instant::now(),
                width: 0,
                height: 0,
            })
        }

        fn on_frame_arrived(
            &mut self,
            frame: &mut Frame,
            capture_control: InternalCaptureControl,
        ) -> Result<(), Self::Error> {
            if !FRAME_SAVED.load(Ordering::SeqCst) {
                self.width = frame.width();
                self.height = frame.height();
                frame.save_as_image(&self.out_path, ImageFormat::Png)?;
                FRAME_SAVED.store(true, Ordering::SeqCst);
                eprintln!(
                    "[spike] gcap first frame {}x{} in {:?}",
                    self.width,
                    self.height,
                    self.start.elapsed()
                );
            }
            capture_control.stop();
            Ok(())
        }

        fn on_closed(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Capture one frame from the primary monitor with NO picker.
    /// Returns (width, height, elapsed_ms, bytes) on success.
    pub fn capture_once(out_path: &str) -> Result<(u32, u32, u128, u64), String> {
        let monitor = Monitor::primary().map_err(|e| format!("Monitor::primary: {}", e))?;
        let mw = monitor.width().map_err(|e| format!("monitor width: {}", e))?;
        let mh = monitor.height().map_err(|e| format!("monitor height: {}", e))?;
        let t0 = Instant::now();

        // Watchdog: if no frame arrives in 20 s, fail loudly instead of
        // hanging the workflow (a headless runner may never deliver one).
        let out = out_path.to_string();
        let watchdog_out = out.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(20));
            if !FRAME_SAVED.load(Ordering::SeqCst) {
                eprintln!("[spike] watchdog: no Graphics Capture frame in 20s");
                write_fragment(
                    "gcap-timeout",
                    "fail",
                    &format!(
                        "{{\"error\":\"no frame within 20s (headless runner?)\",\"out\":\"{}\"}}",
                        json_escape(&watchdog_out)
                    ),
                );
                std::process::exit(1);
            }
        });

        let settings = Settings::new(
            monitor,
            CursorCaptureSettings::Default,
            DrawBorderSettings::Default,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Default,
            DirtyRegionSettings::Default,
            ColorFormat::Rgba8,
            out,
        );
        OneShot::start(settings).map_err(|e| format!("GraphicsCapture start: {}", e))?;
        let elapsed = t0.elapsed().as_millis();
        let bytes = fs::metadata(out_path)
            .map(|m| m.len())
            .unwrap_or(0);
        Ok((mw, mh, elapsed, bytes))
    }
}

#[cfg(windows)]
fn check_gcap(out: &str) -> i32 {
    match gcap::capture_once(out) {
        Ok((w, h, ms, bytes)) => {
            eprintln!("[spike] gcap OK: {}x{} in {}ms, {} bytes", w, h, ms, bytes);
            write_fragment(
                "gcap",
                "pass",
                &format!(
                    "{{\"picker\":false,\"width\":{},\"height\":{},\"first_frame_ms\":{},\"file\":\"{}\",\"bytes\":{},\"note\":\"Graphics Capture from primary monitor without picker\"}}",
                    w, h, ms, json_escape(out), bytes
                ),
            );
            0
        }
        Err(e) => fail("gcap", &e),
    }
}

// ---------------------------------------------------------------- DXGI Duplication
#[cfg(windows)]
fn check_dxgi(out: &str) -> i32 {
    use windows_capture::dxgi_duplication_api::DxgiDuplicationApi;
    use windows_capture::encoder::ImageFormat;
    use windows_capture::monitor::Monitor;

    let t0 = Instant::now();
    let result: Result<(u32, u32, u64), String> = (|| {
        let monitor = Monitor::primary().map_err(|e| format!("Monitor::primary: {}", e))?;
        let mut dup = DxgiDuplicationApi::new(monitor)
            .map_err(|e| format!("DxgiDuplicationApi::new: {}", e))?;
        let mut last_err = String::new();
        for attempt in 1..=5 {
            match dup.acquire_next_frame(1000) {
                Ok(mut frame) => {
                    let w = frame.width();
                    let h = frame.height();
                    frame
                        .save_as_image(out, ImageFormat::Png)
                        .map_err(|e| format!("save_as_image: {}", e))?;
                    let bytes = fs::metadata(out).map(|m| m.len()).unwrap_or(0);
                    return Ok((w, h, bytes));
                }
                Err(e) => {
                    last_err = format!("{}", e);
                    eprintln!("[spike] dxgi attempt {}: {}", attempt, last_err);
                }
            }
        }
        Err(format!(
            "acquire_next_frame timed out 5x (headless runner?): {}",
            last_err
        ))
    })();
    match result {
        Ok((w, h, bytes)) => {
            let ms = t0.elapsed().as_millis();
            eprintln!("[spike] dxgi OK: {}x{} in {}ms, {} bytes", w, h, ms, bytes);
            write_fragment(
                "dxgi",
                "pass",
                &format!(
                    "{{\"width\":{},\"height\":{},\"elapsed_ms\":{},\"file\":\"{}\",\"bytes\":{},\"note\":\"DXGI Desktop Duplication fallback, one frame\"}}",
                    w, h, ms, json_escape(out), bytes
                ),
            );
            0
        }
        Err(e) => fail("dxgi", &e),
    }
}

// ---------------------------------------------------------------- Fullscreen window
#[cfg(windows)]
unsafe extern "system" fn spike_wndproc(
    hwnd: windows::Win32::Foundation::HWND,
    msg: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam)
}

#[cfg(windows)]
fn check_fullscreen(out: &str) -> i32 {
    use windows::core::w;
    use windows::Win32::Foundation::{HINSTANCE, COLORREF};
    use windows::Win32::Graphics::Gdi::CreateSolidBrush;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::*;

    let result: Result<(), String> = (|| {
        unsafe {
            let hinstance = GetModuleHandleW(None)
                .map_err(|e| format!("GetModuleHandleW: {}", e))?;
            let class_name = w!("BimoEyeSpike");
            // Vivid orange so the capture is unmistakably the fullscreen window.
            let brush = CreateSolidBrush(COLORREF(0x001478FF));
            let wc = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(spike_wndproc),
                hInstance: HINSTANCE(hinstance.0),
                hCursor: LoadCursorW(None, IDC_ARROW)
                    .map_err(|e| format!("LoadCursorW: {}", e))?,
                hbrBackground: brush,
                lpszClassName: class_name,
                ..Default::default()
            };
            if RegisterClassW(&wc) == 0 {
                return Err("RegisterClassW failed".to_string());
            }
            let cx = GetSystemMetrics(SM_CXSCREEN);
            let cy = GetSystemMetrics(SM_CYSCREEN);
            let hwnd = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name,
                w!("bimo-eye-spike"),
                WS_POPUP | WS_VISIBLE,
                0,
                0,
                cx,
                cy,
                None,
                None,
                Some(HINSTANCE(hinstance.0)),
                None,
            )
            .map_err(|e| format!("CreateWindowExW: {}", e))?;
            let _ = ShowWindow(hwnd, SW_SHOWMAXIMIZED);
            let _ = SetForegroundWindow(hwnd);
            std::thread::sleep(Duration::from_millis(1000));
            eprintln!("[spike] fullscreen window {}x{} shown", cx, cy);
            let r = gcap::capture_once(out);
            let _ = DestroyWindow(hwnd);
            let _ = UnregisterClassW(class_name, Some(HINSTANCE(hinstance.0)));
            r.map(|_| ())
        }
    })();
    match result {
        Ok(()) => {
            let bytes = fs::metadata(out).map(|m| m.len()).unwrap_or(0);
            eprintln!("[spike] fullscreen OK: {} bytes", bytes);
            write_fragment(
                "fullscreen",
                "pass",
                &format!(
                    "{{\"file\":\"{}\",\"bytes\":{},\"note\":\"borderless fullscreen window captured via Graphics Capture (no picker). NOT a real exclusive-fullscreen game — no game exists on the runner; real-game capture is decided on the Legion\"}}",
                    json_escape(out), bytes
                ),
            );
            0
        }
        Err(e) => fail("fullscreen", &e),
    }
}

// ---------------------------------------------------------------- WinEvent hook
#[cfg(windows)]
fn check_hook() -> i32 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Accessibility::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    static EVENTS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn hook_proc(
        _hook: HWINEVENTHOOK,
        event: u32,
        _hwnd: HWND,
        _id_object: i32,
        _id_child: i32,
        _thread: u32,
        _time: u32,
    ) {
        if event == EVENT_SYSTEM_FOREGROUND {
            EVENTS.fetch_add(1, Ordering::SeqCst);
        }
    }

    let result: Result<usize, String> = (|| {
        unsafe {
            let hook = SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND,
                EVENT_SYSTEM_FOREGROUND,
                None,
                Some(hook_proc),
                0,
                0,
                WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS,
            );
            if hook.is_invalid() {
                return Err("SetWinEventHook returned invalid hook".to_string());
            }
            eprintln!("[spike] hook installed, opening Notepad");
            let mut child = std::process::Command::new("notepad.exe")
                .spawn()
                .map_err(|e| format!("spawn notepad: {}", e))?;
            // Pump messages so out-of-context events are delivered.
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut msg = MSG::default();
            while Instant::now() < deadline {
                while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                    let _ = TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
            let n = EVENTS.load(Ordering::SeqCst);
            let _ = UnhookWinEvent(hook);
            eprintln!("[spike] hook saw {} foreground events", n);
            Ok(n)
        }
    })();
    match result {
        Ok(n) => {
            // Notepad opening must produce at least one foreground event;
            // zero events means the hook is installed but blind.
            if n == 0 {
                return fail(
                    "hook",
                    "hook installed but saw 0 foreground events (blind on this host)",
                );
            }
            write_fragment(
                "hook",
                "pass",
                &format!(
                    "{{\"foreground_events\":{},\"note\":\"SetWinEventHook (out-of-context) fired on Notepad open; Defender comparison is in defender-before/after.json\"}}",
                    n
                ),
            );
            0
        }
        Err(e) => fail("hook", &e),
    }
}

// ---------------------------------------------------------------- Merge
#[cfg(windows)]
fn merge() -> i32 {
    let mut checks: Vec<(String, String)> = Vec::new();
    let wanted = ["gcap", "dxgi", "fullscreen", "hook"];
    let mut missing: Vec<&str> = Vec::new();
    let mut all_pass = true;
    for name in wanted {
        let path = format!("spike-{}.json", name);
        match fs::read_to_string(&path) {
            Ok(content) => {
                let pass = content.contains("\"status\":\"pass\"");
                if !pass {
                    all_pass = false;
                }
                checks.push((name.to_string(), content.trim().to_string()));
            }
            Err(_) => {
                missing.push(name);
                all_pass = false;
            }
        }
    }

    // Defender: workflow writes defender-before.json / defender-after.json.
    let defender_note;
    let mut defender_ok = true;
    let before = fs::read_to_string("defender-before.json").ok();
    let after = fs::read_to_string("defender-after.json").ok();
    match (before, after) {
        (Some(b), Some(a)) => {
            let count = |s: &str| -> Option<i64> {
                s.split("\"detections\":")
                    .nth(1)?
                    .split(|c: char| !c.is_ascii_digit() && c != '-')
                    .find(|p| !p.is_empty())?
                    .parse()
                    .ok()
            };
            match (count(&b), count(&a)) {
                (Some(bc), Some(ac)) => {
                    defender_ok = ac <= bc;
                    defender_note = format!(
                        "Defender detections before={} after={} (new={})",
                        bc,
                        ac,
                        ac - bc
                    );
                }
                _ => {
                    defender_note =
                        "Defender JSON present but detections count unparsable".to_string();
                }
            }
        }
        _ => {
            defender_note =
                "Defender before/after files missing — Defender verdict unknown".to_string();
        }
    }
    if !defender_ok {
        all_pass = false;
    }

    let verdict = if all_pass { "pass" } else { "fail" };
    let mut body = String::from("{\"spike\":\"eye-spike\",\"verdict\":\"");
    body.push_str(verdict);
    body.push_str("\",\"ts_unix\":");
    body.push_str(&now_unix().to_string());
    body.push_str(",\"checks\":{");
    for (i, (name, content)) in checks.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!("\"{}\":{}", json_escape(name), content));
    }
    body.push_str("},\"missing\":[");
    for (i, m) in missing.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!("\"{}\"", m));
    }
    body.push_str("],\"defender\":\"");
    body.push_str(&json_escape(&defender_note));
    body.push_str("\",\"honest_limits\":\"fullscreen check is a borderless window, not a real exclusive-fullscreen game; real-game capture is decided on the Legion\"}");
    match fs::write("spike-results.json", &body) {
        Ok(()) => {
            eprintln!("[spike] merge verdict: {} — {}", verdict, defender_note);
            if all_pass {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("[spike] merge failed to write spike-results.json: {}", e);
            1
        }
    }
}
