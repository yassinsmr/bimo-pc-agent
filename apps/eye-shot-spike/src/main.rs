//! eye-shot-spike — proof spike for Track A Unit 2 (the Eye), shots.
//!
//! Design doc: `hidden_files/dev/track-a-unit2-eye-shot-spike.md`
//! (council condition 2 on Unit 2: a spike gate before the full build).
//!
//! Four independent checks, one process invocation each, so a hang or
//! failure in one cannot block the others. Each invocation writes one
//! fragment `shotspike-<check>.json`; `--merge` combines the fragments
//! into `shot-spike-results.json`.
//!
//! Usage (on real Windows):
//!   eye-shot-spike --check capture-works  # one frame, no picker -> JPEG + trial JSONL event
//!   eye-shot-spike --check one-frame-stop # session stops after exactly one frame
//!   eye-shot-spike --check shot-cost      # process CPU during one shot < 5% (council 11)
//!   eye-shot-spike --check dxgi-fallback  # DXGI fallback, only if Graphics Capture failed
//!   eye-shot-spike --merge                # combine fragments -> shot-spike-results.json
//!
//! Honest limits (recorded in the JSON, not hidden):
//! - windows-capture 2.0.1 exposes NO JPEG quality setting and NO resize:
//!   `save_as_image(path, ImageFormat::Jpeg)` encodes at the WIC default
//!   quality, full monitor size. The design doc's "JPEG quality 80, max
//!   width 1920" is therefore NOT proven by this spike: the file is a
//!   valid JPEG at default quality, and the fragment records the real
//!   width plus `max_width_1920` (false when the monitor is wider).
//!   Quality-80 + downscale belong to the eye unit itself (BitmapEncoder
//!   with ImageQuality), and the council decides on that gap.
//! - The runner has no real display and no game: a no-frame timeout is
//!   recorded with `"no_screen": true` and the verdict is a deferral to
//!   the Legion, not a design failure. Capture over a real exclusive
//!   fullscreen game is NOT tested here (second gate, on arrival).
//! - The trial JSONL (`shotspike-events.jsonl`) is PLAINTEXT and uses the
//!   core's chain rule (`hash = sha256(prev_hash + canonical_json)`,
//!   sorted keys, `schema: 1`, GENESIS start) — but the real unit's
//!   writer encrypts with DPAPI and verifies with `verify_file`. This
//!   spike proves the event shape and the chain math, not the crypto.

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
    let path = format!("shotspike-{}.json", name);
    let body = format!(
        "{{\"check\":\"{}\",\"status\":\"{}\",\"ts_unix\":{},\"details\":{}}}",
        json_escape(name),
        status,
        now_unix(),
        details
    );
    match fs::write(&path, &body) {
        Ok(()) => eprintln!("[shotspike] wrote {}", path),
        Err(e) => eprintln!("[shotspike] FAILED to write {}: {}", path, e),
    }
}

fn fail(name: &str, err: &str) -> i32 {
    eprintln!("[shotspike] check {} FAILED: {}", name, err);
    write_fragment(
        name,
        "fail",
        &format!("{{\"error\":\"{}\"}}", json_escape(err)),
    );
    1
}

/// Same verdict shape as the eye-spike: a no-frame timeout on a headless
/// runner is a deferral to the Legion, recorded explicitly — not a silent
/// design failure. The fragment still says "fail" so CI goes red and a
/// human reads the JSON; the `no_screen` flag says why.
fn fail_no_screen(name: &str, err: &str) -> i32 {
    eprintln!("[shotspike] check {} FAILED (no screen): {}", name, err);
    write_fragment(
        name,
        "fail",
        &format!(
            "{{\"error\":\"{}\",\"no_screen\":true,\"note\":\"no frame within 20s — headless runner? Verdict deferred to the Legion, not a design failure\"}}",
            json_escape(err)
        ),
    );
    1
}

#[cfg(not(windows))]
fn main() {
    eprintln!("[shotspike] eye-shot-spike only runs on Windows (this is a non-Windows build)");
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
            eprintln!("usage: eye-shot-spike --check <capture-works|one-frame-stop|shot-cost|dxgi-fallback> | --merge");
            return 2;
        }
    };
    match check.as_str() {
        "capture-works" => check_capture_works("shotspike-shot.jpg"),
        "one-frame-stop" => check_one_frame_stop("shotspike-stop.jpg"),
        "shot-cost" => check_shot_cost("shotspike-cost.jpg"),
        "dxgi-fallback" => check_dxgi_fallback("shotspike-shot-dxgi.jpg"),
        other => {
            eprintln!("[shotspike] unknown check: {}", other);
            2
        }
    }
}

// ---------------------------------------------------------------- Capture core
#[cfg(windows)]
mod capture {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    pub static FRAMES_SEEN: AtomicUsize = AtomicUsize::new(0);

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
            FRAMES_SEEN.fetch_add(1, Ordering::SeqCst);
            if !FRAME_SAVED.load(Ordering::SeqCst) {
                self.width = frame.width();
                self.height = frame.height();
                frame.save_as_image(&self.out_path, ImageFormat::Jpeg)?;
                FRAME_SAVED.store(true, Ordering::SeqCst);
                eprintln!(
                    "[shotspike] first frame {}x{} in {:?}",
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

    /// Capture one frame from the primary monitor with NO picker and save
    /// it as JPEG. Returns (width, height, elapsed_ms, bytes).
    /// A 20 s watchdog fails loudly instead of hanging the workflow when
    /// the runner never delivers a frame (headless host).
    pub fn capture_once(out_path: &str, check_name: &str) -> Result<(u32, u32, u128, u64), String> {
        let monitor = Monitor::primary().map_err(|e| format!("Monitor::primary: {}", e))?;
        let mw = monitor.width().map_err(|e| format!("monitor width: {}", e))?;
        let mh = monitor.height().map_err(|e| format!("monitor height: {}", e))?;
        let t0 = Instant::now();

        let out = out_path.to_string();
        let watchdog_out = out.clone();
        let watchdog_check = check_name.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(20));
            if !FRAME_SAVED.load(Ordering::SeqCst) {
                eprintln!("[shotspike] watchdog: no Graphics Capture frame in 20s");
                write_fragment(
                    &format!("{}-timeout", watchdog_check),
                    "fail",
                    &format!(
                        "{{\"error\":\"no frame within 20s (headless runner?)\",\"no_screen\":true,\"out\":\"{}\"}}",
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
        let bytes = fs::metadata(out_path).map(|m| m.len()).unwrap_or(0);
        Ok((mw, mh, elapsed, bytes))
    }
}

// ---------------------------------------------------------------- Trial JSONL event
#[cfg(windows)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Append one `shot.taken` event to the trial JSONL, using the eye core's
/// chain rule: `hash = sha256(prev_hash + canonical_json_without_hash)`,
/// canonical JSON with sorted keys, `schema: 1`, GENESIS for seq 0.
/// Plaintext trial only — the real unit encrypts with DPAPI.
#[cfg(windows)]
fn append_trial_event(file: &str, width: u32, height: u32) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;

    let ts = now_unix();
    // Keys already in sorted order: event, file, height, schema, seq, ts, width.
    let canonical = format!(
        "{{\"event\":\"shot.taken\",\"file\":\"{}\",\"height\":{},\"schema\":1,\"seq\":0,\"ts\":{},\"width\":{}}}",
        json_escape(file),
        height,
        ts,
        width
    );
    let prev_hash = "GENESIS";
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    let hash = hex_encode(&hasher.finalize());
    let line = format!(
        "{{\"event\":\"shot.taken\",\"file\":\"{}\",\"hash\":\"{}\",\"height\":{},\"prev_hash\":\"{}\",\"schema\":1,\"seq\":0,\"ts\":{},\"width\":{}}}",
        json_escape(file),
        hash,
        height,
        prev_hash,
        ts,
        width
    );
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("shotspike-events.jsonl")
        .map_err(|e| format!("open trial JSONL: {}", e))?;
    writeln!(f, "{}", line).map_err(|e| format!("write trial JSONL: {}", e))?;
    Ok(hash)
}

// ---------------------------------------------------------------- Check 1: capture-works
#[cfg(windows)]
fn check_capture_works(out: &str) -> i32 {
    match capture::capture_once(out, "capture-works") {
        Ok((w, h, ms, bytes)) => {
            let hash = match append_trial_event(out, w, h) {
                Ok(h) => h,
                Err(e) => return fail("capture-works", &e),
            };
            eprintln!(
                "[shotspike] capture-works OK: {}x{} in {}ms, {} bytes, event hash {}",
                w, h, ms, bytes, &hash[..12]
            );
            // JPEG quality is NOT settable in windows-capture 2.0.1
            // (WIC default); max-width 1920 is recorded, not enforced.
            write_fragment(
                "capture-works",
                "pass",
                &format!(
                    "{{\"picker\":false,\"format\":\"jpeg\",\"jpeg_quality\":\"wic-default (not settable in windows-capture 2.0.1; design asked 80)\",\"width\":{},\"height\":{},\"max_width_1920\":{},\"first_frame_ms\":{},\"file\":\"{}\",\"bytes\":{},\"trial_event\":\"shotspike-events.jsonl\",\"event_hash\":\"{}\",\"note\":\"Graphics Capture from primary monitor without picker; one frame saved as JPEG + shot.taken event appended to trial JSONL (chain rule as the eye core, plaintext trial)\"}}",
                    w, h, w <= 1920, ms, json_escape(out), bytes, hash
                ),
            );
            0
        }
        Err(e) => {
            if e.contains("no frame") || e.contains("Monitor::primary") {
                fail_no_screen("capture-works", &e)
            } else {
                fail("capture-works", &e)
            }
        }
    }
}

// ---------------------------------------------------------------- Check 2: one-frame-stop
#[cfg(windows)]
fn check_one_frame_stop(out: &str) -> i32 {
    match capture::capture_once(out, "one-frame-stop") {
        Ok((w, h, ms, bytes)) => {
            // The handler stops the session after the first frame.
            // Wait 2 s: any second frame means continuous recording.
            std::thread::sleep(Duration::from_secs(2));
            let seen = capture::FRAMES_SEEN.load(std::sync::atomic::Ordering::SeqCst);
            if seen != 1 {
                return fail(
                    "one-frame-stop",
                    &format!(
                        "session delivered {} frames after stop (expected exactly 1) — continuous recording, forbidden by design",
                        seen
                    ),
                );
            }
            eprintln!(
                "[shotspike] one-frame-stop OK: {}x{} in {}ms, {} bytes, exactly 1 frame",
                w, h, ms, bytes
            );
            write_fragment(
                "one-frame-stop",
                "pass",
                &format!(
                    "{{\"frames_seen\":{},\"width\":{},\"height\":{},\"first_frame_ms\":{},\"file\":\"{}\",\"bytes\":{},\"note\":\"session stopped after exactly one frame; no second frame within 2 s\"}}",
                    seen, w, h, ms, json_escape(out), bytes
                ),
            );
            0
        }
        Err(e) => {
            if e.contains("no frame") || e.contains("Monitor::primary") {
                fail_no_screen("one-frame-stop", &e)
            } else {
                fail("one-frame-stop", &e)
            }
        }
    }
}

// ---------------------------------------------------------------- Check 3: shot-cost
#[cfg(windows)]
fn process_cpu_100ns() -> u64 {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    unsafe {
        let h = GetCurrentProcess();
        let mut _creation = FILETIME::default();
        let mut _exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if GetProcessTimes(h, &mut _creation, &mut _exit, &mut kernel, &mut user).is_ok() {
            let k = ((kernel.dwHighDateTime as u64) << 32) | kernel.dwLowDateTime as u64;
            let u = ((user.dwHighDateTime as u64) << 32) | user.dwLowDateTime as u64;
            k + u
        } else {
            0
        }
    }
}

/// Same definition as the proof gate: process CPU time / wall time x 100
/// (% of one core). Council condition 11: a shot must cost < 5%.
#[cfg(windows)]
fn cpu_pct(cpu0: u64, cpu1: u64, wall: Duration) -> f64 {
    if wall.is_zero() {
        return 0.0;
    }
    let delta_100ns = cpu1.saturating_sub(cpu0) as f64;
    let wall_100ns = wall.as_secs_f64() * 10_000_000.0;
    delta_100ns / wall_100ns * 100.0
}

#[cfg(windows)]
fn check_shot_cost(out: &str) -> i32 {
    let cpu0 = process_cpu_100ns();
    let wall0 = Instant::now();
    match capture::capture_once(out, "shot-cost") {
        Ok((w, h, ms, bytes)) => {
            let wall = wall0.elapsed();
            let cpu1 = process_cpu_100ns();
            let pct = cpu_pct(cpu0, cpu1, wall);
            eprintln!(
                "[shotspike] shot-cost: {}x{} in {}ms, cpu {:.2}% (wall {:?}), {} bytes",
                w, h, ms, pct, wall, bytes
            );
            if pct >= 5.0 {
                return fail(
                    "shot-cost",
                    &format!(
                        "shot cost {:.2}% CPU >= 5% council threshold ({}x{}, {}ms, {} bytes)",
                        pct, w, h, ms, bytes
                    ),
                );
            }
            write_fragment(
                "shot-cost",
                "pass",
                &format!(
                    "{{\"cpu_pct\":{:.2},\"threshold_pct\":5.0,\"capture_ms\":{},\"wall_ms\":{},\"width\":{},\"height\":{},\"file\":\"{}\",\"bytes\":{},\"note\":\"process CPU (kernel+user) / wall time, same definition as the proof gate\"}}",
                    pct, ms, wall.as_millis(), w, h, json_escape(out), bytes
                ),
            );
            0
        }
        Err(e) => {
            if e.contains("no frame") || e.contains("Monitor::primary") {
                fail_no_screen("shot-cost", &e)
            } else {
                fail("shot-cost", &e)
            }
        }
    }
}

// ---------------------------------------------------------------- Check 4: dxgi-fallback
#[cfg(windows)]
fn check_dxgi_fallback(out: &str) -> i32 {
    // Only runs when Graphics Capture did NOT pass: read the check-1 fragment.
    let gcap_pass = fs::read_to_string("shotspike-capture-works.json")
        .map(|c| c.contains("\"status\":\"pass\""))
        .unwrap_or(false);
    if gcap_pass {
        eprintln!("[shotspike] dxgi-fallback skipped: primary Graphics Capture passed");
        write_fragment(
            "dxgi-fallback",
            "pass",
            "{\"skipped\":true,\"reason\":\"primary ok\",\"note\":\"DXGI fallback not needed — Graphics Capture passed\"}",
        );
        return 0;
    }
    eprintln!("[shotspike] primary failed or missing — trying DXGI Duplication fallback");
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
                        .save_as_image(out, ImageFormat::Jpeg)
                        .map_err(|e| format!("save_as_image: {}", e))?;
                    let bytes = fs::metadata(out).map(|m| m.len()).unwrap_or(0);
                    return Ok((w, h, bytes));
                }
                Err(e) => {
                    last_err = format!("{}", e);
                    eprintln!("[shotspike] dxgi attempt {}: {}", attempt, last_err);
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
            eprintln!("[shotspike] dxgi-fallback OK: {}x{} in {}ms, {} bytes", w, h, ms, bytes);
            write_fragment(
                "dxgi-fallback",
                "pass",
                &format!(
                    "{{\"width\":{},\"height\":{},\"elapsed_ms\":{},\"file\":\"{}\",\"bytes\":{},\"note\":\"DXGI Desktop Duplication fallback produced a valid JPEG after Graphics Capture failed\"}}",
                    w, h, ms, json_escape(out), bytes
                ),
            );
            0
        }
        Err(e) => {
            if e.contains("headless") || e.contains("Monitor::primary") {
                fail_no_screen("dxgi-fallback", &e)
            } else {
                fail("dxgi-fallback", &e)
            }
        }
    }
}

// ---------------------------------------------------------------- Merge
#[cfg(windows)]
fn merge() -> i32 {
    let mut checks: Vec<(String, String)> = Vec::new();
    let wanted = ["capture-works", "one-frame-stop", "shot-cost", "dxgi-fallback"];
    let mut missing: Vec<&str> = Vec::new();
    let mut all_pass = true;
    let mut any_no_screen = false;
    for name in wanted {
        let path = format!("shotspike-{}.json", name);
        match fs::read_to_string(&path) {
            Ok(content) => {
                let pass = content.contains("\"status\":\"pass\"");
                if !pass {
                    all_pass = false;
                    if content.contains("\"no_screen\":true") {
                        any_no_screen = true;
                    }
                }
                checks.push((name.to_string(), content.trim().to_string()));
            }
            Err(_) => {
                missing.push(name);
                all_pass = false;
            }
        }
    }

    let verdict = if all_pass {
        "pass"
    } else if any_no_screen && missing.is_empty() {
        "deferred"
    } else {
        "fail"
    };
    let mut body = String::from("{\"spike\":\"eye-shot-spike\",\"verdict\":\"");
    body.push_str(verdict);
    body.push_str("\",\"ts_unix\":");
    body.push_str(&now_unix().to_string());
    body.push_str(",\"perf_tag\":\"runner-only — does not prove device performance\",\"checks\":{");
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
    body.push_str("],\"honest_limits\":\"JPEG is WIC-default quality (windows-capture 2.0.1 exposes no quality setting; design asked 80) and full monitor width (no resize in the spike); capture over a real exclusive-fullscreen game is NOT tested here and is decided on the Legion; trial JSONL is plaintext (the real unit encrypts with DPAPI)\"}");
    match fs::write("shot-spike-results.json", &body) {
        Ok(()) => {
            eprintln!("[shotspike] merge verdict: {}", verdict);
            match verdict {
                "pass" => 0,
                _ => 1,
            }
        }
        Err(e) => {
            eprintln!("[shotspike] merge failed to write shot-spike-results.json: {}", e);
            1
        }
    }
}
