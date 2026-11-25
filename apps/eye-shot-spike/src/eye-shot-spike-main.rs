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
//!   eye-shot-spike --check shot-cost      # RE-MEASURED (council c27):
//!                                          # AGGREGATE — 10 cold shots
//!                                          # (fresh session each) + 100
//!                                          # warm shots in ONE session;
//!                                          # per-shot CPU = total / N,
//!                                          # so the 15.625 ms tick
//!                                          # error is ~0.16 ms/shot;
//!                                          # pre-set decision rules
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
        "shot-cost" => check_shot_cost("shotspike-cost"),
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

    /// One measured shot inside the aggregate re-measurement.
    /// `wait_ms` is the wall time from the previous encode's end to
    /// this frame's arrival (frame 1: from session start) — on a
    /// static desktop the compositor may take its time, and that
    /// idle wait costs ~0 CPU, so the decision rules use CPU
    /// deltas, never the wait. `cycles_*` are raw
    /// QueryProcessCycleTime readings (None = the OS call failed).
    #[derive(Clone, Debug)]
    pub struct ShotStat {
        pub n: usize,
        pub arrival_wall_ms: u128,
        pub wait_ms: u128,
        pub encode_ms: u128,
        pub cpu_arrival_100ns: u64,
        pub cpu_after_encode_100ns: u64,
        pub cycles_arrival: Option<u64>,
        pub cycles_after_encode: Option<u64>,
        pub width: u32,
        pub height: u32,
        pub bytes: u64,
    }

    pub static SHOT_STATS: std::sync::Mutex<Vec<ShotStat>> =
        std::sync::Mutex::new(Vec::new());
    pub static CPU_AT_CHECK_START: AtomicU64 = AtomicU64::new(0);

    /// Aggregate capture: `target` frames from ONE session in ONE
    /// process (council c27). Frame 1 is cold (includes D3D device +
    /// session setup); frames 2..=target are warm (same device, same
    /// session). The handler records, per frame, arrival wall + CPU
    /// (GetProcessTimes), raw cycle counts (QueryProcessCycleTime),
    /// and encode wall + CPU — the measurement points the council
    /// ordered. EVERY frame is encoded to JPEG: the encode is part
    /// of the cost being measured, so skipping it would understate
    /// the total.
    pub struct AggregateShot {
        prefix: String,
        target: usize,
        start: Instant,
        last_encode_end: Instant,
    }

    impl GraphicsCaptureApiHandler for AggregateShot {
        type Flags = String;
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn new(ctx: Context<Self::Flags>) -> Result<Self, Self::Error> {
            let now = Instant::now();
            // Flags carry "prefix|target" (target parsed here because
            // the handler constructor only receives the flags string).
            let (prefix, target) = match ctx.flags.split_once('|') {
                Some((p, t)) => (p.to_string(), t.parse::<usize>().unwrap_or(5)),
                None => (ctx.flags.clone(), 5),
            };
            Ok(Self {
                prefix,
                target,
                start: now,
                last_encode_end: now,
            })
        }

        fn on_frame_arrived(
            &mut self,
            frame: &mut Frame,
            capture_control: InternalCaptureControl,
        ) -> Result<(), Self::Error> {
            let n = FRAMES_SEEN.fetch_add(1, Ordering::SeqCst) + 1;
            let arrival = Instant::now();
            let cpu_arrival = process_cpu_100ns();
            let cycles_arrival = process_cycles();
            let wait_ms = arrival.duration_since(self.last_encode_end).as_millis();
            let width = frame.width();
            let height = frame.height();
            let out = format!("{}-{}.jpg", self.prefix, n);
            let enc0 = Instant::now();
            frame.save_as_image(&out, ImageFormat::Jpeg)?;
            let encode_ms = enc0.elapsed().as_millis();
            let cpu_after = process_cpu_100ns();
            let cycles_after = process_cycles();
            let bytes = fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
            eprintln!(
                "[shotspike] frame {} ({}x{}): wait {}ms, encode {}ms, {} bytes",
                n, width, height, wait_ms, encode_ms, bytes
            );
            if let Ok(mut stats) = SHOT_STATS.lock() {
                stats.push(ShotStat {
                    n,
                    arrival_wall_ms: arrival.duration_since(self.start).as_millis(),
                    wait_ms,
                    encode_ms,
                    cpu_arrival_100ns: cpu_arrival,
                    cpu_after_encode_100ns: cpu_after,
                    cycles_arrival,
                    cycles_after_encode: cycles_after,
                    width,
                    height,
                    bytes,
                });
            }
            self.last_encode_end = Instant::now();
            if n >= self.target {
                capture_control.stop();
            }
            Ok(())
        }

        fn on_closed(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Capture `target` frames in one session. Fails loudly when the
    /// session cannot deliver them all: a 20 s watchdog for the first
    /// frame (headless runner), and a 10 s stall watchdog between
    /// frames — a stall means the session is NOT reusable across
    /// shots in one process, which is an immediate stop condition
    /// of the council ruling ("reuse-impossible"), not a silent gap.
    pub fn capture_n(prefix: &str, target: usize, check_name: &str) -> Result<Vec<ShotStat>, String> {
        let monitor = Monitor::primary().map_err(|e| format!("Monitor::primary: {}", e))?;
        let _mw = monitor.width().map_err(|e| format!("monitor width: {}", e))?;
        let _mh = monitor.height().map_err(|e| format!("monitor height: {}", e))?;
        if let Ok(mut stats) = SHOT_STATS.lock() {
            stats.clear();
        }
        FRAMES_SEEN.store(0, Ordering::SeqCst);
        CPU_AT_CHECK_START.store(process_cpu_100ns(), Ordering::SeqCst);

        let watchdog_check = check_name.to_string();
        let watchdog_prefix = prefix.to_string();
        std::thread::spawn(move || {
            let t0 = Instant::now();
            let mut last_count = 0usize;
            let mut last_change = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let n = FRAMES_SEEN.load(Ordering::SeqCst);
                if n != last_count {
                    last_count = n;
                    last_change = Instant::now();
                }
                if n == 0 && t0.elapsed() > Duration::from_secs(20) {
                    eprintln!("[shotspike] watchdog: no Graphics Capture frame in 20s");
                    write_fragment(
                        &format!("{}-timeout", watchdog_check),
                        "fail",
                        &format!(
                            "{{\"error\":\"no frame within 20s (headless runner?)\",\"no_screen\":true,\"out\":\"{}\"}}",
                            json_escape(&watchdog_prefix)
                        ),
                    );
                    std::process::exit(1);
                }
                if (1..target).contains(&n) && last_change.elapsed() > Duration::from_secs(10) {
                    eprintln!(
                        "[shotspike] watchdog: session stalled after {} frame(s) — cannot deliver {} frames in one process",
                        n, target
                    );
                    write_fragment(
                        &watchdog_check,
                        "fail",
                        &format!(
                            "{{\"stop_condition\":\"reuse-impossible\",\"frames_delivered\":{},\"frames_target\":{},\"note\":\"session stalled >10 s after frame {} — the session is NOT reusable across shots in one process; immediate stop per the council ruling, escalate\"}}",
                            n, target, n
                        ),
                    );
                    std::process::exit(1);
                }
                if n >= target {
                    return;
                }
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
            format!("{}|{}", prefix, target),
        );
        AggregateShot::start(settings).map_err(|e| format!("GraphicsCapture start: {}", e))?;
        match SHOT_STATS.lock() {
            Ok(stats) => Ok(stats.clone()),
            Err(_) => Err("SHOT_STATS lock poisoned".to_string()),
        }
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

#[cfg(windows)]
fn process_cycles() -> Option<u64> {
    // QueryProcessCycleTime is NOT exposed by the `windows` 0.61 crate
    // (checked 2026-11-25: no binding in windows-0.61.3), so it is
    // declared directly against kernel32 (available since Vista).
    // Returns RAW cycle counts: no frequency conversion is applied
    // here, so cycles are supplementary evidence only — the verdict
    // uses GetProcessTimes aggregates. None when the OS call fails.
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    extern "system" {
        fn QueryProcessCycleTime(hprocess: *mut c_void, cycles: *mut u64) -> i32;
    }
    use windows::Win32::System::Threading::GetCurrentProcess;
    unsafe {
        let mut cycles: u64 = 0;
        let h = GetCurrentProcess();
        let ok = QueryProcessCycleTime(h.0 as *mut c_void, &mut cycles);
        if ok != 0 {
            Some(cycles)
        } else {
            None
        }
    }
}

#[cfg(windows)]
fn median_u128(mut v: Vec<u128>) -> u128 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    }
}

// ---------------------------------------------------------------- Check 3: shot-cost (AGGREGATE, council c27)
/// Aggregate re-measurement (council ruling on the escalation,
/// 2026-11-25): the 15.625 ms tick of GetProcessTimes makes single
/// shots undecidable at the 5/15 ms thresholds, so the cost is
/// measured as an AGGREGATE: 10 cold shots (a fresh session each —
/// D3D device + session setup every time) and 100 warm shots in ONE
/// session (frame 1 in-session cold, frames 2-101 warm). Per-shot
/// CPU = total / N, so the tick error is ~0.16 ms per shot.
/// Raw QueryProcessCycleTime totals are recorded as supplementary
/// evidence (no frequency conversion — the verdict uses the
/// GetProcessTimes aggregates only).
///
/// DECISION RULES, fixed BEFORE seeing the numbers (written in the
/// dev log, cycle 27, before the run):
/// - warm per-shot aggregate CPU <= 5 ms => pass
///   ("aggregate-warm-cheap": merge PR #9, the shots build continues);
/// - warm per-shot 5-15 ms => pass with `definition_review: true`
///   (acceptable as an absolute cost; the council fixes the new
///   definition — the build does NOT stop);
/// - warm per-shot > 15 ms => fail ("stop-escalate", new escalation).
/// The cold aggregate is RECORDED, not gated: most v1 shots are cold
/// (<= 1/min), and the cold cost is the setup the council already
/// priced in §6 (a 31 ms cold shot once a minute is ~0.05% of a core).
/// Immediate stops: the session cannot deliver its frames
/// ("reuse-impossible", written by the watchdog); any warm encode
/// alone > 25 ms wall.
#[cfg(windows)]
fn check_shot_cost(prefix: &str) -> i32 {
    // ---- Cold aggregate: 10 fresh sessions, 1 frame each. ----
    let mut cold_cpu_total_ms = 0.0f64;
    let mut cold_encode_wall_total: u128 = 0;
    let mut cold_cycles_total: u64 = 0;
    let mut cold_qpc_ok = true;
    let mut cold_first_wall_ms: u128 = 0;
    let mut cold_first_cpu_ms = 0.0f64;
    for i in 1..=10usize {
        let p = format!("{}-cold-{}", prefix, i);
        let cpu_before = process_cpu_100ns();
        let cyc_before = process_cycles();
        let stats = match capture::capture_n(&p, 1, "shot-cost") {
            Ok(s) => s,
            Err(e) => {
                if e.contains("no frame") || e.contains("Monitor::primary") {
                    return fail_no_screen("shot-cost", &e);
                }
                return fail("shot-cost", &e);
            }
        };
        if stats.len() != 1 {
            return fail(
                "shot-cost",
                &format!(
                    "cold session {} delivered {} frames, expected 1 (reuse-impossible — escalate to the council)",
                    i,
                    stats.len()
                ),
            );
        }
        let cpu_after = process_cpu_100ns();
        let cyc_after = process_cycles();
        let shot_cpu_ms =
            (cpu_after.saturating_sub(cpu_before)) as f64 / 10_000.0;
        cold_cpu_total_ms += shot_cpu_ms;
        cold_encode_wall_total += stats[0].encode_ms;
        match (cyc_before, cyc_after) {
            (Some(b), Some(a)) => cold_cycles_total += a.saturating_sub(b),
            _ => cold_qpc_ok = false,
        }
        if i == 1 {
            cold_first_wall_ms = stats[0].arrival_wall_ms + stats[0].encode_ms;
            cold_first_cpu_ms = shot_cpu_ms;
        }
        eprintln!(
            "[shotspike] cold shot {}: {:.2}ms CPU, encode {}ms",
            i, shot_cpu_ms, stats[0].encode_ms
        );
    }
    let cold_per_shot_ms = cold_cpu_total_ms / 10.0;
    let cold_encode_wall_mean_ms = cold_encode_wall_total as f64 / 10.0;
    let cold_cpu_pct_old = if cold_first_wall_ms > 0 {
        cold_first_cpu_ms / cold_first_wall_ms as f64 * 100.0
    } else {
        0.0
    };

    // ---- Warm aggregate: 101 frames in ONE session. ----
    let warm_prefix = format!("{}-warm", prefix);
    let warm_stats = match capture::capture_n(&warm_prefix, 101, "shot-cost") {
        Ok(s) => s,
        Err(e) => {
            if e.contains("no frame") || e.contains("Monitor::primary") {
                return fail_no_screen("shot-cost", &e);
            }
            return fail("shot-cost", &e);
        }
    };
    if warm_stats.len() != 101 {
        return fail(
            "shot-cost",
            &format!(
                "warm session delivered {} frames, expected 101 in one process (reuse-impossible — escalate to the council)",
                warm_stats.len()
            ),
        );
    }
    let cpu0 = capture::CPU_AT_CHECK_START.load(std::sync::atomic::Ordering::SeqCst);
    let in_session_cold = &warm_stats[0];
    let setup_cpu_ms =
        (in_session_cold.cpu_arrival_100ns.saturating_sub(cpu0)) as f64 / 10_000.0;
    let in_session_cold_cpu_ms =
        (in_session_cold.cpu_after_encode_100ns.saturating_sub(cpu0)) as f64 / 10_000.0;
    let setup_share_pct = if in_session_cold_cpu_ms > 0.0 {
        setup_cpu_ms / in_session_cold_cpu_ms * 100.0
    } else {
        0.0
    };
    // Warm total = process CPU from the end of frame 1 (cold) to the
    // end of frame 101 — 100 warm frames, one tick of error total.
    let warm_total_cpu_ms = (warm_stats[100]
        .cpu_after_encode_100ns
        .saturating_sub(warm_stats[0].cpu_after_encode_100ns)) as f64
        / 10_000.0;
    let warm_per_shot_ms = warm_total_cpu_ms / 100.0;
    let warm_encode: Vec<u128> = warm_stats[1..].iter().map(|s| s.encode_ms).collect();
    let warm_encode_median_ms = median_u128(warm_encode.clone());
    let warm_encode_max_ms = *warm_encode.iter().max().unwrap_or(&0);
    let encode_dominant =
        warm_per_shot_ms > 0.0 && (warm_encode_median_ms as f64) >= 0.5 * warm_per_shot_ms;
    let warm_cycles_total = match (
        warm_stats[0].cycles_after_encode,
        warm_stats[100].cycles_after_encode,
    ) {
        (Some(b), Some(a)) => Some(a.saturating_sub(b)),
        _ => None,
    };
    let warm_cycles_per_shot = warm_cycles_total.map(|t| t / 100);

    let (status, cost_rule, definition_review, note) = if warm_encode_max_ms > 25 {
        (
            "fail",
            "stop-escalate",
            false,
            "immediate stop: a warm encode alone exceeded 25 ms wall",
        )
    } else if warm_per_shot_ms <= 5.0 {
        (
            "pass",
            "aggregate-warm-cheap",
            false,
            "aggregate warm cost <= 5 ms CPU per shot (100-shot aggregate, tick error ~0.16 ms/shot) — the shots build continues; merge PR #9",
        )
    } else if warm_per_shot_ms <= 15.0 {
        (
            "pass",
            "acceptable-absolute",
            true,
            "aggregate warm cost 5-15 ms CPU per shot — acceptable as an absolute cost; the council fixes the new definition; the build does NOT stop",
        )
    } else {
        (
            "fail",
            "stop-escalate",
            false,
            "aggregate warm cost above 15 ms CPU per shot — stop and escalate to the council",
        )
    };

    let qpc_json = |total: Option<u64>, per_shot: Option<u64>, ok: bool| -> String {
        match (total, per_shot) {
            (Some(t), Some(p)) => format!(
                "{{\"available\":{},\"cycles_total\":{},\"cycles_per_shot\":{},\"note\":\"raw cycles, no frequency conversion — supplementary only\"}}",
                ok, t, p
            ),
            (Some(t), None) => format!(
                "{{\"available\":{},\"cycles_total\":{},\"cycles_per_shot\":null,\"note\":\"raw cycles, no frequency conversion — supplementary only\"}}",
                ok, t
            ),
            _ => "{\"available\":false,\"cycles_total\":null,\"cycles_per_shot\":null,\"note\":\"QueryProcessCycleTime unavailable on this host — verdict uses GetProcessTimes aggregates\"}".to_string(),
        }
    };
    let details = format!(
        "{{\"rule\":\"council-c27-aggregate\",\"frames\":{{\"cold_shots\":10,\"warm_shots\":100}},\"tick_ms\":15.625,\"aggregate_error_ms_per_shot\":0.16,\"cold\":{{\"total_cpu_ms\":{:.2},\"per_shot_cpu_ms\":{:.2},\"encode_wall_total_ms\":{},\"encode_wall_mean_ms\":{:.2},\"first_shot_cpu_pct_old_definition\":{:.2},\"cycles\":{}}},\"warm\":{{\"total_cpu_ms\":{:.2},\"per_shot_cpu_ms\":{:.2},\"encode_median_ms\":{},\"encode_max_ms\":{},\"encode_dominant\":{},\"in_session_cold\":{{\"cpu_ms\":{:.2},\"setup_cpu_ms\":{:.2},\"setup_share_pct\":{:.1}}},\"cycles\":{}}},\"cost_rule\":\"{}\",\"definition_review\":{},\"note\":\"{}\"}}",
        cold_cpu_total_ms, cold_per_shot_ms, cold_encode_wall_total, cold_encode_wall_mean_ms,
        cold_cpu_pct_old,
        qpc_json(Some(cold_cycles_total), Some(cold_cycles_total / 10), cold_qpc_ok),
        warm_total_cpu_ms, warm_per_shot_ms, warm_encode_median_ms, warm_encode_max_ms,
        encode_dominant, in_session_cold_cpu_ms, setup_cpu_ms, setup_share_pct,
        qpc_json(warm_cycles_total, warm_cycles_per_shot, warm_cycles_total.is_some()),
        cost_rule, definition_review, note
    );
    eprintln!(
        "[shotspike] shot-cost aggregate: cold {:.2}ms/shot (10 sessions), warm {:.2}ms/shot (100 frames), encode median {}ms, rule {}",
        cold_per_shot_ms, warm_per_shot_ms, warm_encode_median_ms, cost_rule
    );
    if status == "fail" {
        write_fragment("shot-cost", "fail", &details);
        return 1;
    }
    write_fragment("shot-cost", "pass", &details);
    0
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
