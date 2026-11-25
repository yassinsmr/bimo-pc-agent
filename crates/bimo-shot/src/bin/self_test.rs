//! bimo-shot self-test (Windows only) — the shot unit's own CI check.
//!
//! Usage (on real Windows):
//!   bimo-shot-self-test --out shot-unit-results.json [--measure]
//!
//! Checks (each writes into the result JSON; any failure fails the run):
//! 1. `rate-limiter`: the §6 draft tests, live (7 in 1 s → 5 allowed /
//!    2 refused; 1/min × 5 → all allowed).
//! 2. `one-shot`: one real shot through `ShotService` (persistent
//!    session): file exists, valid JPEG (magic + SOF dimensions
//!    parsed independently), width ≤ 1920, quality recorded.
//! 3. `--measure` (unit's own regression measurement, flawhunt 11-w):
//!    10 cold shots (fresh session each) + 100 warm shots in ONE
//!    persistent session, same aggregate rules as council c27
//!    (warm ≤ 5 ms/shot pass; 5–15 pass with `definition_review`;
//!    > 15 fail; one warm encode > 25 ms wall fails immediately).
//!    The limiter is bypassed here on purpose: the measurement prices
//!    the capture cost, and 100 shots in seconds would trip §6.
//!
//! Honest limits: a no-frame timeout on a headless runner is recorded
//! with `"no_screen": true` and the verdict is a deferral to the
//! Legion, not a design failure. Capture over a real exclusive
//! fullscreen game is NOT tested here (second gate, on arrival).

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

#[cfg(not(windows))]
fn main() {
    eprintln!("[bimo-shot] self-test only runs on Windows (this is a non-Windows build)");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    std::process::exit(real_main());
}

#[cfg(windows)]
fn real_main() -> i32 {
    use bimo_shot::rate_limiter::{Acquire, RateLimiter};

    let args: Vec<String> = std::env::args().collect();
    let get = |flag: &str| -> Option<String> {
        args.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].clone())
    };
    let out = get("--out").unwrap_or_else(|| "shot-unit-results.json".to_string());
    let measure = args.iter().any(|a| a == "--measure");

    let mut checks: Vec<(String, bool, String)> = Vec::new();

    // ---- Check 1: rate limiter (live, synthetic instants) ----
    let (ok, detail) = {
        let mut lim = RateLimiter::new();
        let start = Instant::now();
        let mut allowed = 0;
        let mut refused = 0;
        for i in 0..7 {
            match lim.try_acquire(start + Duration::from_millis(i * 100)) {
                Acquire::Allowed => allowed += 1,
                Acquire::Refused => refused += 1,
            }
        }
        let mut lim2 = RateLimiter::new();
        let mut slow_ok = true;
        for i in 0..5 {
            if lim2.try_acquire(start + Duration::from_secs(60 * i)) != Acquire::Allowed {
                slow_ok = false;
            }
        }
        let ok = allowed == 5 && refused == 2 && slow_ok && lim2.refused_total == 0;
        (
            ok,
            format!(
                "{{\"burst_7_in_1s\":{{\"allowed\":{},\"refused\":{}}},\"one_per_min_x5_all_allowed\":{},\"rule\":\"5 per rolling 10 s (§6)\"}}",
                allowed, refused, slow_ok
            ),
        )
    };
    checks.push(("rate-limiter".to_string(), ok, detail));

    // ---- Check 2: one real shot through the service ----
    let (ok, detail) = check_one_shot();
    let one_shot_ok = ok;
    checks.push(("one-shot".to_string(), ok, detail));

    // ---- Check 3 (optional): aggregate measurement ----
    let mut measure_detail: Option<String> = None;
    if measure {
        let (ok, detail) = check_measure();
        measure_detail = Some(detail.clone());
        checks.push(("shot-cost-aggregate".to_string(), ok, detail));
    }

    let all_pass = checks.iter().all(|(_, ok, _)| *ok);
    let verdict = if all_pass {
        "pass"
    } else if !one_shot_ok
        && checks
            .iter()
            .find(|(n, _, _)| n == "one-shot")
            .map(|(_, _, d)| d.contains("\"no_screen\":true"))
            .unwrap_or(false)
    {
        "deferred"
    } else {
        "fail"
    };
    let mut body = String::from("{\"unit\":\"bimo-shot\",\"verdict\":\"");
    body.push_str(verdict);
    body.push_str("\",\"ts_unix\":");
    body.push_str(&now_unix().to_string());
    body.push_str(",\"perf_tag\":\"runner-only — does not prove device performance\",\"checks\":{");
    for (i, (name, ok, detail)) in checks.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&format!(
            "\"{}\":{{\"status\":\"{}\",\"details\":{}}}",
            json_escape(name),
            if *ok { "pass" } else { "fail" },
            detail
        ));
    }
    body.push_str("},\"honest_limits\":\"capture over a real exclusive-fullscreen game is NOT tested here (second gate, on the Legion); JPEG dimensions are parsed independently from the SOF marker\"}");
    if let Some(m) = &measure_detail {
        body = body.trim_end_matches('}').to_string();
        body.push_str(&format!(",\"measure\":{}", m));
        body.push('}');
    }
    match fs::write(&out, &body) {
        Ok(()) => eprintln!("[bimo-shot] self-test verdict: {} -> {}", verdict, out),
        Err(e) => {
            eprintln!("[bimo-shot] FAILED to write {}: {}", out, e);
            return 1;
        }
    }
    match verdict {
        "pass" => 0,
        _ => 1,
    }
}

/// Parse JPEG dimensions independently from the SOF0/SOF1/SOF2 marker
/// (the encoder's own report is not trusted for the assertion).
#[cfg(windows)]
fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return None;
    }
    let mut i = 2usize;
    while i + 9 < bytes.len() {
        if bytes[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = bytes[i + 1];
        if marker == 0x00 || marker == 0xFF {
            i += 1;
            continue;
        }
        if marker == 0xD9 {
            return None; // EOI before any SOF
        }
        if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
            // SOF segment: len(2) precision(1) height(2) width(2).
            let h = u16::from_be_bytes([bytes[i + 5], bytes[i + 6]]) as u32;
            let w = u16::from_be_bytes([bytes[i + 7], bytes[i + 8]]) as u32;
            return Some((w, h));
        }
        // Standalone markers have no length field.
        if marker == 0x01 || (0xD0..=0xD8).contains(&marker) {
            i += 2;
            continue;
        }
        let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
        if len < 2 {
            return None;
        }
        i += 2 + len;
    }
    None
}

#[cfg(windows)]
fn check_one_shot() -> (bool, String) {
    use bimo_shot::service::{ShotOutcome, ShotService};

    let data_dir = std::env::temp_dir().join(format!("bimo-shot-test-{}", now_unix()));
    let _ = fs::create_dir_all(&data_dir);
    let mut service = ShotService::new(data_dir.clone());
    let outcome = service.request_shot("self-test");
    service.stop();
    match outcome {
        ShotOutcome::Taken(info) => {
            let bytes = match fs::read(&info.file) {
                Ok(b) => b,
                Err(e) => {
                    return (
                        false,
                        format!("{{\"error\":\"cannot read shot file: {}\"}}", json_escape(&e.to_string())),
                    )
                }
            };
            let dims = jpeg_dimensions(&bytes);
            let dims_ok = dims == Some((info.width, info.height));
            let width_ok = info.width <= 1920;
            let ok = dims_ok && width_ok && info.bytes == bytes.len() as u64 && bytes.len() > 1000;
            (
                ok,
                format!(
                    "{{\"file\":\"{}\",\"width\":{},\"height\":{},\"bytes\":{},\"quality\":\"{}\",\"cold\":{},\"wait_ms\":{},\"encode_ms\":{},\"jpeg_magic_ok\":{},\"sof_dimensions_match\":{},\"width_le_1920\":{},\"note\":\"one frame from the persistent session; quality 80 + max width 1920 via WIC (or wic-default-fallback, recorded)\"}}",
                    json_escape(&info.file.display().to_string()),
                    info.width,
                    info.height,
                    info.bytes,
                    info.quality,
                    info.cold,
                    info.wait_ms,
                    info.encode_ms,
                    bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
                    dims_ok,
                    width_ok
                ),
            )
        }
        ShotOutcome::RateLimited { rejected_total } => (
            false,
            format!(
                "{{\"error\":\"rate limited on the first shot (impossible in a fresh service)\",\"rejected_total\":{}}}",
                rejected_total
            ),
        ),
        ShotOutcome::Failed { reason } => {
            let no_screen = reason.contains("no frame") || reason.contains("Monitor::primary");
            (
                false,
                format!(
                    "{{\"error\":\"{}\",\"no_screen\":{},\"note\":\"no frame within 20 s — headless runner? Verdict deferred to the Legion, not a design failure\"}}",
                    json_escape(&reason),
                    no_screen
                ),
            )
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

/// Aggregate measurement of the UNIT's capture path (flawhunt 11-w):
/// 10 cold shots (fresh `CaptureSession` each) + 100 warm shots in
/// ONE persistent session. Same decision rules as council c27.
/// Cycle 29 (council condition 1): the belt also records the
/// per-frame warm encode distribution — every warm frame's encode
/// wall time, the frame index of the max, median and p95 — so the
/// next outlier can be attributed to a frame. The verdict rule is
/// UNCHANGED for the fair re-run (answer 5): one warm encode
/// > 25 ms wall still fails the belt; the merge decision on the
/// re-run follows the council's answer-5 rules, not this field alone.
#[cfg(windows)]
fn check_measure() -> (bool, String) {
    use bimo_shot::capture::CaptureSession;

    let data_dir = std::env::temp_dir().join(format!("bimo-shot-measure-{}", now_unix()));
    let _ = fs::create_dir_all(&data_dir);

    // ---- Cold: 10 fresh sessions, 1 frame each. ----
    let mut cold_cpu_total_ms = 0.0f64;
    let mut cold_encode_total: u128 = 0;
    for i in 1..=10usize {
        let session = CaptureSession::start_new();
        let cpu_before = process_cpu_100ns();
        let path = data_dir.join(format!("measure-cold-{}.jpg", i));
        match session.request(&path) {
            Ok(info) => {
                let cpu_after = process_cpu_100ns();
                cold_cpu_total_ms += (cpu_after.saturating_sub(cpu_before)) as f64 / 10_000.0;
                cold_encode_total += info.encode_ms;
            }
            Err(e) => {
                return (
                    false,
                    format!(
                        "{{\"error\":\"cold shot {} failed: {}\",\"no_screen\":{}}}",
                        i,
                        json_escape(&e),
                        e.contains("no frame") || e.contains("Monitor::primary")
                    ),
                );
            }
        }
        session.stop();
    }
    let cold_per_shot_ms = cold_cpu_total_ms / 10.0;

    // ---- Warm: 101 frames in ONE persistent session. ----
    // Frame i=1 is the cold-in-session frame (session setup cost);
    // warm frames are i=2..=101, reported as warm index 0..=99
    // (warm index = i - 2). Every warm encode wall time is kept so
    // the distribution can be published (council condition 1).
    let session = CaptureSession::start_new();
    let mut cpu_after: Vec<u64> = Vec::with_capacity(101);
    let mut warm_encode_ms: Vec<u128> = Vec::with_capacity(100);
    for i in 1..=101usize {
        let path = data_dir.join(format!("measure-warm-{}.jpg", i));
        match session.request(&path) {
            Ok(info) => {
                cpu_after.push(process_cpu_100ns());
                if i > 1 {
                    warm_encode_ms.push(info.encode_ms);
                }
            }
            Err(e) => {
                return (
                    false,
                    format!(
                        "{{\"error\":\"warm frame {} failed: {}\",\"no_screen\":{}}}",
                        i,
                        json_escape(&e),
                        e.contains("no frame") || e.contains("Monitor::primary")
                    ),
                );
            }
        }
    }
    session.stop();
    if cpu_after.len() != 101 {
        return (
            false,
            format!(
                "{{\"error\":\"warm session delivered {} frames, expected 101\"}}",
                cpu_after.len()
            ),
        );
    }
    let warm_total_cpu_ms =
        (cpu_after[100].saturating_sub(cpu_after[0])) as f64 / 10_000.0;
    let warm_per_shot_ms = warm_total_cpu_ms / 100.0;

    // Per-frame warm encode distribution (council condition 1):
    // max + its warm frame index, median, p95 (95th smallest of 100
    // = sorted[94]), and the full 100-value list in warm order.
    let mut sorted_encode = warm_encode_ms.clone();
    sorted_encode.sort_unstable();
    let encode_median_ms = (sorted_encode[49] as f64 + sorted_encode[50] as f64) / 2.0;
    let encode_p95_ms = sorted_encode[94];
    let (encode_max_ms, encode_max_frame) = warm_encode_ms
        .iter()
        .enumerate()
        .max_by_key(|(_, &v)| v)
        .map(|(idx, &v)| (v, idx))
        .unwrap_or((0, 0));
    let encode_wall_list = warm_encode_ms
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let (ok, cost_rule, definition_review, note) = if encode_max_ms > 25 {
        (
            false,
            "stop-escalate",
            false,
            "immediate stop: a warm encode alone exceeded 25 ms wall",
        )
    } else if warm_per_shot_ms <= 5.0 {
        (
            true,
            "aggregate-warm-cheap",
            false,
            "aggregate warm cost <= 5 ms CPU per shot (100-shot aggregate, tick error ~0.16 ms/shot)",
        )
    } else if warm_per_shot_ms <= 15.0 {
        (
            true,
            "acceptable-absolute",
            true,
            "aggregate warm cost 5-15 ms CPU per shot — acceptable as an absolute cost; the council fixed this definition (cycle 27)",
        )
    } else {
        (
            false,
            "stop-escalate",
            false,
            "aggregate warm cost above 15 ms CPU per shot — stop and escalate to the council",
        )
    };
    (
        ok,
        format!(
            "{{\"rule\":\"council-c27-aggregate (unit path)\",\"frames\":{{\"cold_shots\":10,\"warm_shots\":100}},\"tick_ms\":15.625,\"cold\":{{\"total_cpu_ms\":{:.2},\"per_shot_cpu_ms\":{:.2},\"encode_wall_mean_ms\":{:.2}}},\"warm\":{{\"total_cpu_ms\":{:.2},\"per_shot_cpu_ms\":{:.2},\"encode_max_ms\":{},\"encode_max_frame\":{},\"encode_median_ms\":{:.2},\"encode_p95_ms\":{},\"encode_wall_ms\":[{}]}},\"cost_rule\":\"{}\",\"definition_review\":{},\"note\":\"{}\"}}",
            cold_cpu_total_ms,
            cold_per_shot_ms,
            cold_encode_total as f64 / 10.0,
            warm_total_cpu_ms,
            warm_per_shot_ms,
            encode_max_ms,
            encode_max_frame,
            encode_median_ms,
            encode_p95_ms,
            encode_wall_list,
            cost_rule,
            definition_review,
            note
        ),
    )
}
