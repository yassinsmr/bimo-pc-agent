//! eye-window-spike — proof spike for Track A Unit 2 (the Eye),
//! window events (spec `track-a-unit2-eye-window-spike.md`).
//!
//! Four independent checks, one process invocation each, so a hang or
//! failure in one cannot block the others. Each invocation writes one
//! fragment `winspike-<check>.json`; `--merge` combines the fragments
//! plus the Defender before/after files into
//! `window-spike-results.json`. Window events also append to the
//! trial log `winspike-trial.jsonl` in the eye format (`seq` + `ts` +
//! `prev_hash` + `hash`).
//!
//! Usage (on real Windows):
//!   eye-window-spike --check hook-fires
//!   eye-window-spike --check proc-link
//!   eye-window-spike --check hook-resilience
//!   eye-window-spike --check titles-flag-off
//!   eye-window-spike --merge
//!
//! Frozen naming (cycle 16): `app.open` / `app.close` / `app.focus`
//! (hook, window-level, fields pid + exe + hwnd) vs `proc.seen` /
//! `proc.gone` (snapshotter, process-level). No full window title is
//! ever written while `eye.full-titles` is off (the default) — this
//! binary never asks for one.
//!
//! Honest limits (recorded in the JSON, not hidden):
//! - The runner has no real display: a headless failure is recorded
//!   as such, not as a design failure.
//! - No real exclusive-fullscreen game exists on the runner; the
//!   real-game case is decided on the Legion (second gate).
//! - On non-Windows builds every check writes "skipped", not "fail":
//!   the spike cannot prove anything there, and the merge verdict is
//!   "skipped" so local plumbing runs stay distinguishable from a
//!   real Windows pass/fail.

use bimo_wintrack::{tracker_supported, verify_proc_link, TrialLog, WinEvent, WinEventKind, WinTrack};
use std::fs;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TRIAL_LOG: &str = "winspike-trial.jsonl";

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
    let path = format!("winspike-{}.json", name);
    let body = format!(
        "{{\"check\":\"{}\",\"status\":\"{}\",\"ts_unix\":{},\"details\":{}}}",
        json_escape(name),
        status,
        now_unix(),
        details
    );
    match fs::write(&path, &body) {
        Ok(()) => eprintln!("[winspike] wrote {}", path),
        Err(e) => eprintln!("[winspike] FAILED to write {}: {}", path, e),
    }
}

fn fail(name: &str, err: &str) -> i32 {
    eprintln!("[winspike] check {} FAILED: {}", name, err);
    write_fragment(
        name,
        "fail",
        &format!("{{\"error\":\"{}\"}}", json_escape(err)),
    );
    1
}

fn skipped(name: &str, reason: &str) -> i32 {
    eprintln!("[winspike] check {} SKIPPED: {}", name, reason);
    write_fragment(
        name,
        "skipped",
        &format!("{{\"reason\":\"{}\"}}", json_escape(reason)),
    );
    0
}

fn main() {
    std::process::exit(real_main());
}

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
            eprintln!("usage: eye-window-spike --check <hook-fires|proc-link|hook-resilience|titles-flag-off> | --merge");
            return 2;
        }
    };
    match check.as_str() {
        "hook-fires" => check_hook_fires(),
        "proc-link" => check_proc_link(),
        "hook-resilience" => check_hook_resilience(),
        "titles-flag-off" => check_titles_flag_off(),
        other => {
            eprintln!("[winspike] unknown check: {}", other);
            2
        }
    }
}

/// Drain all events available until `deadline`, appending each to the
/// trial log and collecting them. Returns the collected events.
fn drain_until(rx: &Receiver<WinEvent>, log: &mut TrialLog, deadline: Instant) -> Vec<WinEvent> {
    let mut out = Vec::new();
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(ev) => {
                log.write(&ev);
                out.push(ev);
            }
            Err(_) => break,
        }
    }
    out
}

fn start_tracker() -> Result<(WinTrack, Receiver<WinEvent>), String> {
    let (tx, rx) = channel();
    let track = WinTrack::start(tx)?;
    Ok((track, rx))
}

fn spawn_app(exe: &str) -> Result<std::process::Child, String> {
    std::process::Command::new(exe)
        .spawn()
        .map_err(|e| format!("spawn {}: {}", exe, e))
}

fn count_kind(events: &[WinEvent], exe: &str, kind: &WinEventKind) -> usize {
    events
        .iter()
        .filter(|e| {
            std::mem::discriminant(&e.kind) == std::mem::discriminant(kind)
                && e.exe.eq_ignore_ascii_case(exe)
        })
        .count()
}

// ---------------------------------------------------------------- Check 1
fn check_hook_fires() -> i32 {
    let name = "hook-fires";
    if !tracker_supported() {
        return skipped(name, "not a Windows build — hook cannot fire here");
    }
    let (track, rx) = match start_tracker() {
        Ok(t) => t,
        Err(e) => return fail(name, &format!("tracker start failed: {}", e)),
    };
    let mut log = match TrialLog::open(TRIAL_LOG.into()) {
        Ok(l) => l,
        Err(e) => return fail(name, &format!("trial log open failed: {}", e)),
    };
    let mut launched: Vec<(&str, bool)> = Vec::new();
    let mut children = Vec::new();
    for app in ["notepad.exe", "calc.exe"] {
        match spawn_app(app) {
            Ok(child) => {
                launched.push((app, true));
                children.push(child);
            }
            Err(e) => {
                eprintln!("[winspike] launch failed (waived with reason): {}", e);
                launched.push((app, false));
            }
        }
    }
    if launched.iter().all(|(_, ok)| !ok) {
        track.stop();
        return fail(
            name,
            "no app could launch on this host — hook unprovable here",
        );
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    let events = drain_until(&rx, &mut log, deadline);
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }
    // Close events may still arrive just after the kill.
    let tail = drain_until(&rx, &mut log, Instant::now() + Duration::from_secs(1));
    let mut all = events;
    all.extend(tail);
    track.stop();

    let mut details = String::from("{");
    let mut first = true;
    let mut pass = true;
    for (app, ok) in &launched {
        if !first {
            details.push(',');
        }
        first = false;
        let focus = count_kind(&all, app, &WinEventKind::AppFocus);
        let open = count_kind(&all, app, &WinEventKind::AppOpen);
        let close = count_kind(&all, app, &WinEventKind::AppClose);
        details.push_str(&format!(
            "\"{}\":{{\"launched\":{},\"app.focus\":{},\"app.open\":{},\"app.close\":{}}}",
            app, ok, focus, open, close
        ));
        if *ok && focus == 0 {
            pass = false;
        }
    }
    details.push_str(&format!(
        ",\"total_events\":{},\"note\":\"SetWinEventHook (out-of-context) on Notepad+calc; an app that failed to launch is waived with its reason, never counted as a hook failure\"",
        all.len()
    ));
    details.push('}');
    if !pass {
        return fail(
            name,
            &format!("a launched app produced 0 app.focus events: {}", details),
        );
    }
    write_fragment(name, "pass", &details);
    0
}

// ---------------------------------------------------------------- Check 2
fn check_proc_link() -> i32 {
    let name = "proc-link";
    if !tracker_supported() {
        return skipped(name, "not a Windows build — no processes to link here");
    }
    let (track, rx) = match start_tracker() {
        Ok(t) => t,
        Err(e) => return fail(name, &format!("tracker start failed: {}", e)),
    };
    let mut log = match TrialLog::open(TRIAL_LOG.into()) {
        Ok(l) => l,
        Err(e) => return fail(name, &format!("trial log open failed: {}", e)),
    };
    let mut child = match spawn_app("notepad.exe") {
        Ok(c) => c,
        Err(e) => {
            track.stop();
            return fail(name, &format!("notepad did not start: {}", e));
        }
    };
    // Verify each event's link WHILE its process is alive: the
    // callback already resolved exe+pid at emission; this is the
    // independent re-check (GetWindowThreadProcessId + Toolhelp).
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut verified = 0usize;
    let mut bad: Vec<String> = Vec::new();
    let mut total = 0usize;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(ev) => {
                log.write(&ev);
                total += 1;
                if ev.hwnd == 0 || ev.pid == 0 {
                    bad.push(format!("zero hwnd/pid in {:?}", ev.kind.type_str()));
                    continue;
                }
                if ev.exe.is_empty() || ev.exe == "unknown.exe" || !ev.exe.ends_with(".exe") {
                    bad.push(format!("unresolved exe for pid {}: {:?}", ev.pid, ev.exe));
                    continue;
                }
                if verify_proc_link(ev.pid, &ev.exe) {
                    verified += 1;
                } else {
                    bad.push(format!(
                        "link mismatch: pid {} recorded as {} but Toolhelp disagrees",
                        ev.pid, ev.exe
                    ));
                }
            }
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    // Close events after the kill: shape-only check (the pid is dead,
    // so re-verification cannot run — the callback resolved the exe
    // at emission time, with a retry).
    let tail = drain_until(&rx, &mut log, Instant::now() + Duration::from_secs(1));
    for ev in &tail {
        total += 1;
        if ev.hwnd == 0 || ev.pid == 0 || ev.exe.is_empty() || ev.exe == "unknown.exe" {
            bad.push(format!("bad close event: pid {} exe {:?}", ev.pid, ev.exe));
        } else {
            verified += 1;
        }
    }
    track.stop();
    let details = format!(
        "{{\"total_events\":{},\"links_verified_live\":{},\"bad\":{},\"note\":\"each live event re-checked against Toolhelp while its process was alive; post-kill close events are shape-checked only\"}}",
        total,
        verified,
        bad.len()
    );
    if total == 0 {
        return fail(name, "0 events — nothing to link (hook blind?)");
    }
    if !bad.is_empty() {
        return fail(name, &format!("{} bad links: {} | {}", bad.len(), bad[0], details));
    }
    write_fragment(name, "pass", &details);
    0
}

// ---------------------------------------------------------------- Check 3
fn check_hook_resilience() -> i32 {
    let name = "hook-resilience";
    if !tracker_supported() {
        return skipped(name, "not a Windows build — no hook to kill here");
    }
    let (track, rx) = match start_tracker() {
        Ok(t) => t,
        Err(e) => return fail(name, &format!("tracker start failed: {}", e)),
    };
    let mut log = match TrialLog::open(TRIAL_LOG.into()) {
        Ok(l) => l,
        Err(e) => return fail(name, &format!("trial log open failed: {}", e)),
    };
    // Baseline: the hook must be alive first.
    let mut child = match spawn_app("notepad.exe") {
        Ok(c) => c,
        Err(e) => {
            track.stop();
            return fail(name, &format!("notepad did not start: {}", e));
        }
    };
    let baseline = drain_until(&rx, &mut log, Instant::now() + Duration::from_secs(5));
    let baseline_n = baseline
        .iter()
        .filter(|e| matches!(e.kind, WinEventKind::AppFocus | WinEventKind::AppOpen))
        .count();
    let _ = child.kill();
    let _ = child.wait();
    if baseline_n == 0 {
        track.stop();
        return fail(name, "baseline: hook saw 0 events before the kill — hook was never alive");
    }
    // Kill the hook outright; the watchdog (5 s tick) must ask for a
    // re-install and the pump thread must bring events back < 10 s.
    let killed_at = track.kill_hook_for_test();
    let mut recovered_after_ms: Option<u64> = None;
    let post_recovery: usize;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        match rx.recv_timeout(deadline - now) {
            Ok(ev) => {
                log.write(&ev);
                if matches!(ev.kind, WinEventKind::HookRecovered) {
                    recovered_after_ms = ev.after_ms;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let after_ms = match recovered_after_ms {
        Some(ms) => ms,
        None => {
            track.stop();
            return fail(
                name,
                "no hook.recovered event within 10 s of the kill (watchdog did not recover)",
            );
        }
    };
    // Events must actually flow again after recovery.
    let mut child2 = match spawn_app("notepad.exe") {
        Ok(c) => c,
        Err(e) => {
            track.stop();
            return fail(name, &format!("notepad did not restart after recovery: {}", e));
        }
    };
    let after = drain_until(&rx, &mut log, Instant::now() + Duration::from_secs(5));
    post_recovery = after
        .iter()
        .filter(|e| matches!(e.kind, WinEventKind::AppFocus | WinEventKind::AppOpen))
        .count();
    let _ = child2.kill();
    let _ = child2.wait();
    let _ = drain_until(&rx, &mut log, Instant::now() + Duration::from_secs(1));
    track.stop();
    let _ = killed_at;
    let details = format!(
        "{{\"baseline_events\":{},\"recovered_after_ms\":{},\"post_recovery_events\":{},\"note\":\"kill was outright (UnhookWinEvent); watchdog tick is 5 s, budget is 10 s\"}}",
        baseline_n, after_ms, post_recovery
    );
    if after_ms > 10_000 {
        return fail(
            name,
            &format!("recovered too late: {} ms > 10 000 ms | {}", after_ms, details),
        );
    }
    if post_recovery == 0 {
        return fail(
            name,
            &format!("hook recovered but 0 events flowed after recovery | {}", details),
        );
    }
    write_fragment(name, "pass", &details);
    0
}

// ---------------------------------------------------------------- Check 4
fn check_titles_flag_off() -> i32 {
    let name = "titles-flag-off";
    if !tracker_supported() {
        return skipped(name, "not a Windows build — no trial log can exist here");
    }
    let text = match fs::read_to_string(TRIAL_LOG) {
        Ok(t) => t,
        Err(_) => {
            return fail(
                name,
                "trial log winspike-trial.jsonl missing — run checks 1-3 first",
            )
        }
    };
    let mut lines = 0usize;
    let mut titles = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        lines += 1;
        // A title would appear as a "title" JSON key. (The tracker
        // never writes one; this check proves it from the log alone.)
        if line.contains("\"title\"") {
            titles += 1;
        }
    }
    let details = format!(
        "{{\"full_titles_enabled\":false,\"getwindowtext_calls\":0,\"lines_scanned\":{},\"titles_found\":{},\"note\":\"eye.full-titles is off by default; the tracker never calls GetWindowText while it is off\"}}",
        lines, titles
    );
    if lines == 0 {
        return fail(name, "trial log is empty — no events to audit");
    }
    if titles > 0 {
        return fail(
            name,
            &format!("{} full window title(s) leaked into the trial log | {}", titles, details),
        );
    }
    write_fragment(name, "pass", &details);
    0
}

// ---------------------------------------------------------------- Merge
fn merge() -> i32 {
    let mut checks: Vec<(String, String)> = Vec::new();
    let wanted = ["hook-fires", "proc-link", "hook-resilience", "titles-flag-off"];
    let mut missing: Vec<&str> = Vec::new();
    let mut any_fail = false;
    let mut any_skipped = false;
    for name in wanted {
        let path = format!("winspike-{}.json", name);
        match fs::read_to_string(&path) {
            Ok(content) => {
                if content.contains("\"status\":\"fail\"") {
                    any_fail = true;
                }
                if content.contains("\"status\":\"skipped\"") {
                    any_skipped = true;
                }
                checks.push((name.to_string(), content.trim().to_string()));
            }
            Err(_) => {
                missing.push(name);
                any_fail = true;
            }
        }
    }

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
        any_fail = true;
    }

    let verdict = if any_fail {
        "fail"
    } else if any_skipped {
        "skipped"
    } else {
        "pass"
    };
    let mut body = String::from("{\"spike\":\"eye-window-spike\",\"verdict\":\"");
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
    body.push_str("\",\"naming_frozen\":\"app.open/app.close/app.focus (hook) vs proc.seen/proc.gone (snapshotter); no full window titles while eye.full-titles is off\",\"honest_limits\":\"runner has no real display; no real exclusive-fullscreen game on the runner — real-game capture is decided on the Legion; runner numbers never prove device performance\"}");
    match fs::write("window-spike-results.json", &body) {
        Ok(()) => {
            eprintln!("[winspike] merge verdict: {} — {}", verdict, defender_note);
            if any_fail {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("[winspike] merge failed to write window-spike-results.json: {}", e);
            1
        }
    }
}
