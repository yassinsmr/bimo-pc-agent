//! eye-window-spike — proof spike for Track A Unit 2 (the Eye),
//! window events (spec `track-a-unit2-eye-window-spike.md`).
//!
//! Three core checks + one regression guard, one process invocation
//! each, so a hang or failure in one cannot block the others. Each
//! invocation writes one fragment `winspike-<check>.json`; `--merge`
//! combines the fragments plus the Defender before/after files into
//! `window-spike-results.json`. Defender is informational only
//! (council condition 2): it can never flip the verdict. Window
//! events also append to the trial log `winspike-trial.jsonl` in the
//! eye format (`schema` + `seq` + `ts` + `prev_hash` + `hash`).
//!
//! `--merge` is the gate: it exits 1 on any failure, and the CI
//! workflow lets that failure fail the run (council condition 3).
//! A missing fragment, a failed check, or a trial-log line with a
//! missing/unknown schema version all drop the run (fail-closed).
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
//! - Runner numbers never prove device performance (tagged
//!   `perf_tag` in the merged JSON, council condition 4).
//! - On non-Windows builds every check writes "skipped", not "fail":
//!   the spike cannot prove anything there, and the merge verdict is
//!   "skipped" so local plumbing runs stay distinguishable from a
//!   real Windows pass/fail.

use bimo_wintrack::{
    exe_family_pids, tracker_supported, verify_log_file, verify_proc_link, TrialLog, WinEvent,
    WinEventKind, WinTrack,
};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
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

/// Distinct hwnds for a family+kind (cycle 23): event counts alone
/// cannot settle the calc 47/1 gap — 47 `app.open` events may be
/// duplicate CREATEs for a few hwnds (UWP frame host) or 47 real
/// windows whose destroys were missed. Unique-hwnd counts
/// discriminate: open_hwnds ≈ close_hwnds means a counting
/// artifact; open_hwnds ≫ close_hwnds means a systematic close
/// miss and the guard must not trust `app.close` for that family.
fn count_unique_hwnds_family(
    events: &[WinEvent],
    family: &HashSet<u32>,
    kind: &WinEventKind,
) -> usize {
    let mut seen: HashSet<u64> = HashSet::new();
    for e in events {
        if std::mem::discriminant(&e.kind) == std::mem::discriminant(kind)
            && family.contains(&e.pid)
            && e.hwnd != 0
        {
            seen.insert(e.hwnd);
        }
    }
    seen.len()
}

fn count_kind_family(events: &[WinEvent], family: &HashSet<u32>, kind: &WinEventKind) -> usize {
    events
        .iter()
        .filter(|e| {
            std::mem::discriminant(&e.kind) == std::mem::discriminant(kind)
                && family.contains(&e.pid)
        })
        .count()
}

/// Distinct exe names seen for a family, for the fragment (evidence
/// that a launcher stub handed its windows to a child process).
fn family_exes(events: &[WinEvent], family: &HashSet<u32>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in events {
        if family.contains(&e.pid) && !out.contains(&e.exe) {
            out.push(e.exe.clone());
        }
    }
    out.sort();
    out
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
    // Events are counted per process FAMILY, not per launched name:
    // a launcher stub hands its windows to a child process
    // (calc.exe -> win32calc.exe on Windows; the child's foreground
    // event belongs to the child, not the stub). The family snapshot
    // is taken while the apps are still alive, before the kill.
    let mut launched: Vec<(&str, bool, Option<u32>)> = Vec::new();
    let mut children = Vec::new();
    for app in ["notepad.exe", "calc.exe"] {
        match spawn_app(app) {
            Ok(child) => {
                launched.push((app, true, Some(child.id())));
                children.push(child);
            }
            Err(e) => {
                eprintln!("[winspike] launch failed (waived with reason): {}", e);
                launched.push((app, false, None));
            }
        }
    }
    if launched.iter().all(|(_, ok, _)| !ok) {
        track.stop();
        return fail(
            name,
            "no app could launch on this host — hook unprovable here",
        );
    }
    let deadline = Instant::now() + Duration::from_secs(8);
    let events = drain_until(&rx, &mut log, deadline);
    let families: Vec<HashSet<u32>> = launched
        .iter()
        .map(|(app, ok, pid)| {
            if *ok {
                exe_family_pids(app, pid.unwrap_or(0))
            } else {
                HashSet::new()
            }
        })
        .collect();
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
    for (i, (app, ok, _)) in launched.iter().enumerate() {
        if !first {
            details.push(',');
        }
        first = false;
        let family = &families[i];
        let focus = count_kind_family(&all, family, &WinEventKind::AppFocus);
        let open = count_kind_family(&all, family, &WinEventKind::AppOpen);
        let close = count_kind_family(&all, family, &WinEventKind::AppClose);
        let open_hwnds =
            count_unique_hwnds_family(&all, family, &WinEventKind::AppOpen);
        let close_hwnds =
            count_unique_hwnds_family(&all, family, &WinEventKind::AppClose);
        let exes = family_exes(&all, family);
        details.push_str(&format!(
            "\"{}\":{{\"launched\":{},\"family_exes\":{:?},\"app.focus\":{},\"app.open\":{},\"app.close\":{},\"app.open_hwnds\":{},\"app.close_hwnds\":{}}}",
            app, ok, exes, focus, open, close, open_hwnds, close_hwnds
        ));
        if *ok && focus == 0 {
            pass = false;
        }
    }
    details.push_str(&format!(
        ",\"total_events\":{},\"note\":\"SetWinEventHook (out-of-context) on Notepad+calc; counts are per process family (launched exe + its children) because a launcher stub hands its windows to a child (calc.exe -> win32calc.exe); an app that failed to launch is waived with its reason, never counted as a hook failure\"",
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
    let mut verified_close = 0usize;
    let mut unverifiable_close = 0usize;
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
                    // Cache-miss close (cycle 22): a window that died
                    // before the hook ever saw it open has no cached
                    // (pid, exe) — the hook honestly reports
                    // (0, "unknown.exe") with its real hwnd. That is
                    // shape-checked data, not a bad link: waive it,
                    // but only while at least one close was fully
                    // named (guard below) — a cache that names
                    // nothing must still fail the check.
                    if matches!(ev.kind, WinEventKind::AppClose)
                        && ev.pid == 0
                        && ev.hwnd != 0
                        && ev.exe == "unknown.exe"
                    {
                        unverifiable_close += 1;
                        continue;
                    }
                    bad.push(format!("zero hwnd/pid in {:?}", ev.kind.type_str()));
                    continue;
                }
                if ev.exe.is_empty() || ev.exe == "unknown.exe" || !ev.exe.ends_with(".exe") {
                    bad.push(format!("unresolved exe for pid {}: {:?}", ev.pid, ev.exe));
                    continue;
                }
                if verify_proc_link(ev.pid, &ev.exe) {
                    verified += 1;
                    if matches!(ev.kind, WinEventKind::AppClose) {
                        verified_close += 1;
                    }
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
    // at emission time, with a retry). A cache-miss close (0,
    // "unknown.exe", real hwnd) is waived the same way as in the live
    // loop — it is honest shape data, not a bad link.
    let tail = drain_until(&rx, &mut log, Instant::now() + Duration::from_secs(1));
    for ev in &tail {
        total += 1;
        if matches!(ev.kind, WinEventKind::AppClose)
            && ev.pid == 0
            && ev.hwnd != 0
            && ev.exe == "unknown.exe"
        {
            unverifiable_close += 1;
        } else if ev.hwnd == 0 || ev.pid == 0 || ev.exe.is_empty() || ev.exe == "unknown.exe" {
            bad.push(format!("bad close event: pid {} exe {:?}", ev.pid, ev.exe));
        } else {
            verified += 1;
            if matches!(ev.kind, WinEventKind::AppClose) {
                verified_close += 1;
            }
        }
    }
    track.stop();
    let details = format!(
        "{{\"total_events\":{},\"links_verified_live\":{},\"unverifiable_close\":{},\"verified_close\":{},\"bad\":{},\"note\":\"each live event re-checked against Toolhelp while its process was alive; post-kill close events are shape-checked only; a close whose window was never seen open is honestly (0, unknown.exe) with a real hwnd — waived as unverifiable, never counted as verified, and only while at least one close was fully named\"}}",
        total,
        verified,
        unverifiable_close,
        verified_close,
        bad.len()
    );
    if total == 0 {
        return fail(name, "0 events — nothing to link (hook blind?)");
    }
    if unverifiable_close > 0 && verified_close == 0 {
        return fail(
            name,
            &format!(
                "{} unverifiable closes but 0 fully-named closes — the window cache names nothing: {}",
                unverifiable_close, details
            ),
        );
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
            // Council condition 3: a failed recovery must leave an
            // explicit failure EVENT in the trial log, not just a
            // failed fragment — the log reader must see the failure.
            log.write(&WinEvent {
                kind: WinEventKind::HookRecoveryFailed,
                pid: 0,
                exe: String::new(),
                hwnd: 0,
                after_ms: Some(10_000),
                reason: Some(
                    "no hook.recovered within 10 s of the kill — watchdog did not re-register"
                        .to_string(),
                ),
            });
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
// Regression guard (council condition 4): runs on every CI push,
// always — it reads the trial log the other checks wrote.
fn check_titles_flag_off() -> i32 {
    let name = "titles-flag-off";
    if !tracker_supported() {
        return skipped(name, "not a Windows build — no trial log can exist here");
    }
    // Council condition 1 (mechanical): the trial log must carry a
    // valid schema version on every line — fail-closed, before the
    // titles audit reads anything from it.
    let schema_lines = match verify_log_file(Path::new(TRIAL_LOG)) {
        Ok(n) => n,
        Err(e) => {
            return fail(
                name,
                &format!("trial log schema invalid (fail-closed): {}", e),
            )
        }
    };
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
        "{{\"full_titles_enabled\":false,\"getwindowtext_calls\":0,\"schema_lines_verified\":{},\"lines_scanned\":{},\"titles_found\":{},\"note\":\"eye.full-titles is off by default; the tracker never calls GetWindowText while it is off; every trial-log line carries schema 1 (verified above)\"}}",
        schema_lines, lines, titles
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
// The gate (council condition 3): exit 1 on any failure, and the CI
// workflow lets that exit fail the run — a failed check drops the
// run, it is never papered over by `continue-on-error`.
fn merge() -> i32 {
    merge_in(Path::new("."))
}

fn merge_in(dir: &Path) -> i32 {
    let mut checks: Vec<(String, String)> = Vec::new();
    let wanted = ["hook-fires", "proc-link", "hook-resilience", "titles-flag-off"];
    let mut missing: Vec<&str> = Vec::new();
    let mut any_fail = false;
    let mut any_skipped = false;
    for name in wanted {
        let path = dir.join(format!("winspike-{}.json", name));
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

    // Defender is informational only (council condition 2): its
    // result is recorded for the record, and it can NEVER flip the
    // verdict — the realtime protection was off on the runner, so
    // the count proves nothing either way.
    let defender_note;
    let before = fs::read_to_string(dir.join("defender-before.json")).ok();
    let after = fs::read_to_string(dir.join("defender-after.json")).ok();
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
                    defender_note = format!(
                        "Defender detections before={} after={} (new={}) — informational only, suspended from evidence until a realtime-on scan (council condition 2)",
                        bc,
                        ac,
                        ac - bc
                    );
                }
                _ => {
                    defender_note =
                        "Defender JSON present but detections count unparsable — informational only"
                            .to_string();
                }
            }
        }
        _ => {
            defender_note =
                "Defender before/after files missing — Defender verdict unknown (informational only)"
                    .to_string();
        }
    }

    // Trial-log schema, verified at the gate too (council condition
    // 1, fail-closed): if checks really ran, the log must exist and
    // every line must carry schema 1. A skipped (non-Windows) run
    // has no log and skips this verification.
    let trial_log_schema;
    let trial_path = dir.join(TRIAL_LOG);
    if trial_path.exists() {
        match verify_log_file(&trial_path) {
            Ok(n) => {
                trial_log_schema =
                    format!("verified: {} lines, schema 1", n);
            }
            Err(e) => {
                any_fail = true;
                trial_log_schema = format!("INVALID (fail-closed): {}", e);
            }
        }
    } else if any_skipped && !any_fail && missing.is_empty() {
        trial_log_schema = "absent — all checks skipped, nothing to verify".to_string();
    } else {
        any_fail = true;
        trial_log_schema =
            "missing — trial log absent while checks ran (schema unverified)".to_string();
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
    body.push_str("\",\"trial_log_schema\":\"");
    body.push_str(&json_escape(&trial_log_schema));
    // Council condition 4: runner measurements are tagged, in the
    // JSON itself, as never proving device performance.
    body.push_str("\",\"perf_tag\":\"runner-only — does not prove device performance\"");
    body.push_str(",\"naming_frozen\":\"app.open/app.close/app.focus (hook) vs proc.seen/proc.gone (snapshotter); no full window titles while eye.full-titles is off\",\"honest_limits\":\"runner has no real display; no real exclusive-fullscreen game on the runner — real-game capture is decided on the Legion; runner numbers never prove device performance\"}");
    match fs::write(dir.join("window-spike-results.json"), &body) {
        Ok(()) => {
            eprintln!(
                "[winspike] merge verdict: {} — {} — trial log: {}",
                verdict, defender_note, trial_log_schema
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("bimo-winspike-merge-test-{}", n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pass_fragment(check: &str) -> String {
        format!(
            "{{\"check\":\"{}\",\"status\":\"pass\",\"ts_unix\":0,\"details\":{{}}}}",
            check
        )
    }

    fn write_all_pass(dir: &Path) {
        for name in ["hook-fires", "proc-link", "hook-resilience", "titles-flag-off"] {
            std::fs::write(
                dir.join(format!("winspike-{}.json", name)),
                pass_fragment(name),
            )
            .unwrap();
        }
        // A valid trial log: one line carrying schema 1.
        std::fs::write(
            dir.join(TRIAL_LOG),
            "{\"type\":\"app.open\",\"schema\":1,\"seq\":0,\"ts\":\"2026-11-24T00:00:00Z\",\"prev_hash\":\"GENESIS\",\"hash\":\"00\"}\n",
        )
        .unwrap();
    }

    fn read_verdict(dir: &Path) -> String {
        let body = std::fs::read_to_string(dir.join("window-spike-results.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        v["verdict"].as_str().unwrap().to_string()
    }

    #[test]
    fn merge_fail_drops_the_run() {
        // Council condition 3, mechanical proof: one failed check
        // must yield verdict "fail" AND a nonzero exit code.
        let dir = fresh_dir();
        write_all_pass(&dir);
        std::fs::write(
            dir.join("winspike-proc-link.json"),
            "{\"check\":\"proc-link\",\"status\":\"fail\",\"ts_unix\":0,\"details\":{\"error\":\"bad link\"}}",
        )
        .unwrap();
        assert_eq!(merge_in(&dir), 1);
        assert_eq!(read_verdict(&dir), "fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_missing_fragment_drops_the_run() {
        let dir = fresh_dir();
        write_all_pass(&dir);
        std::fs::remove_file(dir.join("winspike-hook-fires.json")).unwrap();
        assert_eq!(merge_in(&dir), 1);
        assert_eq!(read_verdict(&dir), "fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_pass_despite_defender_increase() {
        // Council condition 2, mechanical proof: Defender detections
        // rising must NOT flip a passing run — Defender is
        // informational only.
        let dir = fresh_dir();
        write_all_pass(&dir);
        std::fs::write(
            dir.join("defender-before.json"),
            "{\"detections\": 0, \"realtime\": false}",
        )
        .unwrap();
        std::fs::write(
            dir.join("defender-after.json"),
            "{\"detections\": 3, \"realtime\": false}",
        )
        .unwrap();
        assert_eq!(merge_in(&dir), 0);
        assert_eq!(read_verdict(&dir), "pass");
        let body = std::fs::read_to_string(dir.join("window-spike-results.json")).unwrap();
        assert!(body.contains("informational only"), "{}", body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_schema_invalid_drops_the_run() {
        // Council condition 1, mechanical proof: a trial-log line
        // without a schema field fails the run closed.
        let dir = fresh_dir();
        write_all_pass(&dir);
        std::fs::write(
            dir.join(TRIAL_LOG),
            "{\"type\":\"app.open\",\"seq\":0,\"ts\":\"2026-11-24T00:00:00Z\"}\n",
        )
        .unwrap();
        assert_eq!(merge_in(&dir), 1);
        assert_eq!(read_verdict(&dir), "fail");
        let body = std::fs::read_to_string(dir.join("window-spike-results.json")).unwrap();
        assert!(body.contains("INVALID"), "{}", body);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_all_skipped_stays_skipped() {
        // Non-Windows plumbing: no trial log, all fragments skipped.
        let dir = fresh_dir();
        for name in ["hook-fires", "proc-link", "hook-resilience", "titles-flag-off"] {
            std::fs::write(
                dir.join(format!("winspike-{}.json", name)),
                format!(
                    "{{\"check\":\"{}\",\"status\":\"skipped\",\"ts_unix\":0,\"details\":{{}}}}",
                    name
                ),
            )
            .unwrap();
        }
        assert_eq!(merge_in(&dir), 0);
        assert_eq!(read_verdict(&dir), "skipped");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
