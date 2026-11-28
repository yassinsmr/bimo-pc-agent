//! `bimo-hand-supervisor`: the elevated supervisor binary.
//!
//! Modes:
//! - default (supervisor): create the job, launch the worker (`--worker`)
//!   inside it, launch command children inside it, watch exec requests,
//!   restart the worker (max 3 unexpected restarts in 10 min), and stop
//!   commands in two levels (cooperative, then forced).
//! - `--worker`: the hand worker — heartbeat, stop file, ping/pong,
//!   supervisor-heartbeat watch. It never launches processes itself.
//! - `--slow-copy <src> <dst>`: a throttled transfer helper (proof 8.2):
//!   copies in 4 MiB chunks, pauses while the game-mode flag is raised,
//!   and exits at once when `hand.stop` appears.
//! - `--probe-grandchild <out>`: spawns a grandchild and writes its pid
//!   (proof 8.5: the grandchild must be in the job).
//!
//! A worker death caused by the supervisor's own `TerminateJobObject`
//! during a stop is EXPECTED (the supervisor knows it killed the job),
//! so it restarts the worker without counting against the 3-in-10-min
//! cap. Only UNEXPECTED worker exits count toward the cap.

use bimo_hand::control::HandControl;
use bimo_hand::executor::{
    exec_request_path, exec_result_path, exec_started_path, ExecRequest,
};
use bimo_hand::kill;
use bimo_hand::supervisor as sup;
use bimo_hand::{alert_event, read_json_file, utc_now_ms, utc_now_secs, write_json_file};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const MAX_RESTARTS: usize = 3;
const RESTART_WINDOW_SECS: u64 = 10 * 60;

fn main() {
    let _ = bimo_hand::win32::enable_debug_privilege();
    let args: Vec<String> = std::env::args().collect();
    let mut data_dir = PathBuf::from(".");
    let mut heartbeat_secs: u64 = 30;
    let mut worker = false;
    let mut slow_copy: Option<(String, String)> = None;
    let mut probe_grandchild: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--data-dir" => {
                i += 1;
                if i < args.len() {
                    data_dir = PathBuf::from(&args[i]);
                }
            }
            "--heartbeat-secs" => {
                i += 1;
                if i < args.len() {
                    heartbeat_secs = args[i].parse().unwrap_or(30);
                }
            }
            "--worker" => worker = true,
            "--slow-copy" => {
                if i + 2 < args.len() {
                    slow_copy = Some((args[i + 1].clone(), args[i + 2].clone()));
                    i += 2;
                }
            }
            "--probe-grandchild" => {
                i += 1;
                if i < args.len() {
                    probe_grandchild = Some(args[i].clone());
                }
            }
            "--help" | "-h" => {
                println!("bimo-hand-supervisor [--data-dir <dir>] [--heartbeat-secs <n>] [--worker]");
                println!("  --slow-copy <src> <dst>      throttled transfer helper (test)");
                println!("  --probe-grandchild <out>     spawn a grandchild, write its pid (test)");
                return;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some((src, dst)) = slow_copy {
        std::process::exit(run_slow_copy(&data_dir, &src, &dst));
    }
    if let Some(out) = probe_grandchild {
        std::process::exit(run_probe_grandchild(&data_dir, &out));
    }
    if worker {
        run_worker(&data_dir, heartbeat_secs);
        return;
    }
    std::process::exit(run_supervisor(&data_dir, heartbeat_secs));
}

// ---------------------------------------------------------------------------
// Test helpers (run inside the job)
// ---------------------------------------------------------------------------

/// Throttled copy: 4 MiB chunks, ~40 ms per chunk, pauses while the
/// game-mode flag (`hand.game-mode`) is raised, exits at once (code 3)
/// when `hand.stop` appears. The partial destination is left for the
/// supervisor to clean up (proof 8.2: `partial-cleaned`).
fn run_slow_copy(data_dir: &Path, src: &str, dst: &str) -> i32 {
    use std::io::{Read, Write};
    let mut input = match fs::File::open(src) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("slow-copy: open {}: {}", src, e);
            return 1;
        }
    };
    let mut output = match fs::File::create(dst) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("slow-copy: create {}: {}", dst, e);
            return 1;
        }
    };
    let mut buf = vec![0u8; 4 * 1024 * 1024];
    loop {
        // Cooperative stop: the stop file is the stop signal.
        if data_dir.join("hand.stop").exists() {
            return 3;
        }
        // Throttle while game mode is on (checked every chunk).
        while data_dir.join("hand.game-mode").exists() {
            std::thread::sleep(Duration::from_millis(200));
            if data_dir.join("hand.stop").exists() {
                return 3;
            }
        }
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if output.write_all(&buf[..n]).is_err() {
                    return 1;
                }
            }
            Err(_) => return 1,
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    let _ = output.flush();
    0
}

/// Spawn a grandchild (a `ping` that sleeps) and write its pid to `out`.
/// The grandchild is a child of this process, so — as a member of the job
/// — it is in the job too (proof 8.5: no escape).
fn run_probe_grandchild(data_dir: &Path, out: &str) -> i32 {
    let mut child = match std::process::Command::new("cmd.exe")
        .args(["/c", "ping", "-n", "120", "127.0.0.1"])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("probe-grandchild: spawn failed: {}", e);
            return 1;
        }
    };
    let pid = child.id();
    if fs::write(out, pid.to_string()).is_err() {
        return 1;
    }
    loop {
        if data_dir.join("hand.stop").exists() {
            let _ = child.kill();
            return 3;
        }
        match child.try_wait() {
            Ok(Some(_)) => return 0,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => return 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Worker mode
// ---------------------------------------------------------------------------

fn run_worker(data_dir: &Path, heartbeat_secs: u64) {
    let ctl = HandControl::new(data_dir, heartbeat_secs);
    let _ = fs::create_dir_all(data_dir);
    let _ = fs::write(
        data_dir.join("hand.worker-pid"),
        std::process::id().to_string(),
    );
    let _ = write_json_file(
        &data_dir.join("hand.worker-pid.json"),
        &json!({"pid": std::process::id(), "ts": utc_now_secs()}),
    );
    let mut stale_warned = false;
    // One beat per heartbeat interval (production 30 s, test 2 s); the
    // control loop itself still polls every 250 ms.
    let mut last_beat = Instant::now() - Duration::from_secs(heartbeat_secs + 1);
    loop {
        if data_dir.join("hand.worker-exit").exists()
            || data_dir.join("hand.supervisor-exit").exists()
        {
            break;
        }
        // Ping/pong: answer a reconnect attempt unless paused.
        if data_dir.join("hand.ping").exists()
            && !data_dir.join("hand.pause-heartbeat").exists()
        {
            let _ = write_json_file(
                &data_dir.join("hand.pong"),
                &json!({"ts": utc_now_secs()}),
            );
            let _ = fs::remove_file(data_dir.join("hand.ping"));
        }
        if ctl.stop_present() {
            let reason = ctl.stop_reason().unwrap_or_else(|| "hand.stop".to_string());
            // Council 35 cond. 1 (single arming authority, c81): the
            // worker consults the same TTL exemption the monitor loop
            // consults, keyed on the running command's kind published
            // by the supervisor in `hand.current-command.json`. A TTL
            // stop for an exempt kind is NEVER applied here — the
            // monitor loop consumes it. No current command (idle) or
            // an unreadable record => apply as before (fail-closed
            // toward stopping; the monitor loop's defence-in-depth
            // cleanup covers the exempt case).
            if reason == "ttl" {
                if let Some(kind) = ctl.current_command_kind() {
                    if bimo_hand::update::ttl_kill_exempt(&kind) {
                        std::thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                }
            }
            let _ = ctl.apply_stop(&reason);
        } else if last_beat.elapsed() >= Duration::from_secs(heartbeat_secs) {
            if ctl.write_heartbeat().unwrap_or(false) {
                last_beat = Instant::now();
            }
        }
        // Mutual monitoring: warn when the supervisor heartbeat goes
        // stale past 2 beats (once per stale episode).
        if ctl.supervisor_heartbeat_stale() {
            if !stale_warned {
                ctl.record_supervisor_stale();
                stale_warned = true;
            }
        } else {
            stale_warned = false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// Supervisor mode
// ---------------------------------------------------------------------------

fn launch_worker(job: &sup::Job, data_dir: &Path, heartbeat_secs: u64) -> Result<u32, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let launched = sup::launch_in_job(
        job,
        &exe.to_string_lossy(),
        &[
            "--worker".to_string(),
            "--data-dir".to_string(),
            data_dir.to_string_lossy().to_string(),
            "--heartbeat-secs".to_string(),
            heartbeat_secs.to_string(),
        ],
        None,
    )?;
    Ok(launched.pid)
}

fn run_supervisor(data_dir: &Path, heartbeat_secs: u64) -> i32 {
    let ctl = HandControl::new(data_dir, heartbeat_secs);
    if let Err(e) = fs::create_dir_all(data_dir) {
        eprintln!("supervisor: create data dir: {}", e);
        return 1;
    }
    let job = match sup::create_job() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("supervisor: {}", e);
            return 1;
        }
    };
    let supervisor_elevated = sup::is_elevated();
    let mut worker_pid = match launch_worker(&job, data_dir, heartbeat_secs) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("supervisor: launch worker: {}", e);
            return 1;
        }
    };
    let mut restarts: Vec<u64> = Vec::new();
    let mut expected_worker_restart = false;
    let mut last_sup_hb = Instant::now() - Duration::from_secs(heartbeat_secs + 1);
    loop {
        if data_dir.join("hand.supervisor-exit").exists() {
            break;
        }
        // Supervisor heartbeat (mutual monitoring).
        if last_sup_hb.elapsed() >= Duration::from_secs(heartbeat_secs) {
            let _ = ctl.write_supervisor_heartbeat();
            last_sup_hb = Instant::now();
        }
        // Worker watch: restart on unexpected exit (max 3 in 10 min).
        if !sup::process_alive(worker_pid) {
            let now = utc_now_secs();
            if expected_worker_restart {
                // The supervisor itself killed the job during a stop:
                // expected, not counted against the cap.
                expected_worker_restart = false;
                match launch_worker(&job, data_dir, heartbeat_secs) {
                    Ok(pid) => worker_pid = pid,
                    Err(e) => {
                        eprintln!("supervisor: relaunch worker: {}", e);
                        return 1;
                    }
                }
            } else {
                restarts.retain(|t| now < t.saturating_add(RESTART_WINDOW_SECS));
                if restarts.len() >= MAX_RESTARTS {
                    let _ = write_json_file(
                        &data_dir.join("hand.supervisor-gave-up"),
                        &json!({"ts": now, "restarts": restarts.len()}),
                    );
                    let _ = alert_event(
                        data_dir,
                        "supervisor-gave-up",
                        json!({"restarts": restarts.len()}),
                    );
                    eprintln!("supervisor: gave up after {} restarts", restarts.len());
                    return 1;
                }
                restarts.push(now);
                let _ = write_json_file(
                    &data_dir.join("hand.supervisor-restarts.json"),
                    &json!({"count": restarts.len(), "last_ts": now}),
                );
                match launch_worker(&job, data_dir, heartbeat_secs) {
                    Ok(pid) => worker_pid = pid,
                    Err(e) => {
                        eprintln!("supervisor: relaunch worker: {}", e);
                        return 1;
                    }
                }
            }
        }
        // One exec request at a time.
        if let Some(req) = next_request(data_dir) {
            let stop_expected = handle_request(&job, data_dir, &req, supervisor_elevated);
            if stop_expected {
                expected_worker_restart = true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    0
}

/// The next pending exec request (no result and not started yet).
fn next_request(data_dir: &Path) -> Option<ExecRequest> {
    let entries = fs::read_dir(data_dir).ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("hand.exec-request-") && n.ends_with(".json"))
        .collect();
    names.sort();
    for name in names {
        let id = name
            .trim_start_matches("hand.exec-request-")
            .trim_end_matches(".json");
        if exec_result_path(data_dir, id).exists() || exec_started_path(data_dir, id).exists() {
            continue;
        }
        let value = read_json_file(&exec_request_path(data_dir, id))?;
        if let Ok(req) = serde_json::from_value::<ExecRequest>(value) {
            return Some(req);
        }
    }
    None
}

/// Launch one request in the job and monitor it. Returns true when a stop
/// was initiated (the worker may die with the job — expected restart).
/// Map a stop reason string (from hand.stop) to the unified trigger.
fn trigger_from_reason(reason: &str) -> kill::StopTrigger {
    match reason {
        "ttl" => kill::StopTrigger::Ttl,
        "dead-man" => kill::StopTrigger::DeadMan,
        "guardian" => kill::StopTrigger::Guardian,
        _ => kill::StopTrigger::HandStop,
    }
}

/// Action-trigger file for one MSI request (8.1 phase B, run-42 fix):
/// `hand.stop-at-action-<id>.json` containing `{"action": "<name>"}`.
/// The monitor thread aborts the install as soon as the external UI
/// handler first reports that action — deterministic in install
/// progress, not in wall-clock time. Written by the self-test only;
/// consumed (deleted) when it fires, and deleted on normal completion
/// so a stale file can never abort a later request.
fn action_trigger_path(data_dir: &Path, id: &str) -> PathBuf {
    data_dir.join(format!("hand.stop-at-action-{}.json", id))
}

fn read_action_trigger(data_dir: &Path, id: &str) -> Option<String> {
    let v = read_json_file(&action_trigger_path(data_dir, id))?;
    v.get("action").and_then(|a| a.as_str()).map(|s| s.to_string())
}

/// v2 (cycle 41, condition 5): MSI install handling. MsiInstallProduct
/// runs in a dedicated thread inside the supervisor; this function is the
/// monitor thread: it watches hand.stop while the install thread is
/// blocked, and stops the install through kill::abort only. It never
/// launches msiexec.exe as a process to kill it, never kills msiexec.exe,
/// and never runs `net stop msiserver`.
fn handle_msi_request(req: &ExecRequest, ctl: &HandControl, data_dir: &Path, started_at: Instant, stale_stop: Option<&str>) -> bool {
    let msi_path = req.args.iter().find(|a| a.to_ascii_lowercase().ends_with(".msi")).cloned().unwrap_or_default();
    let name_substring = req.name_substring.clone().unwrap_or_default();
    let target_dir = req.install_dir.clone().unwrap_or_default();
    let pre_state = bimo_hand::msi::pre_command_state(req.product_code.as_deref(), &target_dir);
    let pre_msiexec: Vec<u32> = bimo_hand::win32::msiexec_processes().iter().map(|p| p.pid).collect();
    let (cancel, outcome_slot) = sup::run_msi_install_in_thread(msi_path.clone());
    let result_path = exec_result_path(data_dir, &req.id);
    loop {
        // Action-based cancel (8.1 phase B, run-42 fix): abort as soon
        // as the UI handler first reports the requested action. The
        // wall-clock trigger (hand.stop at 40% of the phase-A duration)
        // let the install outrun the cancel twice (runs 36/42:
        // last_action PublishProduct, return 0, product left
        // installed) — the trigger must be in install progress, not in
        // elapsed time. The monitor polls every 50 ms, so the abort
        // lands early inside the file-copy phase.
        let action_trigger = read_action_trigger(data_dir, &req.id);
        let action_fired = match &action_trigger {
            Some(a) => bimo_hand::msi::last_action().as_deref() == Some(a.as_str()),
            None => false,
        };
        if ctl.stop_present() || action_fired {
            if action_fired {
                let _ = fs::remove_file(action_trigger_path(data_dir, &req.id));
            }
            let reason = ctl.stop_reason().unwrap_or_else(|| "hand.stop".to_string());
            let _ = ctl.apply_stop(&reason);
            let outcome = kill::abort(
                kill::AbortTarget::Msi {
                    cancel: std::sync::Arc::clone(&cancel),
                    outcome: std::sync::Arc::clone(&outcome_slot),
                    product_code: req.product_code.clone(),
                    name_substring: name_substring.clone(),
                    target_dir: target_dir.clone(),
                    pre_msiexec_pids: pre_msiexec.clone(),
                },
                trigger_from_reason(&reason),
            );
            let _ = write_json_file(&result_path, &json!({
                "id": req.id, "status": outcome.status, "stop_ms": outcome.stop_ms,
                "stop_method": "msi-cancel", "tree_dead": outcome.tree_dead,
                "remaining_pids": outcome.remaining_pids, "handles_released": outcome.handles_released,
                "return_code": outcome.return_code, "forced_ms": outcome.forced_ms,
                "abort": outcome.to_json(), "pre_command_state": pre_state,
                "stale_stop_cleared": stale_stop,
                // (c78 merge note: the branch's "supervisor_rehash" line
                // is NOT carried here — main has no rehash variable; the
                // supervisor rehash gate is a branch-only defence-in-depth
                // layer, NOT ported in this merge. The executor hash gate
                // (§25.2/§39.3, kept in the executor.rs resolution) stays
                // the enforcement point. Open item, recorded in the dev log.)
                "trigger_action": action_trigger,
                "cancel_at_ms": started_at.elapsed().as_millis() as u64,
                "duration_ms": started_at.elapsed().as_millis() as u64,
            }));
            return false;
        }
        let last_beat = ctl.heartbeat_ts().unwrap_or_else(utc_now_secs);
        if ctl.deadman_check(last_beat) {
            let _ = ctl.apply_stop("dead-man");
            let outcome = kill::abort(
                kill::AbortTarget::Msi {
                    cancel: std::sync::Arc::clone(&cancel),
                    outcome: std::sync::Arc::clone(&outcome_slot),
                    product_code: req.product_code.clone(),
                    name_substring: name_substring.clone(),
                    target_dir: target_dir.clone(),
                    pre_msiexec_pids: pre_msiexec.clone(),
                },
                kill::StopTrigger::DeadMan,
            );
            let _ = write_json_file(&result_path, &json!({
                "id": req.id, "status": outcome.status, "stop_ms": outcome.stop_ms,
                "stop_method": "msi-cancel", "tree_dead": outcome.tree_dead,
                "remaining_pids": outcome.remaining_pids, "handles_released": outcome.handles_released,
                "return_code": outcome.return_code, "forced_ms": outcome.forced_ms,
                "abort": outcome.to_json(), "pre_command_state": pre_state,
                "stale_stop_cleared": stale_stop,
                "duration_ms": started_at.elapsed().as_millis() as u64,
            }));
            return false;
        }
        let mut done: Option<bimo_hand::msi::CancelOutcome> = None;
        if let Ok(slot) = outcome_slot.lock() {
            if let Some(o) = slot.as_ref() {
                    done = Some(bimo_hand::msi::CancelOutcome { return_code: o.return_code, cancel_ms: o.cancel_ms, total_ms: o.total_ms, handler_calls: o.handler_calls, handler_first_ms: o.handler_first_ms, internal_ui_prev: o.internal_ui_prev, external_ui_prev_non_null: o.external_ui_prev_non_null, cancelled: o.cancelled });
            }
        }
        if let Some(o) = done {
            // Normal completion without a trigger fire: drop any
            // action-trigger file so it can never abort a later request.
            let _ = fs::remove_file(action_trigger_path(data_dir, &req.id));
            let status = if o.return_code == 0 { "done" } else { "failed" };
            let _ = write_json_file(&result_path, &json!({
                "id": req.id, "status": status, "return_code": o.return_code,
                "cancel_ms": o.cancel_ms, "handler_calls": o.handler_calls,
                "pre_command_state": pre_state,
                "stale_stop_cleared": stale_stop,
                "duration_ms": started_at.elapsed().as_millis() as u64,
            }));
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Council 35 cond. 2 (c81; honesty fix, run-49 lesson): consume a
/// stop filed before this command started. A stop present at command
/// start is stale by definition — the command it could have armed
/// against is not this one — so it is cleared (with a matching
/// `hand.stopped` record, so the on-disk state cannot contradict the
/// fresh run) and its reason is returned for the result JSON. A stop
/// filed AFTER the command starts is never touched here; the monitor
/// loop arms it normally. When the stop file CANNOT be removed (e.g.
/// locked by another process), nothing is claimed: returns `None`
/// and leaves both files for the monitor loop, which retries the
/// bounded consumption and arms the stop instead of reporting a
/// clearance that never happened.
fn consume_stale_stop(ctl: &HandControl) -> Option<String> {
    if !ctl.stop_present() {
        return None;
    }
    let reason = ctl.stop_reason().unwrap_or_else(|| "hand.stop".to_string());
    if ctl.clear_stop().is_err() {
        return None;
    }
    let _ = ctl.clear_stopped_if_reason(&reason);
    Some(reason)
}

/// Council 35 cond. 3 (c81): bounded consumption of an ignored TTL
/// stop. `failures` counts consecutive failed `clear_stop` attempts
/// for the current stop file.
const TTL_CLEAR_MAX_RETRIES: u32 = 3;

enum IgnoredStopOutcome {
    /// The stop file was consumed; the run survives.
    Consumed,
    /// Consumption failed this poll; retry on the next poll.
    Retry,
    /// Consumption failed `TTL_CLEAR_MAX_RETRIES` times; arm the stop
    /// instead of spinning the monitor loop forever with no result.
    Arm,
}

fn consume_ignored_ttl_stop(ctl: &HandControl, failures: &mut u32) -> IgnoredStopOutcome {
    match ctl.clear_stop() {
        Ok(()) => {
            *failures = 0;
            IgnoredStopOutcome::Consumed
        }
        Err(_) => {
            *failures += 1;
            if *failures >= TTL_CLEAR_MAX_RETRIES {
                IgnoredStopOutcome::Arm
            } else {
                IgnoredStopOutcome::Retry
            }
        }
    }
}

fn handle_request(
    job: &sup::Job,
    data_dir: &Path,
    req: &ExecRequest,
    supervisor_elevated: bool,
) -> bool {
    let ctl = HandControl::new(data_dir, 30);
    // Council 35 cond. 2: consume a stale stop before launch.
    let stale_stop = consume_stale_stop(&ctl);
    // Council 35 cond. 1: publish the running command's kind so the
    // worker loop consults the same TTL exemption as the monitor loop.
    let _ = write_json_file(
        &data_dir.join(bimo_hand::control::CURRENT_COMMAND_FILE),
        &json!({"id": req.id, "kind": req.kind, "started_ts": utc_now_secs()}),
    );
    let result = handle_request_inner(job, data_dir, req, supervisor_elevated, stale_stop.as_deref());
    let _ = fs::remove_file(data_dir.join(bimo_hand::control::CURRENT_COMMAND_FILE));
    result
}

fn handle_request_inner(
    job: &sup::Job,
    data_dir: &Path,
    req: &ExecRequest,
    supervisor_elevated: bool,
    stale_stop: Option<&str>,
) -> bool {
    let ctl = HandControl::new(data_dir, 30);
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("bimo-hand-supervisor.exe"));
    let (program, args): (String, Vec<String>) = match req.kind.as_str() {
        "transfer" => (
            exe.to_string_lossy().to_string(),
            vec![
                "--slow-copy".to_string(),
                req.args.first().cloned().unwrap_or_default(),
                req.args.get(1).cloned().unwrap_or_default(),
                "--data-dir".to_string(),
                data_dir.to_string_lossy().to_string(),
            ],
        ),
        "probe-grandchild" => (
            exe.to_string_lossy().to_string(),
            vec![
                "--probe-grandchild".to_string(),
                req.grandchild_out.clone().unwrap_or_default(),
                "--data-dir".to_string(),
                data_dir.to_string_lossy().to_string(),
            ],
        ),
        _ => (req.program.clone(), req.args.clone()),
    };
    let started_at = Instant::now();
    // Council 34 cond. 3 (c80): the TTL exemption (`ttl_kill_exempt`)
    // is consulted only in the generic monitor loop below — this
    // dispatch guarantees MSI requests are kind "install" (never
    // exempt), so no check is needed in `handle_msi_request`.
    if req.kind == "install" && req.installer_kind.as_deref() == Some("msi") {
        return handle_msi_request(req, &ctl, data_dir, started_at, stale_stop);
    }
    let launched = match sup::launch_in_job(
        job,
        &program,
        &args,
        req.working_dir.as_deref(),
    ) {
        Ok(l) => l,
        Err(e) => {
            let _ = write_json_file(
                &exec_result_path(data_dir, &req.id),
                &json!({"status": "failed", "error": e, "supervisor_elevated": supervisor_elevated, "stale_stop_cleared": stale_stop}),
            );
            return false;
        }
    };
    let pid = launched.pid;
    let installer_elevated = sup::is_process_elevated(pid);
    // Orphan identity, captured while the root is alive (8.2b): the
    // --slow-copy root exits ~40 ms after hand.stop, before the 100 ms poll.
    let root_exe_path = bimo_hand::win32::exe_path(pid).unwrap_or_default();
    let root_window_start = bimo_hand::win32::process_creation_time(pid).unwrap_or(SystemTime::UNIX_EPOCH);
    let _ = write_json_file(
        &exec_started_path(data_dir, &req.id),
        &json!({
            "pid": pid,
            "started_ts_ms": utc_now_ms(),
            "supervisor_elevated": supervisor_elevated,
            "installer_elevated": installer_elevated,
        }),
    );
    let mut stop_initiated = false;
    // Council 34 cond. 3 (TTL dead letter, wired c80; hardened c81):
    // counts TTL stops this run survived because its kind is exempt.
    let mut ttl_stop_ignored = false;
    let mut ttl_stop_ignored_count: u32 = 0;
    // Council 35 cond. 3: consecutive failed `clear_stop` attempts
    // for the current stop; at TTL_CLEAR_MAX_RETRIES the stop is
    // armed instead of ignored.
    let mut ttl_clear_failures: u32 = 0;
    let mut ttl_stop_clear_failed = false;
    let mut grandchild_checked = false;
    loop {
        // Probe 8.5: once the grandchild pid file exists, verify the
        // grandchild is in the job, then stop the probe.
        if req.kind == "probe-grandchild" && !grandchild_checked {
            if let Some(out) = &req.grandchild_out {
                if let Ok(text) = fs::read_to_string(out) {
                    if let Ok(gpid) = text.trim().parse::<u32>() {
                        grandchild_checked = true;
                        let in_job = sup::is_process_in_job(gpid, job);
                        let count = sup::job_process_count(job);
                        let _ = job;
            let abort_outcome = kill::abort(
                kill::AbortTarget::Command {
                    root_pid: pid,
exe_path: root_exe_path.clone(),
                    window_start: root_window_start,
                    install_dir: None,
                },
                kill::StopTrigger::HandStop,
            );
            let outcome = sup::StopOutcome {
                method: abort_outcome.status,
                stop_ms: abort_outcome.stop_ms,
                tree_dead: abort_outcome.tree_dead,
                remaining_pids: abort_outcome.remaining_pids,
                handles_released: abort_outcome.handles_released,
            };
                        let _ = write_json_file(
                            &exec_result_path(data_dir, &req.id),
                            &json!({
                                "status": "done",
                                "grandchild_pid": gpid,
                                "grandchild_in_job": in_job,
                                "job_process_count": count,
                                "job_process_limit": sup::MAX_JOB_PROCESSES,
                                "stop_ms": outcome.stop_ms,
                                "stop_method": outcome.method,
                                "tree_dead": outcome.tree_dead,
                                "supervisor_elevated": supervisor_elevated,
                                "installer_elevated": installer_elevated,
                                "stale_stop_cleared": stale_stop,
                                "duration_ms": started_at.elapsed().as_millis() as u64,
                            }),
                        );
                        return outcome.method == "forced";
                    }
                }
            }
        }
        if ctl.stop_present() {
            let reason = ctl.stop_reason().unwrap_or_else(|| "hand.stop".to_string());
            // Council 34 cond. 3 (TTL dead letter, wired c80; single
            // arming authority c81): a TTL stop never kills a running
            // `update` — this arming path consults
            // `update::ttl_kill_exempt(req.kind)` before arming. The
            // worker loop consults the same rule against the published
            // current-command kind, so it never writes `hand.stopped`
            // for an ignored stop; the removal below is defence in
            // depth for a stop the worker applied before the rule was
            // consulted. The spent TTL stop is consumed so it cannot
            // kill the next command, and the ignore is recorded in
            // the result JSON (`ttl_stop_ignored` + count). Any other
            // reason, or a non-exempt kind, arms the stop exactly as
            // before. Council 35 cond. 3: when the stop file cannot be
            // removed, retries are bounded — after TTL_CLEAR_MAX_RETRIES
            // the stop is armed instead of ignored, and the arming is
            // recorded (`ttl_stop_clear_failed`).
            if reason == "ttl" && bimo_hand::update::ttl_kill_exempt(&req.kind) {
                match consume_ignored_ttl_stop(&ctl, &mut ttl_clear_failures) {
                    IgnoredStopOutcome::Consumed => {
                        ttl_stop_ignored = true;
                        ttl_stop_ignored_count += 1;
                        let _ = ctl.clear_stopped_if_reason("ttl");
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    IgnoredStopOutcome::Retry => {
                        std::thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                    IgnoredStopOutcome::Arm => {
                        ttl_stop_clear_failed = true;
                    }
                }
            }
            stop_initiated = true;
            let _ = ctl.apply_stop(&reason);
            let install_dir = req.install_dir.as_deref().map(Path::new);
            let _ = job;
            let abort_outcome = kill::abort(
                kill::AbortTarget::Command {
                    root_pid: pid,
                    exe_path: root_exe_path.clone(),
                    window_start: root_window_start,
                    install_dir: install_dir.map(|d| d.to_string_lossy().to_string()),
                },
                trigger_from_reason(&reason),
            );
            let abort_json = abort_outcome.to_json();
            let outcome = sup::StopOutcome {
                method: abort_outcome.status,
                stop_ms: abort_outcome.stop_ms,
                tree_dead: abort_outcome.tree_dead,
                remaining_pids: abort_outcome.remaining_pids,
                handles_released: abort_outcome.handles_released,
            };
            let mut partial_cleaned = false;
            if let Some(cleanup) = &req.cleanup_path {
                let p = Path::new(cleanup);
                if p.exists() {
                    let _ = fs::remove_file(p);
                    partial_cleaned = true;
                }
            }
            let _ = write_json_file(
                &exec_result_path(data_dir, &req.id),
                &json!({
                    "status": "stopped",
                    "stop_ms": outcome.stop_ms,
                    "stop_method": outcome.method,
                    "tree_dead": outcome.tree_dead,
                    "remaining_pids": outcome.remaining_pids,
                    "handles_released": outcome.handles_released,
                    "partial_cleaned": partial_cleaned,
                    "ttl_stop_clear_failed": ttl_stop_clear_failed,
                    "stale_stop_cleared": stale_stop,
"abort": abort_json,
                    "supervisor_elevated": supervisor_elevated,
                    "installer_elevated": installer_elevated,
                    "duration_ms": started_at.elapsed().as_millis() as u64,
                }),
            );
            return outcome.method == "forced";
        }
        if let Some(code) = sup::process_exit_code(pid) {
            let install_dir = req.install_dir.as_deref().map(Path::new);
            let handles_released = install_dir.map(bimo_hand::try_rename_dir).unwrap_or(true);
            let _ = write_json_file(
                &exec_result_path(data_dir, &req.id),
                &json!({
                    "status": if code == 0 { "done" } else { "failed" },
                    "exit_code": code,
                    "handles_released": handles_released,
                    // Council 34 cond. 3 (c80; hardened c81): true when
                    // a TTL stop was filed mid-run and ignored because
                    // this kind is exempt — the observable proof the
                    // arming path consulted `ttl_kill_exempt`. The
                    // count is the number of TTL stops ignored this
                    // run (council 35 cond. 1 wants a second stop in
                    // the same run proved too).
                    "ttl_stop_ignored": ttl_stop_ignored,
                    "ttl_stop_ignored_count": ttl_stop_ignored_count,
                    "stale_stop_cleared": stale_stop,
                    "supervisor_elevated": supervisor_elevated,
                    "installer_elevated": installer_elevated,
                    "duration_ms": started_at.elapsed().as_millis() as u64,
                }),
            );
            return false;
        }
        if data_dir.join("hand.supervisor-exit").exists() {
            return stop_initiated;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "bimo-hand-sup-test-{}-{}",
            std::process::id(),
            n
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ignored_ttl_stop_consumed_and_counter_reset() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        ctl.write_stop("ttl").unwrap();
        let mut failures = 0u32;
        assert!(matches!(
            consume_ignored_ttl_stop(&ctl, &mut failures),
            IgnoredStopOutcome::Consumed
        ));
        assert_eq!(failures, 0);
        assert!(!ctl.stop_present());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ignored_ttl_stop_arms_after_bounded_retries() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        // A directory in place of the stop file makes every
        // `clear_stop` fail (remove_file on a directory errors).
        fs::create_dir_all(dir.join("hand.stop")).unwrap();
        let mut failures = 0u32;
        assert!(matches!(
            consume_ignored_ttl_stop(&ctl, &mut failures),
            IgnoredStopOutcome::Retry
        ));
        assert_eq!(failures, 1);
        assert!(matches!(
            consume_ignored_ttl_stop(&ctl, &mut failures),
            IgnoredStopOutcome::Retry
        ));
        assert_eq!(failures, 2);
        assert!(matches!(
            consume_ignored_ttl_stop(&ctl, &mut failures),
            IgnoredStopOutcome::Arm
        ));
        assert_eq!(failures, TTL_CLEAR_MAX_RETRIES);
        // A later success resets the counter.
        fs::remove_dir_all(dir.join("hand.stop")).unwrap();
        ctl.write_stop("ttl").unwrap();
        assert!(matches!(
            consume_ignored_ttl_stop(&ctl, &mut failures),
            IgnoredStopOutcome::Consumed
        ));
        assert_eq!(failures, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_stop_consumed_with_matching_stopped_record() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        ctl.write_stop("ttl").unwrap();
        ctl.apply_stop("ttl").unwrap();
        assert_eq!(consume_stale_stop(&ctl).as_deref(), Some("ttl"));
        assert!(!ctl.stop_present());
        assert!(ctl.stopped_info().is_none());
        // Nothing present: None.
        assert_eq!(consume_stale_stop(&ctl), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_stop_not_claimed_when_clear_fails() {
        let dir = test_dir();
        let ctl = HandControl::new(&dir, 2);
        // A directory in place of the stop file makes `clear_stop`
        // fail — the stale stop must NOT be reported as consumed.
        ctl.write_stop("ttl").unwrap();
        fs::remove_file(dir.join("hand.stop")).unwrap();
        fs::create_dir_all(dir.join("hand.stop")).unwrap();
        ctl.apply_stop("ttl").unwrap();
        assert_eq!(consume_stale_stop(&ctl), None);
        // Both files are left for the monitor loop.
        assert!(dir.join("hand.stop").exists());
        assert!(ctl.stopped_info().is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
