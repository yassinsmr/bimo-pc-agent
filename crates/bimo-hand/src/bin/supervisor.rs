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

/// v2 (cycle 41, condition 5): MSI install handling. MsiInstallProduct
/// runs in a dedicated thread inside the supervisor; this function is the
/// monitor thread: it watches hand.stop while the install thread is
/// blocked, and stops the install through kill::abort only. It never
/// launches msiexec.exe as a process to kill it, never kills msiexec.exe,
/// and never runs `net stop msiserver`.
fn handle_msi_request(req: &ExecRequest, ctl: &HandControl, data_dir: &Path, started_at: Instant) -> bool {
    let msi_path = req.args.iter().find(|a| a.to_ascii_lowercase().ends_with(".msi")).cloned().unwrap_or_default();
    let name_substring = req.name_substring.clone().unwrap_or_default();
    let target_dir = req.install_dir.clone().unwrap_or_default();
    let pre_state = bimo_hand::msi::pre_command_state(req.product_code.as_deref(), &target_dir);
    let pre_msiexec: Vec<u32> = bimo_hand::win32::msiexec_processes().iter().map(|p| p.pid).collect();
    let (cancel, outcome_slot) = sup::run_msi_install_in_thread(msi_path.clone());
    let result_path = exec_result_path(data_dir, &req.id);
    loop {
        if ctl.stop_present() {
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
            let status = if o.return_code == 0 { "done" } else { "failed" };
            let _ = write_json_file(&result_path, &json!({
                "id": req.id, "status": status, "return_code": o.return_code,
                "cancel_ms": o.cancel_ms, "handler_calls": o.handler_calls,
                "pre_command_state": pre_state,
                "duration_ms": started_at.elapsed().as_millis() as u64,
            }));
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn handle_request(
    job: &sup::Job,
    data_dir: &Path,
    req: &ExecRequest,
    supervisor_elevated: bool,
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
    if req.kind == "install" && req.installer_kind.as_deref() == Some("msi") {
        return handle_msi_request(req, &ctl, data_dir, started_at);
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
                &json!({"status": "failed", "error": e, "supervisor_elevated": supervisor_elevated}),
            );
            return false;
        }
    };
    let pid = launched.pid;
    let installer_elevated = sup::is_process_elevated(pid);
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
                    exe_path: bimo_hand::win32::exe_path(pid).unwrap_or_default(),
                    window_start: bimo_hand::win32::process_creation_time(pid).unwrap_or(SystemTime::UNIX_EPOCH),
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
                                "duration_ms": started_at.elapsed().as_millis() as u64,
                            }),
                        );
                        return outcome.method == "forced";
                    }
                }
            }
        }
        if ctl.stop_present() {
            stop_initiated = true;
            let reason = ctl.stop_reason().unwrap_or_else(|| "hand.stop".to_string());
            let _ = ctl.apply_stop(&reason);
            let install_dir = req.install_dir.as_deref().map(Path::new);
            let _ = job;
            let abort_outcome = kill::abort(
                kill::AbortTarget::Command {
                    root_pid: pid,
                    exe_path: bimo_hand::win32::exe_path(pid).unwrap_or_default(),
                    window_start: bimo_hand::win32::process_creation_time(pid).unwrap_or(SystemTime::UNIX_EPOCH),
                    install_dir: install_dir.map(|d| d.to_string_lossy().to_string()),
                },
                trigger_from_reason(&reason),
            );
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
                    "abort": abort_outcome.to_json(),
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
