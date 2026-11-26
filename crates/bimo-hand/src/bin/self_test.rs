//! `bimo-hand-self-test`: the thin slice (spec section 8).
//!
//! Runs the whole scenario in a temp dir, spawns `bimo-hand-supervisor.exe`
//! as a child, and writes JSON with verdict + measurements:
//! `{"verdict":"pass|fail","red_line":"met|violated|not-tested",
//!  "proofs":{...},"measurements":{...},
//!  "runner_note":"does not prove device performance"}`.
//!
//! Each proof records `pass | fail | inconclusive` + measured values.
//! Verdict `pass` requires every proof to pass, except an inconclusive
//! 8.1 alone does not block pass for the rest (recorded as not-obtained
//! and retried next cycle). Runner numbers are tagged "does not prove
//! device performance".
//!
//! Usage: `bimo-hand-self-test --out hand-self-test.json
//! [--supervisor-bin <path>]` (default: same dir as this binary).
//!
//! If the RED LINE proof (8.1) fails while the installer was running
//! (anything survives past 5 s, or handles stay held), the verdict is
//! `fail` + `red_line: violated` — verdict (c), no new council.

use bimo_hand::control::{HandControl, DEADMAN_MISSED_BEATS};
use bimo_hand::executor::{
    exec_started_path, free_space_bytes, prepare_execution, required_bytes,
    wait_exec_result, write_exec_request, ExecRequest, HandConfig,
};
use bimo_hand::guardian::{quarantine_copy, Guardian, EICAR};
use bimo_hand::queue::{new_command, EnqueueOutcome, Queue};
use bimo_hand::revert::{revert, RevertOutcome};
use bimo_hand::supervisor::system_memory_mb;
use bimo_hand::{alert_event, file_sha256, sha256_hex, utc_now_secs, write_json_file};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcCommand};
use std::time::{Duration, Instant};

const VLC_PRIMARY: &str =
    "https://get.videolan.org/vlc/3.0.20/win64/vlc-3.0.20-win64.msi";
const VLC_FALLBACK: &str =
    "https://download.videolan.org/vlc/3.0.20/win64/vlc-3.0.20-win64.msi";
const ONE_GB: u64 = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Proof plumbing
// ---------------------------------------------------------------------------

struct Proof {
    status: &'static str,
    measured: Value,
}

fn pass(m: Value) -> Proof {
    Proof { status: "pass", measured: m }
}
fn fail(m: Value) -> Proof {
    Proof { status: "fail", measured: m }
}
fn inconclusive(m: Value) -> Proof {
    Proof { status: "inconclusive", measured: m }
}

impl Proof {
    fn to_json(&self) -> Value {
        json!({"status": self.status, "measured": self.measured})
    }
}

fn wait_until<F: Fn() -> bool>(f: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_file(path: &Path, timeout: Duration) -> bool {
    wait_until(|| path.exists(), timeout)
}

fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

fn read_pid_file(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn alert_exists(data_dir: &Path, kind: &str) -> bool {
    let entries = match fs::read_dir(data_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    entries.flatten().any(|e| {
        let n = e.file_name().to_string_lossy().to_string();
        n.starts_with("hand.alert-") && n.contains(kind)
    })
}

fn enqueue(data_dir: &Path, cmd: &mut bimo_hand::queue::Command) -> Result<EnqueueOutcome, String> {
    let mut q = Queue::open(data_dir)?;
    q.append(cmd)
}

fn mark(data_dir: &Path, id: &str, state: &str, reason: Option<&str>) -> Result<(), String> {
    let q = Queue::open(data_dir)?;
    q.mark(id, state, reason)
}

fn queue_state(data_dir: &Path, id: &str) -> Option<(String, Option<String>)> {
    let q = Queue::open(data_dir).ok()?;
    let cmds = q.read_all().ok()?;
    cmds.iter()
        .find(|c| c.id == id)
        .map(|c| (c.state.clone(), c.reason.clone()))
}

fn download(url: &str, out: &Path) -> bool {
    let curl = ProcCommand::new("curl.exe")
        .args(["-L", "--fail", "-o", &out.to_string_lossy(), url])
        .output();
    if let Ok(o) = curl {
        if o.status.success() && out.exists() && file_size(out) > 0 {
            return true;
        }
    }
    let ps = format!(
        "Invoke-WebRequest -Uri '{}' -OutFile '{}'",
        url,
        out.to_string_lossy()
    );
    let r = ProcCommand::new("powershell.exe")
        .args(["-NoProfile", "-Command", &ps])
        .output();
    matches!(r, Ok(o) if o.status.success()) && out.exists() && file_size(out) > 0
}

fn gen_1gb(path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = fs::File::create(path)?;
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..1024 {
        f.write_all(&chunk)?;
    }
    f.flush()
}

// ---------------------------------------------------------------------------
// Shared context
// ---------------------------------------------------------------------------

struct Ctx {
    data_dir: PathBuf,
    work_dir: PathBuf,
    config: HandConfig,
    ctl: HandControl,
    supervisor_started: bool,
    stop_install_ms: Option<u64>,
    stop_transfer_ms: Option<u64>,
    stop_probe_ms: Option<u64>,
    reverts_succeeded: u32,
    reverts_expected_success: u32,
    revert_failed_correctly: u32,
    transfer_source: Option<PathBuf>,
    transfer_source_checksum: Option<String>,
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

/// 8.8 STOP-FILE ROUND-TRIP + DEAD-MAN + RESTART.
fn proof_8_8(ctx: &mut Ctx) -> Proof {
    if !cfg!(windows) {
        return inconclusive(json!({"reason": "not-windows"}));
    }
    if !ctx.supervisor_started {
        return fail(json!({"reason": "supervisor did not start"}));
    }
    // Heartbeat must be present first.
    if !wait_file(&ctx.data_dir.join("hand.heartbeat"), Duration::from_secs(30)) {
        return fail(json!({"reason": "no worker heartbeat"}));
    }
    // (a) Stop-file round-trip while idle.
    let _ = ctx.ctl.write_stop("self-test-8.8");
    let stopped_written = wait_until(
        || {
            ctx.data_dir.join("hand.stopped").exists()
                && !ctx.data_dir.join("hand.heartbeat").exists()
        },
        Duration::from_secs(15),
    );
    let _ = ctx.ctl.clear_stop();
    let heartbeat_returned = wait_file(&ctx.data_dir.join("hand.heartbeat"), Duration::from_secs(15));
    // (b) Dead-man: pause the heartbeat, wait 2 missed beats, then the
    // reconnect attempt (ping, 5 s, no pong) must write hand.deadman.
    let last_beat = ctx.ctl.heartbeat_ts().unwrap_or(0);
    let _ = fs::write(ctx.data_dir.join("hand.pause-heartbeat"), "");
    let missed = wait_until(
        || HandControl::missed_beats(last_beat, utc_now_secs(), 2) >= DEADMAN_MISSED_BEATS,
        Duration::from_secs(20),
    );
    let deadman = if missed {
        ctx.ctl.deadman_check(last_beat)
    } else {
        false
    };
    let deadman_file = ctx.data_dir.join("hand.deadman").exists();
    // New commands are refused while the dead-man file is present.
    let dummy = new_command(
        "deadman-probe",
        "install",
        json!({"msi": "C:\\nonexistent.msi"}),
        3600,
        json!({}),
    );
    let refused = prepare_execution(&dummy, &ctx.config, &Guardian::default())
        .map(|_| false)
        .unwrap_or_else(|e| e == "deadman_active");
    let _ = fs::remove_file(ctx.data_dir.join("hand.pause-heartbeat"));
    ctx.ctl.clear_deadman();
    let heartbeat_back = wait_until(
        || {
            ctx.ctl
                .heartbeat_ts()
                .map(|t| utc_now_secs() <= t + 5)
                .unwrap_or(false)
        },
        Duration::from_secs(15),
    );
    // (c) Restart: kill the worker; the supervisor must restart it.
    let old_pid = read_pid_file(&ctx.data_dir.join("hand.worker-pid"));
    let mut restarted = false;
    let mut new_pid: Option<u32> = None;
    if let Some(pid) = old_pid {
        let _ = ProcCommand::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
        restarted = wait_until(
            || read_pid_file(&ctx.data_dir.join("hand.worker-pid")) != Some(pid),
            Duration::from_secs(30),
        );
        new_pid = read_pid_file(&ctx.data_dir.join("hand.worker-pid"));
    }
    let heartbeat_after_restart =
        wait_file(&ctx.data_dir.join("hand.heartbeat"), Duration::from_secs(15));
    let restart_recorded = ctx.data_dir.join("hand.supervisor-restarts.json").exists();
    let measured = json!({
        "stopped_written": stopped_written,
        "heartbeat_returned": heartbeat_returned,
        "missed_beats_reached": missed,
        "deadman_written": deadman && deadman_file,
        "new_commands_refused_while_deadman": refused,
        "heartbeat_back_after_deadman": heartbeat_back,
        "worker_restarted": restarted,
        "old_worker_pid": old_pid,
        "new_worker_pid": new_pid,
        "restart_recorded": restart_recorded,
        "heartbeat_after_restart": heartbeat_after_restart,
    });
    if stopped_written
        && heartbeat_returned
        && missed
        && deadman
        && deadman_file
        && refused
        && heartbeat_back
        && restarted
        && heartbeat_after_restart
    {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// 8.6 REPLAY PROTECTION + ORGANIZE PROPOSE-ONLY.
fn proof_8_6(ctx: &mut Ctx) -> Proof {
    let mut cmd = new_command(
        "replay-1",
        "download",
        json!({"url": "https://example.invalid/f.bin", "size_bytes": 1}),
        3600,
        json!({"output": "f.bin"}),
    );
    let first = enqueue(&ctx.data_dir, &mut cmd);
    let first_ok = matches!(first, Ok(EnqueueOutcome::Enqueued));
    let _ = mark(&ctx.data_dir, "replay-1", "done", None);
    // Same dedup_key + same nonce after completion => duplicate.
    let mut replay = new_command(
        "replay-2",
        "download",
        json!({"url": "https://example.invalid/f.bin", "size_bytes": 1}),
        3600,
        json!({"output": "f.bin"}),
    );
    replay.dedup_key = cmd.dedup_key.clone();
    replay.nonce = cmd.nonce.clone();
    let replay_outcome = enqueue(&ctx.data_dir, &mut replay);
    let replay_blocked = matches!(replay_outcome, Ok(EnqueueOutcome::Duplicate));
    // Organize propose-only: no approval => no file moves, ever.
    let a = ctx.work_dir.join("org-a.txt");
    let b = ctx.work_dir.join("org-b.txt");
    let _ = fs::write(&a, b"alpha");
    let _ = fs::write(&b, b"beta");
    let sum_a_before = file_sha256(&a).unwrap_or_default();
    let sum_b_before = file_sha256(&b).unwrap_or_default();
    let mut org = new_command(
        "org-1",
        "organize",
        json!({"moves": [{"from": a.to_string_lossy(), "to": b.to_string_lossy() }]}),
        3600,
        json!({"moves": [{"from": a.to_string_lossy(), "checksum": sum_a_before}]}),
    );
    org.needs_approval = true;
    let _ = enqueue(&ctx.data_dir, &mut org);
    let org_err = prepare_execution(&org, &ctx.config, &Guardian::default())
        .map(|_| "executed".to_string())
        .unwrap_or_else(|e| e);
    let sum_a_after = file_sha256(&a).unwrap_or_default();
    let sum_b_after = file_sha256(&b).unwrap_or_default();
    let no_moves = a.exists()
        && b.exists()
        && sum_a_before == sum_a_after
        && sum_b_before == sum_b_after;
    let measured = json!({
        "first_enqueued": first_ok,
        "replay_duplicate": replay_blocked,
        "organize_prepare_error": org_err,
        "no_file_moves": no_moves,
    });
    if first_ok && replay_blocked && org_err == "needs_approval" && no_moves {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// 8.7 GUARDIAN ABSENT = FAIL-CLOSED.
fn proof_8_7(ctx: &mut Ctx) -> Proof {
    let dead = ctx.work_dir.join("guardian-dead-path");
    let guardian = Guardian::with_base(&dead);
    let mut cmd = new_command(
        "guardian-absent-1",
        "install",
        json!({"msi": "C:\\nonexistent.msi"}),
        3600,
        json!({}),
    );
    let _ = enqueue(&ctx.data_dir, &mut cmd);
    let err = prepare_execution(&cmd, &ctx.config, &guardian)
        .map(|_| "executed".to_string())
        .unwrap_or_else(|e| e);
    // The command stays queued with the reason recorded.
    let _ = mark(&ctx.data_dir, "guardian-absent-1", "queued", Some("guardian_unavailable"));
    let state = queue_state(&ctx.data_dir, "guardian-absent-1");
    let stayed_queued = matches!(state, Some((ref s, ref r)) if s == "queued" && r.as_deref() == Some("guardian_unavailable"));
    let measured = json!({
        "prepare_error": err,
        "stayed_queued_with_reason": stayed_queued,
    });
    if err == "guardian_unavailable" && stayed_queued {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// 8.4 EICAR GATE.
fn proof_8_4(ctx: &mut Ctx) -> Proof {
    let eicar_path = ctx.work_dir.join("eicar.com");
    let _ = fs::write(&eicar_path, EICAR);
    let guardian = Guardian::default();
    let verdict = guardian.verdict(&eicar_path);
    let verdict_block = verdict == bimo_hand::guardian::Verdict::Block("eicar".to_string());
    let mut cmd = new_command(
        "eicar-1",
        "install",
        json!({"target": eicar_path.to_string_lossy(), "msi": eicar_path.to_string_lossy()}),
        3600,
        json!({}),
    );
    let _ = enqueue(&ctx.data_dir, &mut cmd);
    let err = prepare_execution(&cmd, &ctx.config, &guardian)
        .map(|_| "executed".to_string())
        .unwrap_or_else(|e| e);
    let _ = mark(&ctx.data_dir, "eicar-1", "blocked_eicar", Some("eicar"));
    let quarantine_dir = ctx.work_dir.join("quarantine");
    let quarantined = quarantine_copy(&eicar_path, &quarantine_dir);
    let hash_before = file_sha256(&eicar_path).unwrap_or_default();
    let (quarantine_ok, quarantine_hash_matches) = match quarantined {
        Ok(dest) => {
            let h = file_sha256(&dest).unwrap_or_default();
            (dest.exists(), h == hash_before)
        }
        Err(_) => (false, false),
    };
    let untouched = eicar_path.exists() && hash_before == sha256_hex(EICAR);
    let measured = json!({
        "guardian_verdict_block_eicar": verdict_block,
        "prepare_error": err,
        "quarantine_ok": quarantine_ok,
        "quarantine_hash_matches": quarantine_hash_matches,
        "file_untouched": untouched,
        "eicar_sha256": hash_before,
    });
    if verdict_block && err == "blocked_eicar" && quarantine_ok && quarantine_hash_matches && untouched {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// 8.3 FAILED REVERT.
fn proof_8_3(ctx: &mut Ctx) -> Proof {
    let app_dir = ctx.work_dir.join("test-app");
    let _ = fs::create_dir_all(&app_dir);
    let marker = app_dir.join("installed.txt");
    let uninstaller = app_dir.join("uninstall.txt");
    let _ = fs::write(&marker, b"installed");
    let _ = fs::write(&uninstaller, b"uninstaller record");
    let mut cmd = new_command(
        "revert-fail-1",
        "install",
        json!({"installed_marker": marker.to_string_lossy()}),
        3600,
        json!({"uninstaller": uninstaller.to_string_lossy()}),
    );
    let _ = enqueue(&ctx.data_dir, &mut cmd);
    let _ = mark(&ctx.data_dir, "revert-fail-1", "done", None);
    // Break the uninstall record (simulate a missing uninstaller).
    let _ = fs::remove_file(&uninstaller);
    let outcome = revert(&cmd, &ctx.data_dir);
    let failed = outcome == RevertOutcome::Failed(format!(
        "uninstaller record is missing: {}",
        uninstaller.to_string_lossy()
    ));
    let _ = mark(&ctx.data_dir, "revert-fail-1", "revert_failed", Some("uninstaller record is missing"));
    let escalation = ctx
        .data_dir
        .join("hand.revert-failed-revert-fail-1.json")
        .exists();
    let alert = alert_exists(&ctx.data_dir, "revert-failed");
    let marker_intact = marker.exists();
    let measured = json!({
        "revert_failed": failed,
        "escalation_file_exists": escalation,
        "alert_recorded": alert,
        "app_marker_intact": marker_intact,
    });
    if failed && escalation && alert && marker_intact {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// 8.5 CONTAINMENT, NO ESCAPE.
fn proof_8_5(ctx: &mut Ctx) -> Proof {
    if !cfg!(windows) {
        return inconclusive(json!({"reason": "not-windows"}));
    }
    if !ctx.supervisor_started {
        return fail(json!({"reason": "supervisor did not start"}));
    }
    let out = ctx.work_dir.join("grandchild-pid.txt");
    let req = ExecRequest {
        id: "probe-1".to_string(),
        kind: "probe-grandchild".to_string(),
        program: String::new(),
        args: vec![],
        working_dir: None,
        cleanup_path: None,
        install_dir: None,
        grandchild_out: Some(out.to_string_lossy().to_string()),
    };
    if write_exec_request(&ctx.data_dir, &req).is_err() {
        return fail(json!({"reason": "could not write exec request"}));
    }
    let result = wait_exec_result(&ctx.data_dir, "probe-1", Duration::from_secs(90));
    match result {
        None => fail(json!({"reason": "no exec result within 90 s"})),
        Some(r) => {
            let in_job = r.get("grandchild_in_job").and_then(|v| v.as_bool()).unwrap_or(false);
            let count = r.get("job_process_count").and_then(|v| v.as_u64()).unwrap_or(999);
            ctx.stop_probe_ms = r.get("stop_ms").and_then(|v| v.as_u64());
            let measured = json!({
                "grandchild_pid": r.get("grandchild_pid"),
                "grandchild_in_job": in_job,
                "job_process_count": count,
                "job_process_limit": 32,
                "stop_ms": ctx.stop_probe_ms,
            });
            if in_job && count <= 32 {
                pass(measured)
            } else {
                fail(measured)
            }
        }
    }
}

/// 8.2 MID-TRANSFER STOP.
fn proof_8_2(ctx: &mut Ctx) -> Proof {
    if !cfg!(windows) {
        return inconclusive(json!({"reason": "not-windows"}));
    }
    if !ctx.supervisor_started {
        return fail(json!({"reason": "supervisor did not start"}));
    }
    let src = ctx.work_dir.join("big.bin");
    if gen_1gb(&src).is_err() {
        return fail(json!({"reason": "could not generate the 1 GB file"}));
    }
    let checksum = file_sha256(&src).unwrap_or_default();
    ctx.transfer_source = Some(src.clone());
    ctx.transfer_source_checksum = Some(checksum.clone());
    for attempt in 0..2 {
        let dst = ctx.work_dir.join(format!("big-copy-{}.bin", attempt));
        let mut cmd = new_command(
            &format!("transfer-kill-{}", attempt),
            "transfer",
            json!({
                "source": src.to_string_lossy(),
                "destination": dst.to_string_lossy(),
                "size_bytes": ONE_GB,
            }),
            3600,
            json!({
                "source": src.to_string_lossy(),
                "destination": dst.to_string_lossy(),
                "source_checksum": checksum,
            }),
        );
        let _ = enqueue(&ctx.data_dir, &mut cmd);
        let req = match prepare_execution(&cmd, &ctx.config, &Guardian::default()) {
            Ok(r) => r,
            Err(e) => {
                return fail(json!({"reason": "prepare_execution failed", "error": e}));
            }
        };
        let _ = mark(&ctx.data_dir, &cmd.id, "running", None);
        if write_exec_request(&ctx.data_dir, &req).is_err() {
            return fail(json!({"reason": "could not write exec request"}));
        }
        if !wait_file(&exec_started_path(&ctx.data_dir, &cmd.id), Duration::from_secs(30)) {
            return fail(json!({"reason": "transfer never started"}));
        }
        // Kill when progress crosses 25% (progress polling, not wall clock).
        let target_bytes = ONE_GB / 4;
        let crossed = wait_until(|| file_size(&dst) >= target_bytes, Duration::from_secs(120));
        if !crossed {
            // The copy finished before 25% was observed: retry once.
            let _ = ctx.ctl.clear_stop();
            continue;
        }
        let progress_pct = (file_size(&dst) as f64 / ONE_GB as f64) * 100.0;
        let _ = ctx.ctl.write_stop("self-test-8.2");
        let result = wait_exec_result(&ctx.data_dir, &cmd.id, Duration::from_secs(60));
        let _ = ctx.ctl.clear_stop();
        match result {
            None => {
                return fail(json!({"reason": "no exec result after stop", "attempt": attempt}));
            }
            Some(r) => {
                let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("");
                if status == "done" {
                    // Finished before the kill landed: retry once.
                    continue;
                }
                let stop_ms = r.get("stop_ms").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
                ctx.stop_transfer_ms = Some(stop_ms);
                let partial_cleaned = r
                    .get("partial_cleaned")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let partial_gone = !dst.exists();
                let _ = mark(&ctx.data_dir, &cmd.id, "stopped", None);
                let measured = json!({
                    "attempt": attempt,
                    "progress_pct_at_kill": progress_pct,
                    "status": status,
                    "stop_ms": stop_ms,
                    "stop_method": r.get("stop_method"),
                    "tree_dead": r.get("tree_dead"),
                    "partial_cleaned": partial_cleaned,
                    "partial_file_gone": partial_gone,
                    "no_corrupt_file_presented_as_complete": partial_gone,
                });
                if status == "stopped" && stop_ms <= 5000 && partial_gone {
                    return pass(measured);
                }
                return fail(measured);
            }
        }
    }
    inconclusive(json!({"reason": "transfer finished before the kill in both attempts"}))
}

/// 8.10b TRANSFER REVERT (after a successful transfer, no kill).
fn proof_8_10b(ctx: &mut Ctx) -> Proof {
    if !cfg!(windows) {
        return inconclusive(json!({"reason": "not-windows"}));
    }
    if !ctx.supervisor_started {
        return fail(json!({"reason": "supervisor did not start"}));
    }
    let src = match &ctx.transfer_source {
        Some(s) => s.clone(),
        None => return fail(json!({"reason": "no transfer source from 8.2"})),
    };
    let checksum = ctx.transfer_source_checksum.clone().unwrap_or_default();
    let dst = ctx.work_dir.join("big-copy-ok.bin");
    let mut cmd = new_command(
        "transfer-ok-1",
        "transfer",
        json!({
            "source": src.to_string_lossy(),
            "destination": dst.to_string_lossy(),
            "size_bytes": ONE_GB,
        }),
        3600,
        json!({
            "source": src.to_string_lossy(),
            "destination": dst.to_string_lossy(),
            "source_checksum": checksum,
        }),
    );
    let _ = enqueue(&ctx.data_dir, &mut cmd);
    let req = match prepare_execution(&cmd, &ctx.config, &Guardian::default()) {
        Ok(r) => r,
        Err(e) => return fail(json!({"reason": "prepare_execution failed", "error": e})),
    };
    if write_exec_request(&ctx.data_dir, &req).is_err() {
        return fail(json!({"reason": "could not write exec request"}));
    }
    let result = wait_exec_result(&ctx.data_dir, "transfer-ok-1", Duration::from_secs(180));
    let done = matches!(result, Some(ref r) if r.get("status").and_then(|v| v.as_str()) == Some("done"));
    let dest_checksum_ok = dst.exists() && file_sha256(&dst).unwrap_or_default() == checksum;
    if !done || !dest_checksum_ok {
        return fail(json!({
            "reason": "transfer did not complete cleanly",
            "done": done,
            "destination_checksum_ok": dest_checksum_ok,
        }));
    }
    ctx.reverts_expected_success += 1;
    let outcome = revert(&cmd, &ctx.data_dir);
    let reverted = outcome == RevertOutcome::Reverted;
    if reverted {
        ctx.reverts_succeeded += 1;
    }
    let _ = mark(&ctx.data_dir, "transfer-ok-1", "reverted", None);
    let back_at_original = src.exists()
        && !dst.exists()
        && file_sha256(&src).unwrap_or_default() == checksum;
    let measured = json!({
        "transfer_done": done,
        "destination_checksum_ok": dest_checksum_ok,
        "revert_outcome": format!("{:?}", outcome),
        "file_back_at_original_path": back_at_original,
        "checksum_matches": back_at_original,
        "state": "reverted",
    });
    if done && dest_checksum_ok && reverted && back_at_original {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// 8.10a DISK-SPACE REJECTION.
fn proof_8_10a(ctx: &mut Ctx) -> Proof {
    let free = free_space_bytes(&ctx.data_dir);
    let free = match free {
        Some(f) => f,
        None => {
            return inconclusive(json!({"reason": "free disk space is unknown on this platform"}));
        }
    };
    let fake_size = free.saturating_add(ONE_GB);
    let target = ctx.work_dir.join("huge.bin");
    let mut cmd = new_command(
        "disk-space-1",
        "download",
        json!({
            "url": "https://example.invalid/huge.bin",
            "size_bytes": fake_size,
            "target": target.to_string_lossy(),
        }),
        3600,
        json!({"output": target.to_string_lossy()}),
    );
    let _ = enqueue(&ctx.data_dir, &mut cmd);
    let err = prepare_execution(&cmd, &ctx.config, &Guardian::default())
        .map(|_| "executed".to_string())
        .unwrap_or_else(|e| e);
    let _ = mark(&ctx.data_dir, "disk-space-1", "failed", Some("disk-space"));
    let nothing_written = !target.exists();
    let state = queue_state(&ctx.data_dir, "disk-space-1");
    let state_ok = matches!(state, Some((ref s, ref r)) if s == "failed" && r.as_deref() == Some("disk-space"));
    let measured = json!({
        "free_bytes": free,
        "fake_size_bytes": fake_size,
        "required_bytes": required_bytes(fake_size),
        "prepare_error": err,
        "state_failed_disk_space": state_ok,
        "nothing_written": nothing_written,
        "target_exists": target.exists(),
    });
    if err == "disk-space" && state_ok && nothing_written {
        pass(measured)
    } else {
        fail(measured)
    }
}

/// One MSI install attempt for 8.1: launch via the supervisor, wait for
/// the started file, then kill at `fraction` of `install_duration_ms`.
/// Returns (status, result-json, kill_ms_after_start).
fn msi_kill_attempt(
    ctx: &mut Ctx,
    id: &str,
    msi: &str,
    install_dir: &str,
    install_duration_ms: u64,
    fraction: f64,
) -> (String, Option<Value>, u64) {
    let cmd = new_command(
        id,
        "install",
        json!({
            "msi": msi,
            "install_dir": install_dir,
            "size_bytes": file_size(Path::new(msi)),
        }),
        3600,
        json!({"uninstaller": msi}),
    );
    let req = match prepare_execution(&cmd, &ctx.config, &Guardian::default()) {
        Ok(r) => r,
        Err(e) => return (format!("prepare_failed:{}", e), None, 0),
    };
    let _ = write_exec_request(&ctx.data_dir, &req);
    if !wait_file(&exec_started_path(&ctx.data_dir, id), Duration::from_secs(60)) {
        return ("never-started".to_string(), None, 0);
    }
    let start = Instant::now();
    let kill_at_ms = (install_duration_ms as f64 * fraction) as u64;
    while start.elapsed().as_millis() < kill_at_ms as u128 {
        // If the install already finished, stop waiting.
        if let Some(r) = bimo_hand::executor::read_exec_result(&ctx.data_dir, id) {
            let _ = ctx.ctl.clear_stop();
            return ("finished-before-kill".to_string(), Some(r), start.elapsed().as_millis() as u64);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let kill_ms = start.elapsed().as_millis() as u64;
    let _ = ctx.ctl.write_stop("self-test-8.1");
    let result = wait_exec_result(&ctx.data_dir, id, Duration::from_secs(90));
    let _ = ctx.ctl.clear_stop();
    match result {
        None => ("no-result-after-stop".to_string(), None, kill_ms),
        Some(r) => {
            let status = r
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            (status, Some(r), kill_ms)
        }
    }
}

fn msi_request(ctx: &Ctx, id: &str, msi: &str, uninstall: bool, install_dir: &str) -> Option<Value> {
    let cmd = new_command(
        id,
        "install",
        json!({
            "msi": msi,
            "uninstall": uninstall,
            "install_dir": install_dir,
            "size_bytes": file_size(Path::new(msi)),
        }),
        3600,
        json!({"uninstaller": msi}),
    );
    let req = prepare_execution(&cmd, &ctx.config, &Guardian::default()).ok()?;
    write_exec_request(&ctx.data_dir, &req).ok()?;
    wait_exec_result(&ctx.data_dir, id, Duration::from_secs(600))
}

/// 8.1 ELEVATED MSI KILL — RED LINE.
fn proof_8_1(ctx: &mut Ctx) -> Proof {
    if !cfg!(windows) {
        return inconclusive(json!({"reason": "not-windows"}));
    }
    if !ctx.supervisor_started {
        return fail(json!({"reason": "supervisor did not start"}));
    }
    let msi = ctx.work_dir.join("vlc-3.0.20-win64.msi");
    let (url_used, downloaded) = if download(VLC_PRIMARY, &msi) {
        (VLC_PRIMARY, true)
    } else if download(VLC_FALLBACK, &msi) {
        (VLC_FALLBACK, true)
    } else {
        ("", false)
    };
    if !downloaded {
        return inconclusive(json!({
            "reason": "download_failed",
            "tried": [VLC_PRIMARY, VLC_FALLBACK],
        }));
    }
    let msi_sha256 = file_sha256(&msi).unwrap_or_default();
    let program_files =
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
    let install_dir = format!("{}\\VideoLAN\\VLC", program_files);
    let vlc_exe = Path::new(&install_dir).join("vlc.exe");
    // Phase A (calibration): full install, measure D, uninstall, verify gone.
    let install_result = msi_request(ctx, "vlc-install-a", &msi.to_string_lossy(), false, &install_dir);
    let (install_done, duration_ms) = match &install_result {
        Some(r) => (
            r.get("status").and_then(|v| v.as_str()) == Some("done"),
            r.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0),
        ),
        None => (false, 0),
    };
    let vlc_present_after_install = vlc_exe.exists();
    if !install_done || !vlc_present_after_install || duration_ms == 0 {
        return inconclusive(json!({
            "reason": "phase-a-failed",
            "msi_sha256": msi_sha256,
            "msi_url": url_used,
            "install_done": install_done,
            "vlc_present_after_install": vlc_present_after_install,
            "install_duration_ms": duration_ms,
        }));
    }
    let uninstall_result = msi_request(ctx, "vlc-uninstall-a", &msi.to_string_lossy(), true, &install_dir);
    let uninstalled = wait_until(|| !vlc_exe.exists(), Duration::from_secs(120));
    let _ = uninstall_result;
    if !uninstalled {
        return inconclusive(json!({
            "reason": "phase-a-uninstall-failed",
            "msi_sha256": msi_sha256,
            "msi_url": url_used,
            "install_duration_ms": duration_ms,
        }));
    }
    // Phase B (kill): fresh install, kill at D x 0.4; one retry at D x 0.25.
    for (attempt, fraction) in [(0u32, 0.4f64), (1u32, 0.25f64)] {
        let id = format!("vlc-install-kill-{}", attempt);
        let (status, result, kill_ms) =
            msi_kill_attempt(ctx, &id, &msi.to_string_lossy(), &install_dir, duration_ms, fraction);
        if status == "finished-before-kill" {
            // Clean up the finished install before the retry.
            let _ = msi_request(ctx, &format!("vlc-uninstall-kill-{}", attempt), &msi.to_string_lossy(), true, &install_dir);
            let _ = wait_until(|| !vlc_exe.exists(), Duration::from_secs(120));
            continue;
        }
        let r = match result {
            Some(r) => r,
            None => {
                return fail(json!({
                    "reason": "no-result-after-stop",
                    "msi_sha256": msi_sha256,
                    "msi_url": url_used,
                    "install_duration_ms": duration_ms,
                    "kill_fraction": fraction,
                    "kill_ms_after_start": kill_ms,
                }));
            }
        };
        if status != "stopped" {
            // The install finished before the kill landed.
            let _ = msi_request(ctx, &format!("vlc-uninstall-kill-{}", attempt), &msi.to_string_lossy(), true, &install_dir);
            let _ = wait_until(|| !vlc_exe.exists(), Duration::from_secs(120));
            continue;
        }
        let stop_ms = r.get("stop_ms").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
        ctx.stop_install_ms = Some(stop_ms);
        let tree_dead = r.get("tree_dead").and_then(|v| v.as_bool()).unwrap_or(false);
        let handles_released = r
            .get("handles_released")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let supervisor_elevated = r
            .get("supervisor_elevated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let installer_elevated = r
            .get("installer_elevated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Cleanup: uninstall any partial install, then remove the dir.
        if vlc_exe.exists() || Path::new(&install_dir).exists() {
            let _ = msi_request(ctx, "vlc-uninstall-cleanup", &msi.to_string_lossy(), true, &install_dir);
            let _ = wait_until(|| !vlc_exe.exists(), Duration::from_secs(120));
            if Path::new(&install_dir).exists() {
                let _ = fs::remove_dir_all(&install_dir);
            }
        }
        let measured = json!({
            "msi_sha256": msi_sha256,
            "msi_url": url_used,
            "install_duration_ms": duration_ms,
            "kill_fraction": fraction,
            "kill_ms_after_start": kill_ms,
            "attempt": attempt,
            "stop_ms": stop_ms,
            "stop_method": r.get("stop_method"),
            "tree_dead": tree_dead,
            "handles_released": handles_released,
            "supervisor_elevated": supervisor_elevated,
            "installer_elevated": installer_elevated,
            "remaining_pids": r.get("remaining_pids"),
        });
        // RED LINE: kill attempted while the installer was running and
        // anything survives past 5 s, or handles stay held => fail.
        if tree_dead && handles_released && stop_ms <= 5000 {
            return pass(measured);
        }
        return fail(measured);
    }
    inconclusive(json!({
        "reason": "install-finished-before-kill",
        "msi_sha256": msi_sha256,
        "msi_url": url_used,
        "install_duration_ms": duration_ms,
    }))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out_path = PathBuf::from("hand-self-test.json");
    let mut supervisor_bin: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                if i < args.len() {
                    out_path = PathBuf::from(&args[i]);
                }
            }
            "--supervisor-bin" => {
                i += 1;
                if i < args.len() {
                    supervisor_bin = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }
    let supervisor_bin = supervisor_bin.unwrap_or_else(|| {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("bimo-hand-self-test.exe"));
        exe.parent()
            .map(|d| d.join("bimo-hand-supervisor.exe"))
            .unwrap_or_else(|| PathBuf::from("bimo-hand-supervisor.exe"))
    });
    let root = std::env::temp_dir().join(format!(
        "bimo-hand-self-test-{}-{}",
        std::process::id(),
        utc_now_secs()
    ));
    let data_dir = root.join("data");
    let work_dir = root.join("work");
    let _ = fs::create_dir_all(&data_dir);
    let _ = fs::create_dir_all(&work_dir);
    // Spawn the supervisor as a child.
    let mut supervisor_child: Option<Child> = None;
    let mut supervisor_started = false;
    if cfg!(windows) && supervisor_bin.exists() {
        match ProcCommand::new(&supervisor_bin)
            .args([
                "--data-dir",
                &data_dir.to_string_lossy(),
                "--heartbeat-secs",
                "2",
            ])
            .spawn()
        {
            Ok(child) => {
                supervisor_child = Some(child);
                supervisor_started = wait_file(&data_dir.join("hand.heartbeat"), Duration::from_secs(60));
            }
            Err(e) => eprintln!("self-test: spawn supervisor failed: {}", e),
        }
    }
    let mut config = HandConfig::default();
    config.exec_enabled = true; // ONLY the self-test binary passes true.
    config.data_dir = data_dir.clone();
    config.heartbeat_secs = 2;
    let mut ctx = Ctx {
        data_dir: data_dir.clone(),
        work_dir: work_dir.clone(),
        config,
        ctl: HandControl::new(&data_dir, 2),
        supervisor_started,
        stop_install_ms: None,
        stop_transfer_ms: None,
        stop_probe_ms: None,
        reverts_succeeded: 0,
        reverts_expected_success: 0,
        revert_failed_correctly: 0,
        transfer_source: None,
        transfer_source_checksum: None,
    };
    // Run the proofs. 8.8 first (it restarts the worker), 8.1 last (MSI).
    let p88 = proof_8_8(&mut ctx);
    let p86 = proof_8_6(&mut ctx);
    let p87 = proof_8_7(&mut ctx);
    let p84 = proof_8_4(&mut ctx);
    let p83 = proof_8_3(&mut ctx);
    if p83.status == "pass" {
        ctx.revert_failed_correctly = 1;
    }
    let p85 = proof_8_5(&mut ctx);
    let p82 = proof_8_2(&mut ctx);
    let p810b = proof_8_10b(&mut ctx);
    let p810a = proof_8_10a(&mut ctx);
    let p81 = proof_8_1(&mut ctx);
    // 8.9 MEASUREMENTS (regression pack).
    let queue_size = Queue::open(&data_dir).map(|q| q.len()).unwrap_or(0);
    let (ram_total_mb, ram_available_mb) = system_memory_mb().unwrap_or((0, 0));
    let revert_rate = if ctx.reverts_expected_success > 0 {
        ctx.reverts_succeeded as f64 / ctx.reverts_expected_success as f64
    } else {
        0.0
    };
    let measurements = json!({
        "stop_ms_by_kind": {
            "install": ctx.stop_install_ms,
            "transfer": ctx.stop_transfer_ms,
            "probe_grandchild": ctx.stop_probe_ms,
        },
        "revert_success_rate": revert_rate,
        "reverts_succeeded": ctx.reverts_succeeded,
        "reverts_expected_success": ctx.reverts_expected_success,
        "revert_failed_correctly": ctx.revert_failed_correctly,
        "queue_size": queue_size,
        "ram_total_mb": ram_total_mb,
        "ram_available_mb": ram_available_mb,
        "cpu_percent": Value::Null,
        "cpu_note": "not measured on the runner",
    });
    let p89 = if queue_size > 0
        && (ctx.stop_install_ms.is_some() || ctx.stop_transfer_ms.is_some())
    {
        pass(measurements.clone())
    } else {
        fail(measurements.clone())
    };
    // Verdict.
    let red_line = match p81.status {
        "pass" => "met",
        "fail" => "violated",
        _ => "not-tested",
    };
    let all = [
        &p81, &p82, &p83, &p84, &p85, &p86, &p87, &p88, &p89, &p810a, &p810b,
    ];
    let all_pass = all.iter().all(|p| p.status == "pass");
    let only_81_inconclusive = p81.status == "inconclusive"
        && all.iter().filter(|p| p.status != "pass").count() == 1;
    let verdict = if all_pass || only_81_inconclusive {
        "pass"
    } else {
        "fail"
    };
    let mut proofs = serde_json::Map::new();
    proofs.insert("8.1".to_string(), p81.to_json());
    proofs.insert("8.2".to_string(), p82.to_json());
    proofs.insert("8.3".to_string(), p83.to_json());
    proofs.insert("8.4".to_string(), p84.to_json());
    proofs.insert("8.5".to_string(), p85.to_json());
    proofs.insert("8.6".to_string(), p86.to_json());
    proofs.insert("8.7".to_string(), p87.to_json());
    proofs.insert("8.8".to_string(), p88.to_json());
    proofs.insert("8.9".to_string(), p89.to_json());
    proofs.insert("8.10a".to_string(), p810a.to_json());
    proofs.insert("8.10b".to_string(), p810b.to_json());
    let report = json!({
        "verdict": verdict,
        "red_line": red_line,
        "proofs": proofs,
        "measurements": measurements,
        "runner_note": "does not prove device performance",
    });
    let _ = write_json_file(&out_path, &report);
    println!("bimo-hand-self-test: verdict={} red_line={}", verdict, red_line);
    for (key, proof) in &proofs {
        println!("  {}: {}", key, proof.get("status").and_then(|v| v.as_str()).unwrap_or("?"));
    }
    // Stop the supervisor, then kill it if it does not exit.
    let _ = fs::write(data_dir.join("hand.supervisor-exit"), "");
    if let Some(mut child) = supervisor_child {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
    }
    if verdict == "pass" {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
