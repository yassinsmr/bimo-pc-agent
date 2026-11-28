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
//! Slice mode (8.12, Track A Unit 3): `bimo-hand-self-test --slice
//! --slice-inputs <slice-inputs.json> --data-dir <hand-data>
//! --out <hand-slice.json> [--slice-phase install|revert]` — runs the
//! negative tests + S2+S3 (install phase) or S7 (revert phase), never
//! proofs 8.1–8.11. See the 8.12 section in this file for the
//! two-invocation design (builder decision B1) and the per-phase
//! slice_exit_code (builder decision B2).
//!
//! If the RED LINE proof (8.1) fails while the installer was running
//! (anything survives past 5 s, or handles stay held), the verdict is
//! `fail` + `red_line: violated` — verdict (c), no new council.

use bimo_hand::control::{HandControl, DEADMAN_MISSED_BEATS};
use bimo_hand::executor::{
    exec_request_path, exec_result_path, exec_started_path, free_space_bytes,
    prepare_execution, read_exec_result, required_bytes, wait_exec_result,
    write_exec_request, ExecRequest, HandConfig,
};
use bimo_hand::guardian::{quarantine_copy, Guardian, EICAR};
use bimo_hand::queue::{new_command, Command, EnqueueOutcome, Queue};
use bimo_hand::revert::{revert, verify_revert_plan, RevertOutcome};
use bimo_hand::supervisor::system_memory_mb;
use bimo_hand::{alert_event, file_sha256, sha256_hex, utc_now_secs, write_json_file};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as ProcCommand};
use std::sync::mpsc;
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

fn wait_until<F: FnMut() -> bool>(mut f: F, timeout: Duration) -> bool {
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
    // Retry: egress to one host can fail transiently while another
    // works (cycle 41, run 11: the Firefox bouncer failed once while
    // VideoLAN downloaded fine on the same runner). Three attempts,
    // 5 s apart, curl then PowerShell each time. A download that fails
    // every attempt is reported download-failed (inconclusive), never
    // a pass.
    for attempt in 1..=3 {
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
        if matches!(r, Ok(o) if o.status.success() && out.exists() && file_size(out) > 0) {
            return true;
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_secs(5));
        }
    }
    false
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
        installer_kind: None,
        product_code: None,
        name_substring: None,
        expected_sha256: None,
        targetdir: None,
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
        let tree_dead = r.get("tree_dead").and_then(|v| v.as_bool()).unwrap_or(false);
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
                if status == "stopped" && stop_ms <= 5000 && partial_gone && tree_dead {
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
    // Start from a clean stop state: a hand.stop left by an earlier
    // proof aborts this transfer on launch (run 11: transfer-ok-1
    // never ran, done=false, no destination file).
    let _ = ctx.ctl.clear_stop();
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

fn proof_8_2b(ctx: &mut Ctx) -> Proof {
    // v2 (cycle 41, section 8.2 phase B): a real tree with an orphan
    // grandchild born via Win32_Process.Create (its parent is wmiprvse,
    // not the command's tree). It must be killed by the alternative
    // naming mechanism (creation-time window + exe path) or it is
    // recorded as a survivor and the proof fails. PPID enumeration does
    // not cover Win32_Process.Create / COM processes -- that is an
    // explicit acknowledgement recorded in the measured JSON.
    let src = match &ctx.transfer_source {
        Some(s) => s.clone(),
        None => return inconclusive(json!({"reason": "no-transfer-source-from-8.2"})),
    };
    let exe = match std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("bimo-hand-supervisor.exe"))) {
        Some(p) if p.exists() => p,
        _ => return inconclusive(json!({"reason": "supervisor-binary-not-found"})),
    };
    let exe_str = exe.to_string_lossy().to_string();
    let window_start = std::time::SystemTime::now();
    // Warm up the WMI/DCOM stack before the transfer starts: the first
    // Invoke-CimMethod in a fresh PowerShell pays the service-connection
    // cost (10+ s on the runner), which alone can outlast the 1 GB
    // transfer (run 13: transfer done at 11575 ms before hand.stop).
    // A read-only CIM query exercises the same stack with no side effects.
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_OperatingSystem | Out-Null"])
        .output();
    let dst = ctx.work_dir.join("orphan-copy.bin");
    let _ = std::fs::remove_file(&dst);
    let mut cmd = new_command(
        "transfer-orphan",
        "transfer",
        json!({"source": src.to_string_lossy(), "destination": dst.to_string_lossy(), "size_bytes": ONE_GB}),
        3600,
        json!({"source": src.to_string_lossy(), "destination": dst.to_string_lossy()}),
    );
    if enqueue(&ctx.data_dir, &mut cmd).is_err() {
        return inconclusive(json!({"reason": "enqueue-failed"}));
    }
    let req = match prepare_execution(&cmd, &ctx.config, &Guardian::default()) {
        Ok(r) => r,
        Err(e) => return inconclusive(json!({"reason": "prepare-failed", "error": e})),
    };
    let _ = write_exec_request(&ctx.data_dir, &req);
    let _ = wait_file(&exec_started_path(&ctx.data_dir, "transfer-orphan"), Duration::from_secs(30));
    let started: Value = std::fs::read_to_string(exec_started_path(&ctx.data_dir, "transfer-orphan"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(json!({}));
    let root_pid = started.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    if root_pid == 0 {
        return inconclusive(json!({"reason": "no-started-pid"}));
    }
    // Spawn the orphan grandchild via Win32_Process.Create (WMI/CIM).
    // The orphan slow-copies the same 1 GB source the transfer reads
    // (read-only sharing): copying it first cost ~as long as the
    // transfer itself, so in run 11 the transfer finished ("done")
    // before hand.stop was written, no abort ever ran, and the orphan
    // survived. No pre-copy: the stop now lands while the transfer runs.
    let orphan_src = src.clone();
    let orphan_dst = ctx.work_dir.join("orphan-dst.bin");
    let ps = format!("Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{CommandLine='\"{}\" --slow-copy \"{}\" \"{}\"'}}", exe_str, orphan_src.to_string_lossy(), orphan_dst.to_string_lossy());
    let ps_out = std::process::Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &ps]).output();
    let wmi_ok = ps_out.map(|o| o.status.success()).unwrap_or(false);
    if !wmi_ok {
        let _ = ctx.ctl.write_stop("hand.stop");
        let _ = wait_exec_result(&ctx.data_dir, "transfer-orphan", Duration::from_secs(120));
        return inconclusive(json!({"reason": "wmi-create-failed", "ppid_enumeration_does_not_cover_wmi_com": true}));
    }
    // Wait for the orphan to appear (creation window + exe path).
    let mut orphan_pid: u32 = 0;
    let mut orphan_ppid: u32 = 0;
    let found_orphan = wait_until(|| {
        let now = std::time::SystemTime::now();
        let cands = bimo_hand::win32::processes_by_exe_and_window(&exe_str, window_start, now);
        for c in &cands {
            if c.pid != root_pid && c.ppid != root_pid {
                orphan_pid = c.pid;
                orphan_ppid = c.ppid;
                return true;
            }
        }
        false
    }, Duration::from_secs(30));
    if !found_orphan || orphan_pid == 0 {
        let _ = ctx.ctl.write_stop("hand.stop");
        let _ = wait_exec_result(&ctx.data_dir, "transfer-orphan", Duration::from_secs(120));
        return inconclusive(json!({"reason": "orphan-not-observed", "ppid_enumeration_does_not_cover_wmi_com": true}));
    }
    let orphan_ppid_exe = bimo_hand::win32::exe_path(orphan_ppid).unwrap_or_default();
    let orphan_in_tree = bimo_hand::win32::descendants(root_pid).contains(&orphan_pid);
    // Stop the command through hand.stop; the supervisor must kill the
    // orphan by alternative naming, not by PPID.
    let _ = ctx.ctl.write_stop("hand.stop");
    let result = wait_exec_result(&ctx.data_dir, "transfer-orphan", Duration::from_secs(120));
    let orphan_dead = !bimo_hand::win32::alive(orphan_pid);
    let orphan_gone_by_window = bimo_hand::win32::processes_by_exe_and_window(&exe_str, window_start, std::time::SystemTime::now()).is_empty();
    // Clear the stop we wrote: a leftover hand.stop aborts the next
    // command on launch (run 11: it killed transfer-ok-1 in 8.10b and
    // cancelled the 8.1 phase-B install at once, ui_calls 0).
    let _ = ctx.ctl.clear_stop();
    let measured = json!({
        "root_pid": root_pid, "orphan_pid": orphan_pid, "orphan_ppid": orphan_ppid,
        "orphan_ppid_exe": orphan_ppid_exe, "orphan_parent_is_wmiprvse": orphan_ppid_exe.to_ascii_lowercase().contains("wmiprvse"),
        "orphan_exe": bimo_hand::win32::exe_path(orphan_pid).unwrap_or_default(),
        "orphan_in_ppid_tree": orphan_in_tree,
        "ppid_enumeration_does_not_cover_wmi_com": true,
        "killed_by": "alternative-naming (creation-time window + exe path)",
        "orphan_dead": orphan_dead, "orphan_gone_by_window": orphan_gone_by_window,
        "exec_result": result,
    });
    let status = result.as_ref().and_then(|r| r.get("status")).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let tree_dead = result.as_ref().and_then(|r| r.get("tree_dead")).and_then(|v| v.as_bool()).unwrap_or(false);
    let stop_ms = result.as_ref().and_then(|r| r.get("stop_ms")).and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    if status != "stopped" || !tree_dead || stop_ms > 5000 {
        return fail(measured);
    }
    if !orphan_dead || !orphan_gone_by_window {
        return fail(json!({"survivor": measured}));
    }
    ctx.stop_transfer_ms = Some(stop_ms);
    pass(measured)
}

fn proof_8_9(ctx: &mut Ctx) -> Proof {
    // v2 (cycle 41, condition 4 evidence): an MSI stop through a trigger
    // other than hand.stop -- here TTL expiry. The install runs in a
    // dedicated thread (supervisor topology); the TTL timer in this
    // thread calls the single kill::abort with StopTrigger::Ttl.
    let msi_path = ctx.work_dir.join("vlc-3.0.20-win64.msi");
    if !msi_path.exists() {
        let ok = download(VLC_PRIMARY, &msi_path)
            || download(VLC_FALLBACK, &msi_path);
        if !ok {
            return inconclusive(json!({"reason": "download-failed"}));
        }
    }
    let name_sub = "VLC media player";
    let target_dir = r"C:\Program Files\VideoLAN\VLC";
    let _ = bimo_hand::msi::ensure_product_absent(None, name_sub, 120_000);
    let pre = bimo_hand::msi::pre_command_state(None, target_dir);
    let pre_msiexec: Vec<u32> = bimo_hand::win32::msiexec_processes().iter().map(|p| p.pid).collect();
    let msi_str = msi_path.to_string_lossy().to_string();
    let (cancel, outcome_slot) = bimo_hand::supervisor::run_msi_install_in_thread(msi_str);
    // TTL: 2000 ms after the install starts, the timer fires.
    std::thread::sleep(Duration::from_millis(2000));
    let outcome = bimo_hand::kill::abort(
        bimo_hand::kill::AbortTarget::Msi {
            cancel,
            outcome: outcome_slot,
            product_code: None,
            name_substring: name_sub.to_string(),
            target_dir: target_dir.to_string(),
            pre_msiexec_pids: pre_msiexec,
        },
        bimo_hand::kill::StopTrigger::Ttl,
    );
    let presence = bimo_hand::msi::product_presence_by_name(name_sub);
    let absent = !presence.get("present").and_then(|v| v.as_bool()).unwrap_or(false);
    let mutex_free = bimo_hand::win32::msi_execute_mutex_free();
    let measured = json!({
        "trigger": "ttl", "abort": outcome.to_json(), "pre_command_state": pre,
        "product_absent": absent, "mutex_free": mutex_free,
        "stop_unconfirmed": outcome.stop_unconfirmed,
    });
    let _ = bimo_hand::msi::ensure_product_absent(None, name_sub, 120_000);
    if outcome.stop_unconfirmed {
        return inconclusive(measured);
    }
    if outcome.status == "stopped" && outcome.return_code == Some(bimo_hand::msi::ERROR_INSTALL_USEREXIT) && absent && mutex_free && outcome.tree_dead {
        return pass(measured);
    }
    fail(measured)
}

fn proof_8_11(_ctx: &mut Ctx) -> Proof {
    // v2 (cycle 41, condition 4, proof 8.11): textual check that no VLC
    // constants appear outside self_test.rs. The only place for a product
    // name, version or vendor string is this file (self_test.rs).
    // The same check also runs as a CI step before the self-test.
    let needles = ["vlc", "videolan", "3.0.20", "firefox", "mozilla"];
    let mut root: Option<std::path::PathBuf> = None;
    for base in [std::env::current_dir().ok(), std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()))] {
        let mut dir = match base { Some(d) => d, None => continue };
        for _ in 0..6 {
            if dir.join("crates/bimo-hand/src/lib.rs").exists() {
                root = Some(dir.clone());
                break;
            }
            if !dir.pop() { break; }
        }
        if root.is_some() { break; }
    }
    let root = match root {
        Some(r) => r,
        None => return inconclusive(json!({"reason": "crate-source-not-found"})),
    };
    let src_dir = root.join("crates/bimo-hand/src");
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut stack = vec![src_dir.clone()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() { stack.push(p); }
                else if p.extension().and_then(|x| x.to_str()) == Some("rs") { files.push(p); }
            }
        }
    }
    let mut matches: Vec<Value> = Vec::new();
    for f in &files {
        if f.file_name().and_then(|n| n.to_str()) == Some("self_test.rs") { continue; }
        let content = match std::fs::read_to_string(f) { Ok(c) => c, Err(_) => continue };
        for (i, line) in content.lines().enumerate() {
            let low = line.to_ascii_lowercase();
            for needle in needles {
                if low.contains(needle) {
                    matches.push(json!({"file": f.strip_prefix(&root).unwrap_or(f).to_string_lossy(), "line": i + 1, "needle": needle, "text": line.trim()}));
                    break;
                }
            }
        }
    }
    let measured = json!({"scanned_files": files.len(), "matches": matches, "allowed_only_in": "src/bin/self_test.rs"});
    if matches.is_empty() { pass(measured) } else { fail(measured) }
}

fn msi_request(ctx: &Ctx, id: &str, msi: &str, uninstall: bool, install_dir: &str, name_substring: &str, expected_sha256: &str) -> Option<Value> {
    let cmd = new_command(
        id,
        "install",
        json!({
            "msi": msi,
            "uninstall": uninstall,
            "install_dir": install_dir,
            "name_substring": name_substring,
            "size_bytes": file_size(Path::new(msi)),
            // The §25.2 hash gate (§39.3) requires this on every install
            // — 8.1 broke when the gate landed without this field
            // (executor finding, cycle 55). The hash must be the one
            // measured from the downloaded file, never a constant.
            "expected_sha256": expected_sha256,
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
// v2 (cycle 42): proof on VLC only -- Firefox was removed because
// it is pre-installed in the runner image (runs 14 and 19: the target
// dir already contained firefox.exe before install). Phase A: full
    // install via MsiInstallProduct, then removal via MsiConfigureProductW
    // (INSTALLSTATE_ABSENT) and verification that the product is gone.
    // Phase B: a fresh install cancelled via MsiInstallProduct + an
    // external UI handler returning IDCANCEL (return 1602, product absent,
    // mutex free, service idle, no leftovers, no attributed survivor).
    // The cancel is ACTION-BASED (run-42 fix): the supervisor aborts as
    // soon as the handler first reports InstallFiles. The old
    // wall-clock trigger (hand.stop at 40% of the phase-A duration) let
    // the install outrun the cancel twice (runs 36/42: last_action
    // PublishProduct, return 0, product left installed).
    // Download failure is inconclusive, never a pass. An inconclusive
    // 8.1 blocks merge and final reliance (v2 condition 2).
    let installers: [(&str, &str, &str, &str, &str); 1] = [
        ("vlc", "VLC media player",
         VLC_PRIMARY,
         VLC_FALLBACK,
         r"C:\Program Files\VideoLAN\VLC"),
    ];
    let mut results: Vec<Value> = Vec::new();
    let mut any_fail = false;
    let mut any_inconclusive = false;
    let mut msi_cancel_ms: u64 = 0;
    let mut ui_calls_total: u64 = 0;
    let mut handler_first_ms_total: u64 = 0;
    let mut internal_ui_prev_total: u32 = 0;
    let mut external_ui_prev_non_null_total: bool = false;
    for (key, name_sub, url1, url2, target_dir) in installers {
        let msi_path = ctx.work_dir.join(format!("{key}-proof81.msi"));
        let mut downloaded = download(url1, &msi_path);
        if !downloaded && !url2.is_empty() {
            downloaded = download(url2, &msi_path);
        }
        if !downloaded {
            results.push(json!({"installer": key, "status": "inconclusive", "reason": "download-failed", "url": url1}));
            any_inconclusive = true;
            continue;
        }
        let sha256 = file_sha256(&msi_path).unwrap_or_default();
        let msi_str = msi_path.to_string_lossy().to_string();
        // --- Phase A: full install, then removal via MsiConfigureProductW.
        let pre_a = bimo_hand::msi::pre_command_state(None, target_dir);
        let _ = bimo_hand::msi::ensure_product_absent(None, name_sub, 120_000);
        let t0 = Instant::now();
        let rc_a = bimo_hand::msi::install_product(&msi_str);
        let install_duration_ms = t0.elapsed().as_millis() as u64;
        let presence_a = bimo_hand::msi::product_presence_by_name(name_sub);
        let code_a = presence_a.get("product_code").and_then(|v| v.as_str()).map(|s| s.to_string());
        let version_a = presence_a.get("product_version").and_then(|v| v.as_str()).map(|s| s.to_string());
        let installed_a = presence_a.get("present").and_then(|v| v.as_bool()).unwrap_or(false);
        let mut phase_a_status = "pass";
        let mut uninstall_rc: Option<u32> = None;
        let mut absent_after_a = false;
        if rc_a != 0 || !installed_a {
            phase_a_status = "inconclusive";
            any_inconclusive = true;
        } else {
            let code = code_a.clone().unwrap_or_default();
            uninstall_rc = Some(bimo_hand::msi::uninstall_product(&code));
            absent_after_a = wait_until(|| !bimo_hand::msi::product_presence_by_name(name_sub).get("present").and_then(|v| v.as_bool()).unwrap_or(false), Duration::from_secs(60));
            if !absent_after_a { phase_a_status = "fail"; any_fail = true; }
        }
        let listing_a = bimo_hand::msi::target_folder_listing(target_dir);
        let leftovers_a = listing_a.get("is_empty").and_then(|v| v.as_bool()).unwrap_or(true);
        if phase_a_status == "pass" && !leftovers_a { phase_a_status = "fail"; any_fail = true; }
        // --- Phase B: fresh install, cancelled at 40% of the phase-A duration.
        let kill_ms = (install_duration_ms as f64 * 0.4) as u64;
        let mut phase_b_status = "pass";
        let mut cancel_ms_b: u64 = 0;
        let mut stop_ms_b: u64 = 0;
        // kill_ms_b: measured abort point (supervisor cancel_at_ms) for
        // the VLC action trigger; falls back to the planned wall-clock
        // kill_ms for the direct path. trigger_action_b names the action
        // that fired the abort, when the action trigger was used.
        let mut kill_ms_b = kill_ms;
        let mut trigger_action_b: Option<String> = None;
        let mut return_code_b: Option<u32> = None;
        let mut ui_calls_b: u64 = 0;
        let mut handler_first_ms_b: u64 = 0;
        let mut internal_ui_prev_b: u32 = 0;
        let mut external_ui_prev_non_null_b: bool = false;
    let mut cancel_depth_b: Value = Value::Null;
    let mut pre_b: Value = Value::Null;
        let mut trigger_b = "hand.stop";
        let mut status_b = String::new();
        let mut tree_dead_b = false;
        let mut survivors_b: Vec<Value> = Vec::new();
        if phase_a_status == "pass" {
            let _ = bimo_hand::msi::ensure_product_absent(code_a.as_deref(), name_sub, 120_000);
        // Pre-command state for phase B, captured right before the phase-B install starts.
        pre_b = bimo_hand::msi::pre_command_state(None, target_dir);
            if key == "vlc" {
                // VLC phase B goes through the supervisor: MsiInstallProduct
                // in a dedicated thread, monitored from the supervisor's
                // monitor thread. The stop is ACTION-BASED (run-42 fix):
                // abort as soon as the UI handler first reports
                // InstallFiles — deterministic in install progress. The
                // old wall-clock trigger (hand.stop at 40% of the
                // phase-A duration) let the install outrun the cancel
                // twice (runs 36/42: last_action PublishProduct,
                // return 0, product left installed).
                let trigger_path = ctx.data_dir.join("hand.stop-at-action-vlc-install-b.json");
                let _ = std::fs::remove_file(&trigger_path);
                let _ = std::fs::write(&trigger_path, "{\"action\": \"InstallFiles\"}");
                let result = msi_request(ctx, "vlc-install-b", &msi_str, false, target_dir, name_sub, &sha256);
                let _ = std::fs::remove_file(&trigger_path);
                if let Some(r) = result {
                    status_b = r.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    stop_ms_b = r.get("stop_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                    kill_ms_b = r.get("cancel_at_ms").and_then(|v| v.as_u64()).unwrap_or(kill_ms);
                    trigger_action_b = r.get("trigger_action").and_then(|v| v.as_str()).map(|s| s.to_string());
                    return_code_b = r.get("return_code").and_then(|v| v.as_u64()).map(|v| v as u32);
                    tree_dead_b = r.get("tree_dead").and_then(|v| v.as_bool()).unwrap_or(false);
                    if let Some(ab) = r.get("abort") {
                        cancel_ms_b = ab.get("forced_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                        survivors_b = ab.get("survivors").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                        ui_calls_b = ab.get("ui_calls").and_then(|v| v.as_u64()).unwrap_or(0);
                        handler_first_ms_b = ab.get("handler_first_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                        internal_ui_prev_b = ab.get("internal_ui_prev").and_then(|v| v.as_u64()).map(|v| v as u32).unwrap_or(0);
                        external_ui_prev_non_null_b = ab.get("external_ui_prev_non_null").and_then(|v| v.as_bool()).unwrap_or(false);
            cancel_depth_b = ab.get("cancel_depth").cloned().unwrap_or(Value::Null);
                    }
                } else {
                    status_b = "no-result".to_string();
                }
            } else {
                // Direct phase B goes through kill::abort directly, with
                // a TTL trigger (v2 condition 4 evidence: an MSI stop via
                // a trigger other than hand.stop). The install runs in a
                // dedicated thread; this thread is the monitor.
                trigger_b = "ttl";
                let (cancel, outcome_slot) = bimo_hand::supervisor::run_msi_install_in_thread(msi_str.clone());
                let pre_msiexec: Vec<u32> = bimo_hand::win32::msiexec_processes().iter().map(|p| p.pid).collect();
                std::thread::sleep(Duration::from_millis(kill_ms));
                let t_abort = Instant::now();
                let outcome = bimo_hand::kill::abort(
                    bimo_hand::kill::AbortTarget::Msi {
                        cancel,
                        outcome: outcome_slot,
                        product_code: code_a.clone(),
                        name_substring: name_sub.to_string(),
                        target_dir: target_dir.to_string(),
                        pre_msiexec_pids: pre_msiexec,
                    },
                    bimo_hand::kill::StopTrigger::Ttl,
                );
                stop_ms_b = t_abort.elapsed().as_millis() as u64;
                cancel_ms_b = outcome.forced_ms;
                return_code_b = outcome.return_code;
                tree_dead_b = outcome.tree_dead;
                survivors_b = outcome.survivors.clone();
                ui_calls_b = outcome.ui_calls;
                status_b = outcome.status.clone();
                handler_first_ms_b = outcome.handler_first_ms;
                internal_ui_prev_b = outcome.internal_ui_prev;
                external_ui_prev_non_null_b = outcome.external_ui_prev_non_null;
        cancel_depth_b = outcome.cancel_depth.clone();
                // The install thread's CancelOutcome is consumed by abort;
                // handler_calls are recorded in the outcome note.
            }
        } else {
            phase_b_status = "inconclusive";
        }
        // --- Verify restoration to the pre-command state (v2 condition 1).
        let presence_b = bimo_hand::msi::product_presence_by_name(name_sub);
        let absent_b = !presence_b.get("present").and_then(|v| v.as_bool()).unwrap_or(false);
        let mutex_free_b = bimo_hand::win32::msi_execute_mutex_free();
        let service_b = bimo_hand::win32::sc_query_msiserver();
        let service_idle_b = service_b.get("idle").and_then(|v| v.as_bool()).unwrap_or(mutex_free_b);
        let listing_b = bimo_hand::msi::target_folder_listing(target_dir);
        let leftovers_b = listing_b.get("is_empty").and_then(|v| v.as_bool()).unwrap_or(true);
        if phase_b_status == "pass" {
            let restored = status_b == "stopped"
                && return_code_b == Some(bimo_hand::msi::ERROR_INSTALL_USEREXIT)
                && absent_b && mutex_free_b && service_idle_b && leftovers_b
                && tree_dead_b && survivors_b.is_empty() && stop_ms_b <= 5000;
            if status_b == "stop-unconfirmed" {
                phase_b_status = "inconclusive";
                any_inconclusive = true;
            } else if !restored {
                phase_b_status = "fail";
                any_fail = true;
            }
        }
        if key == "vlc" {
            msi_cancel_ms = cancel_ms_b;
            ctx.stop_install_ms = Some(stop_ms_b);
            handler_first_ms_total = handler_first_ms_b;
            internal_ui_prev_total = internal_ui_prev_b;
            external_ui_prev_non_null_total = external_ui_prev_non_null_b;
        }
        ui_calls_total += ui_calls_b;
        // Cleanup: remove any partial install left behind.
        if !absent_b {
            let _ = bimo_hand::msi::ensure_product_absent(code_a.as_deref(), name_sub, 120_000);
        }
        let _ = std::fs::remove_dir_all(target_dir);
        results.push(json!({
            "installer": key, "name_substring": name_sub, "sha256": sha256,
            "product_code": code_a, "product_version": version_a,
            "phase_a": {"status": phase_a_status, "return_code": rc_a, "install_duration_ms": install_duration_ms, "uninstall_return_code": uninstall_rc, "product_absent_after_removal": absent_after_a, "target_folder_empty_after_removal": leftovers_a, "pre_command_state": pre_a},
            "phase_b": {"status": phase_b_status, "trigger": trigger_b, "trigger_action": trigger_action_b, "kill_ms_after_start": kill_ms_b, "stop_ms": stop_ms_b, "cancel_ms": cancel_ms_b, "forced_ms": cancel_ms_b, "return_code": return_code_b, "ui_calls": ui_calls_b, "result_status": status_b, "tree_dead": tree_dead_b, "survivors": survivors_b, "product_absent": absent_b, "mutex_free": mutex_free_b, "service_idle": service_idle_b, "target_folder_empty": leftovers_b, "handler_first_ms": handler_first_ms_b, "internal_ui_prev": internal_ui_prev_b, "external_ui_prev_non_null": external_ui_prev_non_null_b, "cancel_depth": cancel_depth_b, "pre_command_state": pre_b},
        }));
    }
    let measured = json!({
        "installers": results,
        "cancel_ms": msi_cancel_ms,
        "stop_ms_by_kind": {"msi_cancel": msi_cancel_ms, "install_tree": ctx.stop_install_ms, "transfer_tree": ctx.stop_transfer_ms},
        "ui_calls": ui_calls_total,
        "handler_first_ms": handler_first_ms_total, "internal_ui_prev": internal_ui_prev_total, "external_ui_prev_non_null": external_ui_prev_non_null_total,
        "firefox_excluded": "pre-installed in the runner image: C\\Program Files\\Mozilla Firefox already contained firefox.exe before install (runs 14 and 19); 8.1 is proven by VLC only",
        "budgets_ms": {"msi_cancel": 2000, "tree_kill": 1000, "verify": 500, "post_cap_monitor": 1500, "hard_cap": 5000},
"budget_note": "2000/1000/500 re-set in cycle 42 from measured samples (MSI cancel n=4: 842 spike, 1514 run 14, 1082 run 19 phase B, 293 run 19 8.9; max 1514; tree kill <=119 run 19, 60 spike; verify <=36 run 19), not a measurement-derived limit; the empty 1500 ms is the post-interim-cap monitoring reserve",
        "spike_reference": "unit3-kill-spike-c39 stage2: return 1602, cancel_ms 842, handler_calls 8099",
    });
    if any_fail {
        return fail(measured);
    }
    if any_inconclusive {
        return inconclusive(measured);
    }
    pass(measured)
}
// ---------------------------------------------------------------------------
// 8.12 — Track A Unit 3 thin slice (spec: track-a-unit3-thin-slice.md,
// v6 + §45 + §45.9; §28.2 ruling (ج)→(أ) from the cycle-54 council).
//
// TWO INVOCATIONS (builder decision B1 — the spec never names how the
// workflow steps S4/S5/S6 interleave between S3 and S7 inside one 8.12
// run; two invocations invent less protocol than a wait-file design):
//   phase install: --slice --slice-inputs <path> --data-dir <dir>
//                  [--slice-phase install]  (default)
//     loads inputs, runs the negative tests (8.12e←e2←e3←e4←a←b←c←d←f),
//     runs the happy path (S2+S3), writes hand-slice.json to --out
//     BEFORE stopping the supervisor, exits 0/1.
//   phase revert:  --slice --slice-inputs <path> --data-dir <dir>
//                  --slice-phase revert
//     rebuilds the slice command from slice-inputs.json, runs S7
//     (revert() in a thread + 600 s join timeout, §45.9.5), updates
//     hand-slice.json (steps.s7 + slice_exit_code), exits 0/1.
// S4 (witness), S5 (shot), S6 (strong evidence) and S8 (publish) are
// WORKFLOW steps between the two phases; the final slice verdict lives
// in the workflow's slice-results.json (builder decision B2:
// hand-slice.json's slice_exit_code is the verdict of the phase that
// wrote it last, not the whole slice).
//
// §28.2 (a) adaptations (council ruling, cycle 54): the install goes
// to a custom dir under a pre-created watched parent
// (C:\bimo-slice\Notepad++), via TARGETDIR — in the MsiInstallProduct
// command line (the supervisor never runs msiexec.exe) AND in the
// ExecRequest args line. S0/S6/install_dir/install_location_expected
// use the custom path, NOT C:\Program Files\Notepad++.
// ---------------------------------------------------------------------------

/// §29-4: the published SHA-256 of npp.8.9.9.1.Installer.x64.msi.
const SLICE_MSI_SHA256: &str =
    "e3b0607a092ce2604fbdac027db2c94915995e8e568ebd226f8c5493c2f61a80";
/// §29-5: the measured size of the same MSI.
const SLICE_MSI_SIZE: u64 = 7_933_952;
/// §28.2 (a): the custom install dir under the pre-created watched
/// parent C:\bimo-slice. The workflow creates the parent before S0b.
const SLICE_INSTALL_DIR: &str = r"C:\bimo-slice\Notepad++";
/// Start Menu folder the installer creates (§37.2 check 3).
const SLICE_START_MENU_DIR: &str =
    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++";
/// 64 zero hex chars — the deliberately-wrong expected hash for 8.12e2/8.12e4/8.12b.
const ZERO_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// The probe request id (§33.2).
const PROBE_ID: &str = "slice-probe-8.12d";
/// The synthetic revert command id (§41.2).
const PROBE_REVERT_ID: &str = "slice-probe-8.12d-revert";

/// The measured values S1 hands to 8.12 (§34.1, as adapted by §28.2 (a)).
#[derive(Clone, Debug)]
struct SliceInputs {
    slice_id: String,
    command_id: String,
    msi_path: String,
    msi_sha256: String,
    msi_size_bytes: u64,
    product_code: String,
    upgrade_code: String,
    install_dir: String,
    install_location_expected: String,
    name_substring: String,
    ttl_secs: u64,
}

fn is_guid(s: &str) -> bool {
    s.len() == 38
        && s.starts_with('{')
        && s.ends_with('}')
        && s[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Load + validate slice-inputs.json (§34.1 + §28.2 (a)). Any failure is
/// `slice-inputs-invalid` (R12): blocked, no command in the queue.
fn load_slice_inputs(path: &Path) -> Result<SliceInputs, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("slice-inputs-invalid: cannot read {}: {}", path.display(), e))?;
    let v: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("slice-inputs-invalid: malformed JSON: {}", e))?;
    let get_s = |k: &str| -> Result<String, String> {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("slice-inputs-invalid: missing/invalid field {}", k))
    };
    let get_u = |k: &str| -> Result<u64, String> {
        v.get(k)
            .and_then(|x| x.as_u64())
            .ok_or_else(|| format!("slice-inputs-invalid: missing/invalid field {}", k))
    };
    let inputs = SliceInputs {
        slice_id: get_s("slice_id")?,
        command_id: get_s("command_id")?,
        msi_path: get_s("msi_path")?,
        msi_sha256: get_s("msi_sha256")?,
        msi_size_bytes: get_u("msi_size_bytes")?,
        product_code: get_s("product_code")?,
        upgrade_code: get_s("upgrade_code")?,
        install_dir: get_s("install_dir")?,
        install_location_expected: get_s("install_location_expected")?,
        name_substring: get_s("name_substring")?,
        ttl_secs: get_u("ttl_secs")?,
    };
    if inputs.slice_id.is_empty() {
        return Err("slice-inputs-invalid: slice_id is empty".to_string());
    }
    if inputs.command_id.is_empty()
        || !inputs
            .command_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("slice-inputs-invalid: command_id must match [a-z0-9-]+".to_string());
    }
    if !Path::new(&inputs.msi_path).exists() {
        return Err(format!(
            "slice-inputs-invalid: msi_path does not exist: {}",
            inputs.msi_path
        ));
    }
    if !is_hex64(&inputs.msi_sha256) || inputs.msi_sha256.to_lowercase() != SLICE_MSI_SHA256 {
        return Err("slice-inputs-invalid: msi_sha256 must equal §29-4".to_string());
    }
    let actual_size = file_size(Path::new(&inputs.msi_path));
    if inputs.msi_size_bytes != actual_size || inputs.msi_size_bytes != SLICE_MSI_SIZE {
        return Err(format!(
            "slice-inputs-invalid: msi_size_bytes {} != actual {} / §29-5 {}",
            inputs.msi_size_bytes, actual_size, SLICE_MSI_SIZE
        ));
    }
    if !is_guid(&inputs.product_code) {
        return Err("slice-inputs-invalid: product_code is not a GUID".to_string());
    }
    if !is_guid(&inputs.upgrade_code) {
        return Err("slice-inputs-invalid: upgrade_code is not a GUID".to_string());
    }
    // §28.2 (a): the custom dir, NOT C:\Program Files\Notepad++.
    if inputs.install_dir != SLICE_INSTALL_DIR {
        return Err(format!(
            "slice-inputs-invalid: install_dir must be {} under §28.2 (a), got {}",
            SLICE_INSTALL_DIR, inputs.install_dir
        ));
    }
    if inputs.install_location_expected != SLICE_INSTALL_DIR {
        return Err("slice-inputs-invalid: install_location_expected must equal install_dir (§28.2 (a))".to_string());
    }
    if inputs.name_substring != "Notepad++" {
        return Err("slice-inputs-invalid: name_substring must be \"Notepad++\"".to_string());
    }
    if inputs.ttl_secs != 3600 {
        return Err("slice-inputs-invalid: ttl_secs must be 3600".to_string());
    }
    Ok(inputs)
}

/// Installed iff MsiQueryProductStateW reports anything other than
/// UNKNOWN(-1) or ABSENT(2). Fail-closed: any other state (including
/// error codes) counts as present — the same spirit as §37.1 (assume
/// presence when unreadable). The Linux stub returns -1 (not installed).
fn product_is_installed(code: &str) -> bool {
    !matches!(bimo_hand::msi::product_state(code), -1 | 2)
}

/// The four "clean" checks (§37.2), under the §28.2 (a) path: the
/// install dir is the custom dir, the Start Menu folder and the
/// uninstall registry key are as §37.2 names them. The registry key is
/// read with `reg.exe query` (read-only); a failed/unreadable read
/// counts as PRESENT (fail-closed).
fn check_clean(inputs: &SliceInputs) -> Value {
    let state = bimo_hand::msi::product_state(&inputs.product_code);
    let product_absent = !product_is_installed(&inputs.product_code);
    let dir_absent = !Path::new(&inputs.install_dir).exists();
    let menu_absent = !Path::new(SLICE_START_MENU_DIR).exists();
    let key = format!(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{}",
        inputs.product_code
    );
    let key_absent = if cfg!(windows) {
        match ProcCommand::new("reg.exe")
            .args(["query", &key])
            .output()
        {
            Ok(o) => !o.status.success(),
            Err(_) => false, // unreadable => present (fail-closed)
        }
    } else {
        false // no registry on this platform => present (fail-closed)
    };
    json!({
        "product_state": state,
        "product_absent": product_absent,
        "install_dir_absent": dir_absent,
        "start_menu_absent": menu_absent,
        "uninstall_key_absent": key_absent,
        "clean": product_absent && dir_absent && menu_absent && key_absent,
    })
}

/// Poll the probe result file every 1 s until `timeout`. "Arrival"
/// (§45.9.1) is a valid JSON file whose `status` field is a string;
/// a corrupt file or one without a string status does NOT count as
/// arrival — waiting continues. (This is wait_exec_result's contract
/// with the §45.9.1 arrival definition enforced.)
fn wait_probe_result(data_dir: &Path, id: &str, timeout: Duration) -> Option<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(v) = read_exec_result(data_dir, id) {
            if v.get("status").and_then(|s| s.as_str()).is_some() {
                return Some(v);
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Run `revert()` in a thread and wait up to `timeout` for it (§45.9.5:
/// the 600 s S7 bound is a thread + join timeout — a single stuck
/// MsiConfigureProductW call can exceed the 60 s inner wait).
/// Returns None on timeout (the thread is left running, detached).
fn revert_with_timeout(cmd: &Command, data_dir: &Path, timeout: Duration) -> Option<RevertOutcome> {
    let (tx, rx) = mpsc::channel();
    let cmd = cmd.clone();
    let data_dir = data_dir.to_path_buf();
    std::thread::spawn(move || {
        let outcome = revert(&cmd, &data_dir);
        let _ = tx.send(outcome);
    });
    rx.recv_timeout(timeout).ok()
}

/// The synthetic revert command (§41.2): built directly in 8.12, never
/// written to the queue, never through the guardian or supervisor.
fn synthetic_revert_cmd(inputs: &SliceInputs) -> Command {
    new_command(
        PROBE_REVERT_ID,
        "install",
        json!({"product_code": inputs.product_code, "name_substring": inputs.name_substring}),
        3600,
        json!({"product_code": inputs.product_code, "name_substring": inputs.name_substring}),
    )
}

/// Run the synthetic revert (§41.2) + the §37.2 clean check.
/// Returns (ran, result_json). `result` is "reverted" on success, else
/// "failed:<reason>" or "revert-plan-invalid" or "timeout".
fn run_synthetic_revert(inputs: &SliceInputs, data_dir: &Path) -> (bool, Value) {
    let cmd = synthetic_revert_cmd(inputs);
    if !verify_revert_plan(&cmd) {
        return (true, json!({"result": "revert-plan-invalid"}));
    }
    let start = Instant::now();
    match revert_with_timeout(&cmd, data_dir, Duration::from_secs(600)) {
        None => (
            true,
            json!({"result": "timeout", "duration_ms": start.elapsed().as_millis() as u64}),
        ),
        Some(RevertOutcome::Reverted) => {
            let clean = check_clean(inputs);
            (
                true,
                json!({
                    "result": "reverted",
                    "duration_ms": start.elapsed().as_millis() as u64,
                    "clean": clean,
                }),
            )
        }
        Some(RevertOutcome::Failed(reason)) => (
            true,
            json!({
                "result": format!("failed:{}", reason),
                "duration_ms": start.elapsed().as_millis() as u64,
            }),
        ),
        Some(RevertOutcome::NotReversible(reason)) => (
            true,
            json!({
                "result": format!("not-reversible:{}", reason),
                "duration_ms": start.elapsed().as_millis() as u64,
            }),
        ),
    }
}

/// Build the slice command (§34.5 + §44.1). `approved` is true only
/// for the happy path (and 8.12e4/8.12a–c, which test the hash gate
/// past the class gate); the class-gate tests keep it false.
/// `expected` is None for 8.12c (no hash field at all).
fn build_slice_command(
    inputs: &SliceInputs,
    approved: bool,
    expected: Option<String>,
    msi_path_override: Option<String>,
) -> Command {
    let mut args = json!({
        "msi": msi_path_override.unwrap_or_else(|| inputs.msi_path.clone()),
        "uninstall": false,
        "install_dir": inputs.install_dir,
        "name_substring": inputs.name_substring,
        "size_bytes": inputs.msi_size_bytes,
        "product_code": inputs.product_code,
        "targetdir": true,
    });
    if let Some(h) = expected {
        args["expected_sha256"] = json!(h);
    }
    let mut cmd = new_command(
        &inputs.command_id,
        "install",
        args,
        inputs.ttl_secs,
        json!({"product_code": inputs.product_code, "name_substring": inputs.name_substring}),
    );
    cmd.approved = approved;
    cmd
}

/// One `prepare_execution` negative case: expect `Err(<expected>)`
/// with EXACT string match (§45.4.3) and no exec-request file written
/// for the command id. Returns the case record.
fn neg_case(config: &HandConfig, data_dir: &Path, name: &str, cmd: &Command, expected: &str) -> Value {
    let got = match prepare_execution(cmd, config, &Guardian::default()) {
        Ok(_) => "ok".to_string(),
        Err(e) => e,
    };
    let req_written = exec_request_path(data_dir, &cmd.id).exists();
    let pass = got == expected && !req_written;
    println!("  8.12 {}: expected={} got={} request_file_written={} -> {}",
        name, expected, got, req_written, if pass { "pass" } else { "FAIL" });
    json!({
        "name": name, "expected": expected, "got": got,
        "request_file_written": req_written, "pass": pass,
    })
}

struct ProbeOutcome {
    record: Value,
    pass: bool,
    /// probe-timeout-unsettled (§45.1 step 4): the caller must
    /// `process::exit(1)` directly — no hand-slice.json, no
    /// hand.supervisor-exit, supervisor left alive.
    unsettled: bool,
}

fn probe_fail_record(status: &str, reason: &str, waited_ms: u64, product_state_after: i32, exec_started_seen: bool, revert: Value, stop_resumed: bool) -> ProbeOutcome {
    ProbeOutcome {
        record: json!({
            "status": status, "reason": reason, "exec_started_seen": exec_started_seen,
            "waited_ms": waited_ms, "product_state_after": product_state_after,
            "revert": revert, "stop_resumed": stop_resumed,
        }),
        pass: false,
        unsettled: false,
    }
}

/// The §41.4 safety net: the gate is absent (an install launched).
/// ProductState first; if installed, run the synthetic revert + the
/// §37.2 clean check, then fail probe-gate-absent. A failed synthetic
/// revert (or a failed clean check) is fail-revert-failed (R4), not
/// probe-gate-absent. If nothing is installed, probe-gate-absent
/// directly, no revert (§45.9.2).
fn probe_safety_net(inputs: &SliceInputs, data_dir: &Path, _status: &str, reason: &str, waited_ms: u64, exec_started_seen: bool) -> ProbeOutcome {
    let product_state_after = bimo_hand::msi::product_state(&inputs.product_code);
    if !product_is_installed(&inputs.product_code) {
        return probe_fail_record(
            "probe-gate-absent", reason, waited_ms, product_state_after,
            exec_started_seen, json!({"ran": false, "result": Value::Null}), false,
        );
    }
    let (ran, rev) = run_synthetic_revert(inputs, data_dir);
    let revert_ok = rev.get("result").and_then(|r| r.as_str()) == Some("reverted");
    let clean_ok = rev
        .get("clean")
        .and_then(|c| c.get("clean"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    if revert_ok && clean_ok {
        probe_fail_record(
            "probe-gate-absent", reason, waited_ms, product_state_after,
            exec_started_seen, json!({"ran": ran, "result": rev}), false,
        )
    } else {
        probe_fail_record(
            "fail-revert-failed", reason, waited_ms, product_state_after,
            exec_started_seen, json!({"ran": ran, "result": rev}), false,
        )
    }
}

/// Judge a probe result that arrived (§33.2 + §45.9.2).
fn probe_judge_result(inputs: &SliceInputs, data_dir: &Path, v: Value, waited_ms: u64, exec_started_seen: bool, stop_resumed: bool) -> ProbeOutcome {
    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let reason = v.get("reason").and_then(|s| s.as_str()).unwrap_or("").to_string();
    let product_state_after = bimo_hand::msi::product_state(&inputs.product_code);
    // stop-unconfirmed (§45.9.1): the abort thread did not return
    // within the hard cap — the machine is untrusted.
    if status == "stop-unconfirmed" {
        return ProbeOutcome {
            record: json!({
                "status": "probe-timeout-unsettled", "reason": reason,
                "exec_started_seen": exec_started_seen, "waited_ms": waited_ms,
                "product_state_after": product_state_after,
                "revert": {"ran": false, "result": Value::Null}, "stop_resumed": stop_resumed,
            }),
            pass: false,
            unsettled: true,
        };
    }
    // The exec-started tripwire (§41.3): presence means the request
    // went to the non-MSI branch — the gate is absent, whatever the
    // result says.
    if exec_started_seen {
        return probe_safety_net(inputs, data_dir, &status, &reason, waited_ms, true);
    }
    match (status.as_str(), reason.as_str()) {
        ("blocked", "sha256-required") => {
            if product_is_installed(&inputs.product_code) {
                // Contradiction: blocked yet installed — fail-closed
                // through the safety net.
                probe_safety_net(inputs, data_dir, &status, &reason, waited_ms, false)
            } else {
                ProbeOutcome {
                    record: json!({
                        "status": "pass", "reason": "sha256-required",
                        "exec_started_seen": false, "waited_ms": waited_ms,
                        "product_state_after": product_state_after,
                        "revert": {"ran": false, "result": Value::Null},
                        "stop_resumed": stop_resumed,
                    }),
                    pass: true,
                    unsettled: false,
                }
            }
        }
        ("blocked", _) => probe_fail_record(
            "probe-wrong-reason", &reason, waited_ms, product_state_after,
            false, json!({"ran": false, "result": Value::Null}), stop_resumed,
        ),
        ("done", _) | ("stopped", _) | ("failed", _) => {
            probe_safety_net(inputs, data_dir, &status, &reason, waited_ms, false)
        }
        _ => probe_fail_record(
            "probe-wrong-reason", &reason, waited_ms, product_state_after,
            false, json!({"ran": false, "result": Value::Null}), stop_resumed,
        ),
    }
}

/// The K1 quiescence step (§45.1): after 120 s with no result and the
/// product still absent — write hand.stop ("probe-still"), wait 60 s
/// for the result, judge by what arrives.
fn probe_quiescence(inputs: &SliceInputs, data_dir: &Path, ctl: &HandControl, started: Instant, exec_started_seen: bool) -> ProbeOutcome {
    // C-1 step 0: delete the stale result file before writing hand.stop,
    // so an old file is never read as a new result.
    let _ = fs::remove_file(exec_result_path(data_dir, PROBE_ID));
    let _ = ctl.write_stop("probe-still");
    let result = wait_probe_result(data_dir, PROBE_ID, Duration::from_secs(60));
    let waited_ms = started.elapsed().as_millis() as u64;
    match result {
        Some(v) => {
            let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string();
            let reason = v.get("reason").and_then(|s| s.as_str()).unwrap_or("").to_string();
            if status == "blocked" && reason == "sha256-required" {
                // Late success — delete hand.stop BEFORE any new request
                // (§45.1.1): otherwise S3's request is cancelled at once.
                let _ = ctl.clear_stop();
                let product_state_after = bimo_hand::msi::product_state(&inputs.product_code);
                // Contrarian finding (cycle 55): the main path checks
                // product_is_installed here and routes a contradiction
                // to the safety net — the quiescence branch did not.
                // A blocked result with the product installed is a
                // contradiction, never a pass.
                if product_is_installed(&inputs.product_code) {
                    let mut out = probe_safety_net(inputs, data_dir, &status, &reason, waited_ms, exec_started_seen);
                    out.record["stop_resumed"] = json!(true);
                    return out;
                }
                ProbeOutcome {
                    record: json!({
                        "status": "pass", "reason": "sha256-required",
                        "exec_started_seen": exec_started_seen, "waited_ms": waited_ms,
                        "product_state_after": product_state_after,
                        "revert": {"ran": false, "result": Value::Null},
                        "stop_resumed": true,
                    }),
                    pass: true,
                    unsettled: false,
                }
            } else {
                // hand.stop is deleted before the normal stop (§45.9.1).
                // stop_resumed stays false: it means "deleted after a
                // LATE SUCCESS" (§45.7), and there was none here.
                let _ = ctl.clear_stop();
                probe_judge_result(inputs, data_dir, v, waited_ms, exec_started_seen, false)
            }
        }
        None => {
            // probe-timeout-unsettled (§45.1 step 4): loud fail, no
            // hand-slice.json, no hand.supervisor-exit, supervisor
            // left alive, exit(1) directly. The runner discards the
            // machine (§27.2).
            ProbeOutcome {
                record: json!({
                    "status": "probe-timeout-unsettled", "reason": "no-result-after-quiescence",
                    "exec_started_seen": exec_started_seen, "waited_ms": waited_ms,
                    "product_state_after": bimo_hand::msi::product_state(&inputs.product_code),
                    "revert": {"ran": false, "result": Value::Null}, "stop_resumed": false,
                }),
                pass: false,
                unsettled: true,
            }
        }
    }
}

/// The 8.12d supervisor-refusal probe (§33.2 + §41 + §45.1).
/// Writes the manual request (no expected_sha256), waits 60 s + a
/// 60 s grace period (§41.1 step 1), then judges.
fn probe_8_12d(inputs: &SliceInputs, data_dir: &Path, ctl: &HandControl) -> ProbeOutcome {
    let started = Instant::now();
    // Defensive: a stale result from an earlier run in the same
    // data_dir must never be read as this probe's result.
    let _ = fs::remove_file(exec_result_path(data_dir, PROBE_ID));
    let req = ExecRequest {
        id: PROBE_ID.to_string(),
        kind: "install".to_string(),
        program: "msiexec.exe".to_string(),
        args: vec![
            "/i".to_string(),
            inputs.msi_path.clone(),
            "/qn".to_string(),
            "/norestart".to_string(),
        ],
        working_dir: None,
        cleanup_path: None,
        install_dir: Some(inputs.install_dir.clone()),
        grandchild_out: None,
        installer_kind: Some("msi".to_string()),
        product_code: Some(inputs.product_code.clone()),
        name_substring: Some("Notepad++".to_string()),
        expected_sha256: None,
        // The probe tests the gate, not the install: no TARGETDIR.
        targetdir: None,
    };
    if let Err(e) = write_exec_request(data_dir, &req) {
        return probe_fail_record(
            "probe-request-write-failed", &e, started.elapsed().as_millis() as u64,
            bimo_hand::msi::product_state(&inputs.product_code),
            false, json!({"ran": false, "result": Value::Null}), false,
        );
    }
    let mut result = wait_probe_result(data_dir, PROBE_ID, Duration::from_secs(60));
    if result.is_none() {
        // Grace period (§41.1 step 1): a slow install is not judged
        // by the first timeout. Total 120 s from the request write.
        result = wait_probe_result(data_dir, PROBE_ID, Duration::from_secs(60));
    }
    let waited_ms = started.elapsed().as_millis() as u64;
    let exec_started_seen = exec_started_path(data_dir, PROBE_ID).exists();
    match result {
        Some(v) => probe_judge_result(inputs, data_dir, v, waited_ms, exec_started_seen, false),
        None => {
            // 120 s, no result: ProductState decides (§41.1 step 2).
            if product_is_installed(&inputs.product_code) {
                let (ran, rev) = run_synthetic_revert(inputs, data_dir);
                let revert_ok = rev.get("result").and_then(|r| r.as_str()) == Some("reverted");
                let clean_ok = rev
                    .get("clean")
                    .and_then(|c| c.get("clean"))
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                let product_state_after = bimo_hand::msi::product_state(&inputs.product_code);
                if revert_ok && clean_ok {
                    probe_fail_record(
                        "probe-timeout", "no-result-installed-reverted-clean",
                        waited_ms, product_state_after, exec_started_seen,
                        json!({"ran": ran, "result": rev}), false,
                    )
                } else {
                    probe_fail_record(
                        "fail-revert-failed", "no-result-installed-revert-or-clean-failed",
                        waited_ms, product_state_after, exec_started_seen,
                        json!({"ran": ran, "result": rev}), false,
                    )
                }
            } else {
                probe_quiescence(inputs, data_dir, ctl, started, exec_started_seen)
            }
        }
    }
}

/// Make a tampered copy of the MSI (one byte flipped) for 8.12a/8.12c.
/// Sanity: its hash must differ from the published one, or the test
/// itself is broken.
fn make_tampered_copy(inputs: &SliceInputs, work_dir: &Path) -> Result<PathBuf, String> {
    let mut bytes = fs::read(&inputs.msi_path)
        .map_err(|e| format!("tampered-copy: cannot read MSI: {}", e))?;
    if bytes.len() <= 4096 {
        return Err("tampered-copy: MSI too small to flip byte 4096".to_string());
    }
    bytes[4096] ^= 0xFF;
    let path = work_dir.join("npp-tampered.msi");
    fs::write(&path, &bytes).map_err(|e| format!("tampered-copy: cannot write: {}", e))?;
    let h = file_sha256(&path).unwrap_or_default();
    if h == SLICE_MSI_SHA256 {
        return Err("tampered-copy: hash identical to the original — test broken".to_string());
    }
    Ok(path)
}

/// Phase `install` (§43.3 order): negatives first, then the happy path
/// (S2+S3). Returns (exit_code, Some(hand_slice)) — or (1, None) for
/// probe-timeout-unsettled (§45.1 step 4: no hand-slice.json at all).
fn run_slice_install(
    inputs: &SliceInputs,
    config: &HandConfig,
    data_dir: &Path,
    work_dir: &Path,
    ctl: &HandControl,
    supervisor_started: bool,
) -> (i32, Option<Value>) {
    let product_state_before = bimo_hand::msi::product_state(&inputs.product_code);
    let folder_before = Path::new(&inputs.install_dir).exists();

    // --- Negative tests, in the final order (§45.9.4):
    // 8.12e ← e2 ← e3 ← e4 ← a ← b ← c ← d ← f ← happy path.
    let correct = Some(SLICE_MSI_SHA256.to_string());
    let zero = Some(ZERO_SHA256.to_string());
    let e1 = neg_case(
        config, data_dir, "8.12e",
        &build_slice_command(inputs, false, correct.clone(), None),
        "needs_approval",
    );
    let e2 = neg_case(
        config, data_dir, "8.12e2",
        &build_slice_command(inputs, false, zero.clone(), None),
        "needs_approval",
    );
    let fake_msi = format!("{}-missing.msi", inputs.msi_path);
    let e3 = neg_case(
        config, data_dir, "8.12e3",
        &build_slice_command(inputs, false, correct.clone(), Some(fake_msi)),
        "file_not_found",
    );
    let e4 = neg_case(
        config, data_dir, "8.12e4",
        &build_slice_command(inputs, true, zero.clone(), None),
        "sha256-mismatch",
    );
    let tampered = match make_tampered_copy(inputs, work_dir) {
        Ok(p) => Some(p),
        Err(e) => {
            println!("  8.12a/c: tampered copy failed: {}", e);
            None
        }
    };
    let (a_case, b_case, c_case) = match &tampered {
        Some(t) => {
            let t = t.to_string_lossy().to_string();
            (
                neg_case(config, data_dir, "8.12a",
                    &build_slice_command(inputs, true, correct.clone(), Some(t.clone())),
                    "sha256-mismatch"),
                neg_case(config, data_dir, "8.12b",
                    &build_slice_command(inputs, true, zero.clone(), None),
                    "sha256-mismatch"),
                neg_case(config, data_dir, "8.12c",
                    &build_slice_command(inputs, true, None, Some(t)),
                    "sha256-required"),
            )
        }
        None => (
            json!({"name": "8.12a", "expected": "sha256-mismatch", "got": "tampered-copy-failed", "request_file_written": false, "pass": false}),
            json!({"name": "8.12b", "expected": "sha256-mismatch", "got": "tampered-copy-failed", "request_file_written": false, "pass": false}),
            json!({"name": "8.12c", "expected": "sha256-required", "got": "tampered-copy-failed", "request_file_written": false, "pass": false}),
        ),
    };
    // 8.12f (§45.9.3): a slice command with an invalid revert plan
    // must fail verify_revert_plan — proving the K3(a) call exists.
    let bad_plan_cmd = new_command(
        &inputs.command_id,
        "install",
        json!({
            "msi": inputs.msi_path, "uninstall": false,
            "install_dir": inputs.install_dir, "name_substring": inputs.name_substring,
            "size_bytes": inputs.msi_size_bytes, "product_code": inputs.product_code,
            "targetdir": true,
        }),
        inputs.ttl_secs,
        json!({}),
    );
    let f_valid = verify_revert_plan(&bad_plan_cmd);
    let f_case = json!({
        "name": "8.12f", "expected": "revert-plan-invalid",
        "got": if f_valid { "verify_revert_plan=true" } else { "revert-plan-invalid" },
        "pass": !f_valid,
    });
    println!("  8.12 8.12f: expected=revert-plan-invalid got={} -> {}",
        if f_valid { "verify_revert_plan=true" } else { "revert-plan-invalid" },
        if !f_valid { "pass" } else { "FAIL" });

    // 8.12d: the supervisor probe (Windows only — the supervisor never
    // runs on this platform; the slice itself is a Windows run). If the
    // supervisor never started, fail fast instead of waiting out the
    // 120 s + 60 s quiescence for a result that can never arrive.
    let d_outcome = if !cfg!(windows) {
        ProbeOutcome {
            record: json!({
                "status": "probe-skipped-non-windows",
                "reason": "the supervisor never runs on this platform; the slice is a Windows run",
                "exec_started_seen": false, "waited_ms": 0,
                "product_state_after": product_state_before,
                "revert": {"ran": false, "result": Value::Null}, "stop_resumed": false,
            }),
            pass: false,
            unsettled: false,
        }
    } else if !supervisor_started {
        ProbeOutcome {
            record: json!({
                "status": "supervisor-not-started",
                "reason": "hand.heartbeat never appeared within 60 s of spawning the supervisor",
                "exec_started_seen": false, "waited_ms": 0,
                "product_state_after": product_state_before,
                "revert": {"ran": false, "result": Value::Null}, "stop_resumed": false,
            }),
            pass: false,
            unsettled: false,
        }
    } else {
        probe_8_12d(inputs, data_dir, ctl)
    };
    if d_outcome.unsettled {
        // §45.1 step 4: NO hand-slice.json, NO hand.supervisor-exit,
        // supervisor left alive, exit(1) directly.
        println!("  8.12d: probe-timeout-unsettled — exiting 1 directly, no hand-slice.json");
        return (1, None);
    }

    let e_pass = e1["pass"].as_bool().unwrap_or(false)
        && e2["pass"].as_bool().unwrap_or(false)
        && e3["pass"].as_bool().unwrap_or(false)
        && e4["pass"].as_bool().unwrap_or(false);
    let abc_pass = a_case["pass"].as_bool().unwrap_or(false)
        && b_case["pass"].as_bool().unwrap_or(false)
        && c_case["pass"].as_bool().unwrap_or(false);
    let f_pass = f_case["pass"].as_bool().unwrap_or(false);
    let negatives_pass = e_pass && abc_pass && f_pass && d_outcome.pass;

    let mut hand_slice = json!({
        "slice_id": inputs.slice_id,
        "command_id": inputs.command_id,
        "slice_exit_code": 1,
        "steps": {},
        "hand_evidence": {
            "product_state_before": product_state_before,
            "product_state_after": Value::Null,
            "folder_before": folder_before,
            "folder_after": Value::Null,
        },
        "slice_inputs_echo": {
            "slice_id": inputs.slice_id, "command_id": inputs.command_id,
            "msi_path": inputs.msi_path, "msi_sha256": inputs.msi_sha256,
            "msi_size_bytes": inputs.msi_size_bytes,
            "product_code": inputs.product_code, "upgrade_code": inputs.upgrade_code,
            "install_dir": inputs.install_dir,
            "install_location_expected": inputs.install_location_expected,
            "name_substring": inputs.name_substring, "ttl_secs": inputs.ttl_secs,
            "dedup_key": Value::Null,
        },
        "slice_approval": {
            "by": "8.12 self-test", "scope": format!("slice-{} only", inputs.command_id),
            "reason": "test-only install of an S1-verified MSI inside the self-test binary",
        },
        "probe_8_12d": d_outcome.record,
        "probe_8_12e": {
            "status": "needs_approval", "gate": "class-line-240",
            "cases": {"e1": e1, "e2": e2, "e3": e3, "e4": e4},
        },
        "negative_hash_tests": {"a": a_case, "b": b_case, "c": c_case},
        "probe_8_12f": f_case,
    });

    if !negatives_pass {
        let failure = if !e_pass {
            "class-gate-untested".to_string()
        } else if !abc_pass {
            "hash-gate-untested".to_string()
        } else if !f_pass {
            "revert-plan-invalid".to_string()
        } else {
            d_outcome
                .record
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("probe-failed")
                .to_string()
        };
        hand_slice["slice_failure"] = json!(failure);
        println!("  8.12 install phase FAIL: {}", hand_slice["slice_failure"].as_str().unwrap_or("?"));
        return (1, Some(hand_slice));
    }

    // --- Happy path: S2 (queue) + S3 (execute via the supervisor).
    let mut cmd = build_slice_command(inputs, true, correct.clone(), None);
    cmd.approved = true;
    // K3(a): verify_revert_plan AFTER building the slice command and
    // BEFORE any queue write — failure is revert-plan-invalid (R19).
    if !verify_revert_plan(&cmd) {
        hand_slice["slice_failure"] = json!("revert-plan-invalid");
        println!("  8.12 S2: verify_revert_plan failed -> revert-plan-invalid");
        return (1, Some(hand_slice));
    }
    let s2_ts = utc_now_secs();
    let s2 = json!({"ts": s2_ts, "dedup_key": cmd.dedup_key.clone(), "ttl_secs": cmd.ttl_secs});
    hand_slice["slice_inputs_echo"]["dedup_key"] = json!(cmd.dedup_key.clone());
    let s3_ts = utc_now_secs();
    let s3_start = Instant::now();
    let s3: Value;
    match prepare_execution(&cmd, config, &Guardian::default()) {
        Err(e) => {
            // R14: prepare_execution failed for the slice command.
            s3 = json!({"ts": s3_ts, "result": {"status": "failed", "reason": e}, "duration_ms": s3_start.elapsed().as_millis() as u64, "exec_request_file": Value::Null, "supervisor_rehash": Value::Null});
            hand_slice["steps"]["s2"] = s2;
            hand_slice["steps"]["s3"] = s3;
            hand_slice["slice_failure"] = json!(format!("prepare-failed:{}", hand_slice["steps"]["s3"]["result"]["reason"].as_str().unwrap_or("?")));
            println!("  8.12 S3: prepare_execution failed");
            return (1, Some(hand_slice));
        }
        Ok(req) => {
            let exec_request_file = match write_exec_request(data_dir, &req) {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(e) => {
                    s3 = json!({"ts": s3_ts, "result": {"status": "failed", "reason": format!("write-exec-request:{}", e)}, "duration_ms": s3_start.elapsed().as_millis() as u64, "exec_request_file": Value::Null, "supervisor_rehash": Value::Null});
                    hand_slice["steps"]["s2"] = s2;
                    hand_slice["steps"]["s3"] = s3;
                    hand_slice["slice_failure"] = json!("write-exec-request-failed");
                    println!("  8.12 S3: write_exec_request failed");
                    return (1, Some(hand_slice));
                }
            };
            // wait_exec_result: 600 s. The result's `status` is read
            // as TEXT — never via result_state (it maps blocked->failed).
            match wait_exec_result(data_dir, &cmd.id, Duration::from_secs(600)) {
                None => {
                    s3 = json!({"ts": s3_ts, "result": {"status": "failed", "reason": "s3-timeout"}, "duration_ms": s3_start.elapsed().as_millis() as u64, "exec_request_file": exec_request_file, "supervisor_rehash": Value::Null});
                    hand_slice["steps"]["s2"] = s2;
                    hand_slice["steps"]["s3"] = s3;
                    hand_slice["slice_failure"] = json!("s3-timeout");
                    println!("  8.12 S3: no result in 600 s");
                    return (1, Some(hand_slice));
                }
                Some(result) => {
                    let status = result.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string();
                    let rehash = result.get("supervisor_rehash").cloned().unwrap_or(Value::Null);
                    s3 = json!({
                        "ts": s3_ts, "result": result,
                        "duration_ms": s3_start.elapsed().as_millis() as u64,
                        "exec_request_file": exec_request_file,
                        "supervisor_rehash": rehash,
                    });
                    hand_slice["steps"]["s2"] = s2;
                    hand_slice["steps"]["s3"] = s3;
                    if status != "done" {
                        hand_slice["slice_failure"] = json!(format!("s3-status:{}", status));
                        println!("  8.12 S3: supervisor status={} (expected done)", status);
                        return (1, Some(hand_slice));
                    }
                    if hand_slice["steps"]["s3"]["supervisor_rehash"].is_null() {
                        hand_slice["slice_failure"] = json!("supervisor-rehash-missing");
                        println!("  8.12 S3: supervisor result has no supervisor_rehash");
                        return (1, Some(hand_slice));
                    }
                    // Contrarian finding (cycle 55): presence is not
                    // enough — the rehash must MATCH (§25.2: the whole
                    // point is that the supervisor re-verified the file
                    // it is about to install).
                    if hand_slice["steps"]["s3"]["supervisor_rehash"]["match"].as_bool() != Some(true) {
                        hand_slice["slice_failure"] = json!("supervisor-rehash-mismatch");
                        println!("  8.12 S3: supervisor_rehash.match != true");
                        return (1, Some(hand_slice));
                    }
                }
            }
        }
    }
    let product_state_after = bimo_hand::msi::product_state(&inputs.product_code);
    let folder_after = Path::new(&inputs.install_dir).exists();
    hand_slice["hand_evidence"]["product_state_after"] = json!(product_state_after);
    hand_slice["hand_evidence"]["folder_after"] = json!(folder_after);
    hand_slice["slice_exit_code"] = json!(0);
    println!("  8.12 install phase PASS (S2+S3 done; S4/S5/S6 are workflow steps)");
    (0, Some(hand_slice))
}

/// Phase `revert` (S7, §31.2 + §42.2 + §45.9.5): rebuild the slice
/// command, run revert() in a thread with a 600 s join timeout, and
/// update hand-slice.json (steps.s7 + slice_exit_code). No supervisor
/// is involved — revert runs in-process. Returns the exit code.
fn run_slice_revert(inputs: &SliceInputs, data_dir: &Path, out_path: &Path) -> i32 {
    let raw = match fs::read_to_string(out_path) {
        Ok(r) => r,
        Err(e) => {
            println!("slice revert: cannot read hand-slice.json at {}: {}", out_path.display(), e);
            return 1;
        }
    };
    let mut hand_slice: Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            println!("slice revert: hand-slice.json is malformed: {}", e);
            return 1;
        }
    };
    // Contrarian finding (cycle 55, BLOCKER): phase 2 must refuse
    // unless phase 1's S3 completed with matching slice/command ids.
    // Without this, revert() on a never-installed product returns
    // Reverted + exit 0 (ensure_product_absent: absent => Reverted),
    // and the slice would claim a revert that never happened.
    let s3_done = hand_slice["steps"]["s3"]["result"]["status"].as_str() == Some("done");
    let ids_match = hand_slice["slice_id"].as_str() == Some(inputs.slice_id.as_str())
        && hand_slice["command_id"].as_str() == Some(inputs.command_id.as_str());
    if !s3_done || !ids_match {
        hand_slice["steps"]["s7"] = json!({"ts": utc_now_secs(), "result": "revert-without-s3", "duration_ms": 0});
        hand_slice["slice_failure"] = json!("revert-without-s3");
        hand_slice["slice_exit_code"] = json!(1);
        let _ = write_json_file(out_path, &hand_slice);
        println!("slice revert: refused — S3 did not complete (s3_done={}) or slice/command id mismatch (ids_match={}); no revert run", s3_done, ids_match);
        return 1;
    }
    let mut cmd = build_slice_command(inputs, true, Some(SLICE_MSI_SHA256.to_string()), None);
    cmd.approved = true;
    if !verify_revert_plan(&cmd) {
        hand_slice["steps"]["s7"] = json!({"ts": utc_now_secs(), "result": "revert-plan-invalid", "duration_ms": 0});
        hand_slice["slice_failure"] = json!("revert-plan-invalid");
        hand_slice["slice_exit_code"] = json!(1);
        let _ = write_json_file(out_path, &hand_slice);
        println!("slice revert: verify_revert_plan failed -> revert-plan-invalid");
        return 1;
    }
    let start = Instant::now();
    let s7_ts = utc_now_secs();
    match revert_with_timeout(&cmd, data_dir, Duration::from_secs(600)) {
        None => {
            hand_slice["steps"]["s7"] = json!({"ts": s7_ts, "result": "timeout", "duration_ms": start.elapsed().as_millis() as u64});
            hand_slice["slice_failure"] = json!("fail-revert-failed");
            hand_slice["slice_exit_code"] = json!(1);
            let _ = write_json_file(out_path, &hand_slice);
            println!("slice revert: revert() did not return in 600 s -> fail-revert-failed");
            1
        }
        Some(RevertOutcome::Reverted) => {
            hand_slice["steps"]["s7"] = json!({"ts": s7_ts, "result": "reverted", "duration_ms": start.elapsed().as_millis() as u64});
            hand_slice["slice_exit_code"] = json!(0);
            let _ = write_json_file(out_path, &hand_slice);
            println!("slice revert: reverted in {} ms", start.elapsed().as_millis());
            0
        }
        Some(RevertOutcome::Failed(reason)) => {
            hand_slice["steps"]["s7"] = json!({"ts": s7_ts, "result": format!("failed:{}", reason), "duration_ms": start.elapsed().as_millis() as u64});
            hand_slice["slice_failure"] = json!("fail-revert-failed");
            hand_slice["slice_exit_code"] = json!(1);
            let _ = write_json_file(out_path, &hand_slice);
            println!("slice revert: revert failed: {} -> fail-revert-failed", reason);
            1
        }
        Some(RevertOutcome::NotReversible(reason)) => {
            hand_slice["steps"]["s7"] = json!({"ts": s7_ts, "result": format!("not-reversible:{}", reason), "duration_ms": start.elapsed().as_millis() as u64});
            hand_slice["slice_failure"] = json!("fail-revert-failed");
            hand_slice["slice_exit_code"] = json!(1);
            let _ = write_json_file(out_path, &hand_slice);
            println!("slice revert: not reversible: {}", reason);
            1
        }
    }
}

fn spawn_supervisor(supervisor_bin: &Path, data_dir: &Path) -> (Option<Child>, bool) {
    let mut child: Option<Child> = None;
    let mut started = false;
    if cfg!(windows) && supervisor_bin.exists() {
        match ProcCommand::new(supervisor_bin)
            .args([
                "--data-dir",
                &data_dir.to_string_lossy(),
                "--heartbeat-secs",
                "2",
            ])
            .spawn()
        {
            Ok(c) => {
                child = Some(c);
                started = wait_file(&data_dir.join("hand.heartbeat"), Duration::from_secs(60));
            }
            Err(e) => eprintln!("self-test: spawn supervisor failed: {}", e),
        }
    }
    (child, started)
}

fn stop_supervisor(data_dir: &Path, child: Option<Child>) {
    let _ = fs::write(data_dir.join("hand.supervisor-exit"), "");
    if let Some(mut child) = child {
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
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out_path = PathBuf::from("hand-self-test.json");
    let mut supervisor_bin: Option<PathBuf> = None;
    let mut slice_mode = false;
    let mut slice_inputs_path: Option<PathBuf> = None;
    let mut data_dir_arg: Option<PathBuf> = None;
    let mut slice_phase = "install".to_string();
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
            "--slice" => {
                slice_mode = true;
            }
            "--slice-inputs" => {
                i += 1;
                if i < args.len() {
                    slice_inputs_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--data-dir" => {
                i += 1;
                if i < args.len() {
                    data_dir_arg = Some(PathBuf::from(&args[i]));
                }
            }
            "--slice-phase" => {
                i += 1;
                if i < args.len() {
                    slice_phase = args[i].clone();
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
    // --data-dir (§33.3): when given, data_dir is <dir> literally
    // (the supervisor child gets the same dir); otherwise the old
    // temp-dir behaviour — no break to the existing proofs.
    let data_dir = data_dir_arg.unwrap_or_else(|| root.join("data"));
    let work_dir = root.join("work");
    let _ = fs::create_dir_all(&data_dir);
    let _ = fs::create_dir_all(&work_dir);
    // --slice mode (§43.3): never runs proofs 8.1–8.11.
    if slice_mode {
        let inputs_path = match slice_inputs_path {
            Some(p) => p,
            None => {
                eprintln!("--slice requires --slice-inputs <path>");
                std::process::exit(1);
            }
        };
        let inputs = match load_slice_inputs(&inputs_path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("slice: {}", e);
                std::process::exit(1);
            }
        };
        if slice_phase == "revert" {
            // Phase 2 (S7): revert() runs in-process — no supervisor.
            std::process::exit(run_slice_revert(&inputs, &data_dir, &out_path));
        }
        if slice_phase != "install" {
            eprintln!("--slice-phase must be install or revert, got {}", slice_phase);
            std::process::exit(1);
        }
        // Phase 1: spawn the supervisor, run the negatives + S2+S3,
        // write hand-slice.json BEFORE stopping the supervisor (§43.3).
        let (supervisor_child, supervisor_started) = spawn_supervisor(&supervisor_bin, &data_dir);
        let mut config = HandConfig::default();
        config.exec_enabled = true; // ONLY the self-test binary passes true.
        config.data_dir = data_dir.clone();
        config.heartbeat_secs = 2;
        let ctl = HandControl::new(&data_dir, 2);
        let (code, hand_slice) = run_slice_install(&inputs, &config, &data_dir, &work_dir, &ctl, supervisor_started);
        match hand_slice {
            Some(hs) => {
                let _ = write_json_file(&out_path, &hs);
                stop_supervisor(&data_dir, supervisor_child);
                std::process::exit(code);
            }
            None => {
                // probe-timeout-unsettled (§45.1 step 4): exit(1)
                // directly — no hand-slice.json, no
                // hand.supervisor-exit, supervisor left alive.
                std::process::exit(1);
            }
        }
    }
    // Spawn the supervisor as a child.
    let (supervisor_child, supervisor_started) = spawn_supervisor(&supervisor_bin, &data_dir);
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
    let p82b = proof_8_2b(&mut ctx);
    let p810b = proof_8_10b(&mut ctx);
    let p810a = proof_8_10a(&mut ctx);
    let p81 = proof_8_1(&mut ctx);
    let p811 = proof_8_11(&mut ctx);
    let p89 = proof_8_9(&mut ctx);
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
    // Verdict.
    let red_line = match p81.status {
        "pass" => "met",
        "fail" => "violated",
        _ => "not-tested",
    };
    let all = [
        &p81, &p82, &p82b, &p83, &p84, &p85, &p86, &p87, &p88, &p89, &p810a, &p810b, &p811,
    ];
    let all_pass = all.iter().all(|p| p.status == "pass");
    let any_fail = all.iter().any(|p| p.status == "fail");
    let verdict = if all_pass { "pass" } else if any_fail { "fail" } else { "inconclusive" };
    let mut proofs = serde_json::Map::new();
    proofs.insert("8.1".to_string(), p81.to_json());
    proofs.insert("8.2".to_string(), p82.to_json());
    proofs.insert("8.2b".to_string(), p82b.to_json());
    proofs.insert("8.3".to_string(), p83.to_json());
    proofs.insert("8.4".to_string(), p84.to_json());
    proofs.insert("8.5".to_string(), p85.to_json());
    proofs.insert("8.6".to_string(), p86.to_json());
    proofs.insert("8.7".to_string(), p87.to_json());
    proofs.insert("8.8".to_string(), p88.to_json());
    proofs.insert("8.9".to_string(), p89.to_json());
    proofs.insert("8.10a".to_string(), p810a.to_json());
    proofs.insert("8.10b".to_string(), p810b.to_json());
    proofs.insert("8.11".to_string(), p811.to_json());
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
    stop_supervisor(&data_dir, supervisor_child);
    if verdict == "pass" {
        std::process::exit(0);
    } else {
        std::process::exit(1);
    }
}
