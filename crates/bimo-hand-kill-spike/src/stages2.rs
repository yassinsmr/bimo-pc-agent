//! Stages 2 and 3 + the full run (Windows only).
//!
//! Stage 2 — MSI cancel via the API: MsiInstallProduct with an
//! external UI handler returning IDCANCEL on the stop signal.
//! Pass requires all four checks: the API returns
//! ERROR_INSTALL_USEREXIT (1602), the product is absent, the
//! Global_MSI_Execute mutex is free, and the msiserver service
//! is idle (sc.exe reports RUNNING with no install in progress).
//! A remaining msiexec.exe /V process is the idle service host
//! itself, not an install of our product: it is only counted as
//! "a service msiexec for our product" while the mutex is held.
//!
//! Stage 3 — transfer, c38 proof 8.2 shape: a 1 GB file copied
//! by a child of this binary (--slow-copy) inside the job, killed
//! once progress passes 25%, with the PPID tree kill.

use crate::msi;
use crate::stages::{poll_product_absent, wait_msi_idle, ONE_GB, VLC_SHA256, VLC_URL};
use crate::stop;
use crate::win32;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

fn inconclusive(stage: &str, error: String, extra: Value) -> Value {
  json!({ "status": "inconclusive", "stage": stage, "measured": { "error": error, "extra": extra } })
}

pub fn stage2(msi_path: &Path, cancel_after_ms: u64) -> Value {
  let services_pid = win32::services_pid();
  let pre_msiexec: Vec<u32> = win32::msiexec_processes().iter().map(|p| p.pid).collect();
  let pre_absent = msi::ensure_vlc_absent(120_000);
  if pre_absent["product_absent"].as_bool() != Some(true) {
    return inconclusive(
      "stage2",
      "VLC still installed before the stage".to_string(),
      json!({ "pre_absent": pre_absent }),
    );
  }
  let outcome = msi::install_with_cancel(&msi_path.to_string_lossy(), cancel_after_ms);
  // Let the rollback settle: poll up to 60 s for product absent +
  // mutex free.
  let settle_start = Instant::now();
  let mut presence = msi::vlc_presence();
  let mut mutex_free = win32::msi_execute_mutex_free();
  while !(presence["present"].as_bool() != Some(true) && mutex_free) {
    if settle_start.elapsed() > Duration::from_secs(60) {
      break;
    }
    std::thread::sleep(Duration::from_secs(1));
    presence = msi::vlc_presence();
    mutex_free = win32::msi_execute_mutex_free();
  }
  let settled_ms = settle_start.elapsed().as_millis() as u64;
  let post_msiexec = win32::msiexec_processes();
  let new_msiexec: Vec<Value> = post_msiexec
    .iter()
    .filter(|p| !pre_msiexec.contains(&p.pid))
    .map(|p| p.to_json())
    .collect();
  let service_msiexec_idle: Vec<Value> = post_msiexec
    .iter()
    .filter(|p| p.looks_like_service_msiexec(services_pid))
    .map(|p| p.to_json())
    .collect();
  // A service msiexec counts as "for our product" only while an
  // install is still in progress (mutex held). With the mutex
  // free, a remaining /V process is the idle service host.
  let service_msiexec_for_product: Vec<Value> = if mutex_free { Vec::new() } else { new_msiexec.clone() };
  let sc = win32::sc_query_msiserver();
  let sc_running = sc["state_line"]
    .as_str()
    .map(|s| s.contains("RUNNING"))
    .unwrap_or(false);
  let product_absent = presence["present"].as_bool() != Some(true);
  let service_idle = sc_running && mutex_free;
  let no_service_msiexec_for_product = service_msiexec_for_product.is_empty();
  let status = if outcome.return_code == msi::ERROR_INSTALL_USEREXIT
    && product_absent
    && mutex_free
    && service_idle
    && no_service_msiexec_for_product
  {
    "pass"
  } else {
    "fail"
  };
  json!({
    "status": status,
    "stage": "stage2",
    "measured": {
      "msi_url": VLC_URL,
      "msi_sha256": VLC_SHA256,
      "cancel_after_ms": cancel_after_ms,
      "msi_return_code": outcome.return_code,
      "msi_return_code_is_user_exit_1602": outcome.return_code == msi::ERROR_INSTALL_USEREXIT,
      "cancel_requested": outcome.cancelled,
      "ui_handler_calls": outcome.handler_calls,
      "cancel_ms": outcome.cancel_ms,
      "install_attempt_total_ms": outcome.total_ms,
      "product_absent": product_absent,
      "product_presence": presence,
      "mutex_global_msi_execute_free": mutex_free,
      "service_idle": service_idle,
      "service_query": sc,
      "no_service_msiexec_for_product": no_service_msiexec_for_product,
      "service_msiexec_for_product": service_msiexec_for_product,
      "service_msiexec_idle_remaining": service_msiexec_idle,
      "new_msiexec_processes": new_msiexec,
      "settled_ms": settled_ms,
    },
  })
}

/// The slow-copy helper: copy `src` to `dst` in 1 MiB chunks,
/// writing progress JSON each chunk. Run as a child of this
/// binary (`--slow-copy <src> <dst> <progress>`).
pub fn slow_copy(src: &str, dst: &str, progress: &str) -> i32 {
  use std::io::{Read, Write};
  let total = fs::metadata(src).map(|m| m.len()).unwrap_or(0);
  let mut inp = match fs::File::open(src) {
    Ok(f) => f,
    Err(_) => return 2,
  };
  let mut out = match fs::File::create(dst) {
    Ok(f) => f,
    Err(_) => return 3,
  };
  let mut buf = vec![0u8; 1024 * 1024];
  let mut copied: u64 = 0;
  loop {
    let n = match inp.read(&mut buf) {
      Ok(n) => n,
      Err(_) => return 4,
    };
    if n == 0 {
      break;
    }
    if out.write_all(&buf[..n]).is_err() {
      return 5;
    }
    copied += n as u64;
    let pct = if total > 0 { copied as f64 / total as f64 * 100.0 } else { 100.0 };
    let _ = fs::write(
      progress,
      format!("{{\"copied_bytes\": {}, \"total_bytes\": {}, \"progress_pct\": {}}}", copied, total, pct),
    );
    std::thread::sleep(Duration::from_millis(10));
  }
  let _ = out.flush();
  0
}

pub fn stage3(work: &Path) -> Value {
  let exe = match std::env::current_exe() {
    Ok(e) => e,
    Err(e) => return inconclusive("stage3", format!("current_exe failed: {}", e), json!({})),
  };
  let src = work.join("transfer-1gb.bin");
  let dst = work.join("transfer-1gb.dst");
  let progress = work.join("transfer-progress.json");
  // Create the 1 GB source file.
  let cstart = Instant::now();
  let create = (|| -> Result<u64, String> {
    use std::io::Write;
    let mut f = fs::File::create(&src).map_err(|e| format!("create source: {}", e))?;
    let chunk = vec![0u8; 8 * 1024 * 1024];
    let mut left = ONE_GB;
    while left > 0 {
      let n = left.min(chunk.len() as u64) as usize;
      f.write_all(&chunk[..n]).map_err(|e| format!("write source: {}", e))?;
      left -= n as u64;
    }
    f.sync_all().map_err(|e| format!("sync source: {}", e))?;
    Ok(fs::metadata(&src).map(|m| m.len()).unwrap_or(0))
  })();
  let create_ms = cstart.elapsed().as_millis() as u64;
  let source_size = match create {
    Ok(s) => s,
    Err(e) => return inconclusive("stage3", e, json!({ "create_ms": create_ms })),
  };
  let cmd = format!(
    "\"{}\" --slow-copy \"{}\" \"{}\" \"{}\"",
    exe.display(),
    src.display(),
    dst.display(),
    progress.display()
  );
  let mut launched = match win32::launch_in_job(&cmd) {
    Ok(l) => l,
    Err(e) => return inconclusive("stage3", format!("launch_in_job failed: {}", e), json!({})),
  };
  let root_pid = launched.pid;
  let supervisor_elevated = win32::is_elevated();
  // Poll progress until it passes 25%.
  let pstart = Instant::now();
  let mut progress_pct = 0.0f64;
  let mut early_exit = false;
  let mut timed_out = false;
  loop {
    if let Ok(text) = fs::read_to_string(&progress) {
      if let Ok(v) = serde_json::from_str::<Value>(&text) {
        if let Some(p) = v["progress_pct"].as_f64() {
          progress_pct = p;
        }
      }
    }
    if progress_pct > 25.0 {
      break;
    }
    if !win32::alive(root_pid) {
      early_exit = true;
      break;
    }
    if pstart.elapsed() > Duration::from_secs(180) {
      timed_out = true;
      break;
    }
    std::thread::sleep(Duration::from_millis(50));
  }
  if early_exit || timed_out {
    launched.close();
    let _ = fs::remove_file(&src);
    let _ = fs::remove_file(&dst);
    return inconclusive(
      "stage3",
      if early_exit { "slow-copy child exited before 25%".to_string() } else { "progress did not reach 25% in 180 s".to_string() },
      json!({ "progress_pct": progress_pct, "create_ms": create_ms }),
    );
  }
  let tree_pids = win32::descendants(root_pid);
  let (tree_at_kill, _) = stop::identify_survivors(root_pid, &tree_pids, Some(launched.job));
  let stop_res = stop::stop_tree(root_pid, launched.job);
  let partial_size = fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
  let partial_existed = dst.exists();
  let partial_cleaned = if partial_existed {
    fs::remove_file(&dst).is_ok() && !dst.exists()
  } else {
    true
  };
  launched.close();
  let _ = fs::remove_file(&src);
  let status = if stop_res.tree_dead && stop_res.stop_ms <= 5000 && partial_cleaned {
    "pass"
  } else {
    "fail"
  };
  json!({
    "status": status,
    "stage": "stage3",
    "measured": {
      "file_size_bytes": ONE_GB,
      "source_size_bytes": source_size,
      "create_source_ms": create_ms,
      "progress_pct_at_kill": progress_pct,
      "supervisor_elevated": supervisor_elevated,
      "root_pid": root_pid,
      "tree_at_kill": tree_at_kill,
      "tree_pids_at_kill": tree_pids,
      "stop": stop_res.to_json(),
      "stop_ms": stop_res.stop_ms,
      "stop_method": stop_res.method,
      "tree_dead": stop_res.tree_dead,
      "survivors": stop_res.survivors,
      "remaining_pids": stop_res.remaining_pids,
      "partial_file_existed": partial_existed,
      "partial_size_bytes": partial_size,
      "partial_cleaned": partial_cleaned,
    },
  })
}

/// Run all four stages and write hand-kill-spike.json.
/// Returns 0 when the JSON was written (whatever the stage
/// verdicts are — this spike measures, it does not gate).
pub fn run_all(out_path: &str) -> i32 {
  let work = crate::stages::work_dir();
  let _ = fs::create_dir_all(&work);
  let msi_path = work.join("vlc-3.0.20-win64.msi");
  let mut msi_info = json!({
    "url": VLC_URL,
    "sha256_expected": VLC_SHA256,
    "sha256_actual": null,
    "sha256_matches": false,
    "size_bytes": null,
    "download": null,
  });
  let mut calibration = Value::Null;
  let mut stage0 = inconclusive("stage0", "MSI download failed".to_string(), json!({}));
  let mut stage1 = inconclusive("stage1", "MSI download failed".to_string(), json!({}));
  let mut stage2v = inconclusive("stage2", "MSI download failed".to_string(), json!({}));
  let mut stage3v = inconclusive("stage3", "MSI download failed".to_string(), json!({}));
  let downloaded = crate::stages::download_msi(VLC_URL, &msi_path);
  let mut ready = false;
  match downloaded {
    Ok(dl) => {
      msi_info["download"] = dl;
      match crate::stages::sha256_file(&msi_path) {
        Ok(sha) => {
          msi_info["sha256_actual"] = json!(sha);
          msi_info["sha256_matches"] = json!(sha == VLC_SHA256);
          msi_info["size_bytes"] = json!(fs::metadata(&msi_path).map(|m| m.len()).unwrap_or(0));
          ready = sha == VLC_SHA256;
          if !ready {
            msi_info["error"] = json!("SHA256 mismatch");
          }
        }
        Err(e) => {
          msi_info["error"] = json!(e);
        }
      }
    }
    Err(e) => {
      msi_info["error"] = json!(e);
    }
  }
  if ready {
    calibration = crate::stages::calibrate_install(&msi_path);
    let install_duration_ms = calibration["install_duration_ms"].as_u64().unwrap_or(0);
    // Kill at 40% of the calibrated duration, as in c38 8.1
    // (kill_ms_after_start 4497 of install_duration_ms 11186).
    let kill_ms = if install_duration_ms > 0 {
      install_duration_ms * 40 / 100
    } else {
      4497
    };
    stage0 = crate::stages::msi_stage("stage0", "old", &msi_path, kill_ms);
    stage1 = crate::stages::msi_stage("stage1", "tree", &msi_path, kill_ms);
    stage2v = stage2(&msi_path, kill_ms);
    let _ = crate::stages::wait_msi_idle(90_000);
    let _ = msi::ensure_vlc_absent(60_000);
    stage3v = stage3(&work);
  }
  let stop_ms_by_kind = json!({
    "install_old": stage0["measured"]["stop_ms"],
    "install_tree": stage1["measured"]["stop_ms"],
    "msi_cancel": stage2v["measured"]["cancel_ms"],
    "transfer_tree": stage3v["measured"]["stop_ms"],
  });
  let doc = json!({
    "spike": "unit3-kill-spike-c39",
    "branch": "unit3-kill-spike-c39",
    "base": "a0354f8",
    "c38_reference": {
      "branch": "unit3-part4-c38",
      "spike_results_head": "3a92c73",
      "proof_8_1": { "stop_ms": 5040, "tree_dead": false, "remaining_pids": [4568] },
      "proof_8_2": { "stop_ms": 5047, "tree_dead": false },
    },
    "runner_note": "does not prove device performance",
    "supervisor_elevated": win32::is_elevated(),
    "msi": msi_info,
    "calibration": calibration,
    "stages": { "stage0": stage0, "stage1": stage1, "stage2": stage2v, "stage3": stage3v },
    "stop_ms_by_kind": stop_ms_by_kind,
  });
  match fs::write(out_path, serde_json::to_string_pretty(&doc).unwrap_or_default()) {
    Ok(()) => {
      println!(
        "hand-kill-spike: stage0={} stage1={} stage2={} stage3={} -> {}",
        stage0["status"].as_str().unwrap_or("?"),
        stage1["status"].as_str().unwrap_or("?"),
        stage2v["status"].as_str().unwrap_or("?"),
        stage3v["status"].as_str().unwrap_or("?"),
        out_path
      );
      0
    }
    Err(e) => {
      eprintln!("hand-kill-spike: failed to write {}: {}", out_path, e);
      1
    }
  }
}
