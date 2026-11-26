//! Stages 0 and 1 (MSI install, job kill) + shared helpers.
//!
//! Stage 0 reproduces c38 proof 8.1 exactly: the same VLC MSI,
//! the same 40% kill point of the calibrated install duration,
//! the same elevated supervisor, the same job without breakaway,
//! and the old stop (TerminateJobObject only). It also records
//! the identity of every survivor — exe path, PPID, session,
//! user (SYSTEM vs user) and IsProcessInJob — so the c38
//! survivor (PID 4568) can be named for what it is.
//!
//! Stage 1 repeats the scenario with the PPID tree kill.
//! "tree_dead" is reported in two senses, kept apart on purpose:
//! * `client_tree_dead` — the msiexec client and its PPID
//!   descendants are all gone (what the tree kill can do);
//! * `tree_dead` — the c38 sense: no installer process at all
//!   survives, including a new msiexec service process. The
//!   service process is not a job member and not a descendant of
//!   the client, so a tree kill cannot be expected to remove it;
//!   its survival is reported separately instead of being
//!   counted as a tree-kill failure.

use crate::msi;
use crate::stop::{self, StopResult};
use crate::win32;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const VLC_URL: &str = "https://get.videolan.org/vlc/3.0.20/win64/vlc-3.0.20-win64.msi";
pub const VLC_SHA256: &str = "ce1fe655b7cd8e11a55dde25502f42e0bf0a9d3bc0556583b6a841fa37e88f02";
pub const ONE_GB: u64 = 1024 * 1024 * 1024;

pub fn sha256_file(path: &Path) -> Result<String, String> {
  use std::io::Read;
  let mut f = fs::File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
  let mut h = Sha256::new();
  let mut buf = [0u8; 65536];
  loop {
    let n = f.read(&mut buf).map_err(|e| format!("read {}: {}", path.display(), e))?;
    if n == 0 {
      break;
    }
    h.update(&buf[..n]);
  }
  Ok(format!("{:x}", h.finalize()))
}

/// Download the MSI (curl.exe first, PowerShell fallback).
pub fn download_msi(url: &str, dest: &Path) -> Result<Value, String> {
  let dest_s = dest.to_string_lossy().to_string();
  let curl = std::process::Command::new("curl.exe")
    .args(["-L", "--fail", "--retry", "1", "-o", &dest_s, url])
    .output();
  match curl {
    Ok(o) if o.status.success() => {
      return Ok(json!({ "method": "curl.exe", "return_code": 0 }));
    }
    Ok(o) => {
      let _ = o;
    }
    Err(_) => {}
  }
  let ps_cmd = format!("Invoke-WebRequest -UseBasicParsing -Uri '{}' -OutFile '{}'", url, dest_s);
  let ps = std::process::Command::new("powershell.exe")
    .args(["-NoProfile", "-Command", &ps_cmd])
    .output()
    .map_err(|e| format!("powershell download failed to start: {}", e))?;
  if ps.status.success() {
    Ok(json!({ "method": "powershell Invoke-WebRequest", "return_code": 0 }))
  } else {
    Err(format!(
      "download failed (curl + powershell); powershell stderr: {}",
      String::from_utf8_lossy(&ps.stderr)
    ))
  }
}

/// Full silent install (plain msiexec, not in a job) to calibrate
/// the install duration, then uninstall again.
pub fn calibrate_install(msi_path: &Path) -> Value {
  let pre_absent = msi::ensure_vlc_absent(120_000);
  let path_s = msi_path.to_string_lossy().to_string();
  let start = Instant::now();
  let mut child = match std::process::Command::new("msiexec.exe")
    .args(["/i", &path_s, "/qn", "/norestart"])
    .spawn()
  {
    Ok(c) => c,
    Err(e) => {
      return json!({
        "install_duration_ms": null,
        "error": format!("msiexec spawn failed: {}", e),
        "pre_absent": pre_absent,
      });
    }
  };
  let mut exit_code: Option<i32> = None;
  let mut timed_out = false;
  loop {
    match child.try_wait() {
      Ok(Some(s)) => {
        exit_code = s.code();
        break;
      }
      Ok(None) => {
        if start.elapsed() > Duration::from_secs(180) {
          timed_out = true;
          let _ = child.kill();
          break;
        }
        std::thread::sleep(Duration::from_millis(200));
      }
      Err(e) => {
        return json!({
          "install_duration_ms": start.elapsed().as_millis() as u64,
          "error": format!("try_wait failed: {}", e),
          "pre_absent": pre_absent,
        });
      }
    }
  }
  let duration_ms = start.elapsed().as_millis() as u64;
  let installed_after = msi::vlc_presence();
  let uninstall = msi::ensure_vlc_absent(120_000);
  json!({
    "install_duration_ms": duration_ms,
    "exit_code": exit_code,
    "timed_out": timed_out,
    "installed_after": installed_after,
    "uninstall": uninstall,
    "pre_absent": pre_absent,
  })
}

/// Poll until VLC is absent, up to `timeout_ms`.
pub fn poll_product_absent(timeout_ms: u64) -> Value {
  let start = Instant::now();
  loop {
    let presence = msi::vlc_presence();
    if presence["present"].as_bool() != Some(true) {
      return json!({
        "product_absent": true,
        "waited_ms": start.elapsed().as_millis() as u64,
        "presence": presence,
      });
    }
    if start.elapsed().as_millis() as u64 >= timeout_ms {
      return json!({
        "product_absent": false,
        "waited_ms": start.elapsed().as_millis() as u64,
        "presence": presence,
      });
    }
    std::thread::sleep(Duration::from_millis(2000));
  }
}

/// Wait until no install is running (mutex free and no msiexec).
pub fn wait_msi_idle(timeout_ms: u64) -> Value {
  let start = Instant::now();
  loop {
    let free = win32::msi_execute_mutex_free();
    let busy: Vec<Value> = win32::msiexec_processes().iter().map(|p| p.to_json()).collect();
    if free && busy.is_empty() {
      return json!({
        "msi_idle": true,
        "waited_ms": start.elapsed().as_millis() as u64,
        "msiexec_remaining": busy,
      });
    }
    if start.elapsed().as_millis() as u64 >= timeout_ms {
      return json!({
        "msi_idle": false,
        "waited_ms": start.elapsed().as_millis() as u64,
        "mutex_free": free,
        "msiexec_remaining": busy,
      });
    }
    std::thread::sleep(Duration::from_millis(1000));
  }
}

fn inconclusive(stage: &str, error: String, extra: Value) -> Value {
  json!({ "status": "inconclusive", "stage": stage, "measured": { "error": error, "extra": extra } })
}

/// One MSI kill run. `mode` is "old" (stage 0) or "tree" (stage 1).
pub fn msi_stage(stage: &str, mode: &str, msi_path: &Path, kill_ms: u64) -> Value {
  let services_pid = win32::services_pid();
  let pre_msiexec: Vec<u32> = win32::msiexec_processes().iter().map(|p| p.pid).collect();
  let pre_absent = msi::ensure_vlc_absent(120_000);
  if pre_absent["product_absent"].as_bool() != Some(true) {
    return inconclusive(
      stage,
      "VLC still installed before the stage".to_string(),
      json!({ "pre_absent": pre_absent }),
    );
  }
  let cmd = format!("msiexec.exe /i \"{}\" /qn /norestart", msi_path.display());
  let mut launched = match win32::launch_in_job(&cmd) {
    Ok(l) => l,
    Err(e) => return inconclusive(stage, format!("launch_in_job failed: {}", e), json!({})),
  };
  let client_pid = launched.pid;
  let client_elevated = win32::process_elevated(client_pid);
  let supervisor_elevated = win32::is_elevated();
  let start = Instant::now();
  let mut early_exit = false;
  while (start.elapsed().as_millis() as u64) < kill_ms {
    if !win32::alive(client_pid) {
      early_exit = true;
      break;
    }
    std::thread::sleep(Duration::from_millis(100));
  }
  let kill_ms_after_start = start.elapsed().as_millis() as u64;
  if early_exit {
    launched.close();
    return inconclusive(
      stage,
      "installer exited before the kill point".to_string(),
      json!({ "client_pid": client_pid, "kill_ms_after_start": kill_ms_after_start }),
    );
  }
  let tree_pids = win32::descendants(client_pid);
  let (tree_at_kill, _) = stop::identify_survivors(client_pid, &tree_pids, Some(launched.job));
  let stop_res: StopResult = if mode == "old" {
    stop::stop_old(client_pid, &tree_pids, launched.job)
  } else {
    stop::stop_tree(client_pid, launched.job)
  };
  // New msiexec processes that appeared for this install (the
  // service process is among them: parent services.exe, SYSTEM,
  // session 0 — it is not a descendant of the client).
  let post_msiexec = win32::msiexec_processes();
  let new_msiexec: Vec<&win32::Proc> = post_msiexec.iter().filter(|p| !pre_msiexec.contains(&p.pid)).collect();
  let service_msiexec: Vec<Value> = new_msiexec
    .iter()
    .filter(|p| p.looks_like_service_msiexec(services_pid))
    .map(|p| p.to_json())
    .collect();
  let new_msiexec_json: Vec<Value> = new_msiexec.iter().map(|p| p.to_json()).collect();
  let service_survives = !service_msiexec.is_empty();
  // Survivors in the c38 sense: client-tree survivors + any new
  // msiexec service process.
  let mut survivors = stop_res.survivors.clone();
  let mut remaining_pids = stop_res.remaining_pids.clone();
  for p in &new_msiexec_json {
    let pid = p["pid"].as_u64().unwrap_or(0) as u32;
    if !remaining_pids.contains(&pid) {
      remaining_pids.push(pid);
      survivors.push(p.clone());
    }
  }
  let tree_dead_c38 = stop_res.tree_dead && new_msiexec.is_empty();
  let product = poll_product_absent(30_000);
  launched.close();
  let idle = wait_msi_idle(90_000);
  let mut measured = json!({
    "msi_url": VLC_URL,
    "msi_sha256": VLC_SHA256,
    "kill_fraction": 0.4,
    "kill_ms_after_start": kill_ms_after_start,
    "client_pid": client_pid,
    "installer_elevated": client_elevated,
    "supervisor_elevated": supervisor_elevated,
    "tree_at_kill": tree_at_kill,
    "tree_pids_at_kill": tree_pids,
    "stop": stop_res.to_json(),
    "stop_ms": stop_res.stop_ms,
    "stop_method": stop_res.method,
    "client_tree_dead": stop_res.tree_dead,
    "tree_dead": tree_dead_c38,
    "survivors": survivors,
    "remaining_pids": remaining_pids,
    "service_msiexec_survives": service_survives,
    "service_msiexec": service_msiexec,
    "new_msiexec_processes": new_msiexec_json,
    "product_after": product,
    "msi_idle_after": idle,
  });
  if stage == "stage0" {
    measured["c38_remaining_pid"] = json!(4568);
    measured["c38_reference"] = json!({
      "proof": "8.1",
      "stop_ms": 5040,
      "tree_dead": false,
      "remaining_pids": [4568],
    });
  }
  let status = if stage == "stage0" {
    // Reproduction passes when the c38 failure reproduces:
    // an installer process survives and the stop runs to the
    // 5 s budget.
    if !tree_dead_c38 && stop_res.stop_ms > 5000 && !remaining_pids.is_empty() {
      "pass"
    } else if tree_dead_c38 {
      "fail"
    } else {
      "inconclusive"
    }
  } else if stop_res.tree_dead && stop_res.stop_ms <= 5000 {
    "pass"
  } else {
    "fail"
  };
  json!({ "status": status, "stage": stage, "measured": measured })
}

pub fn work_dir() -> PathBuf {
  std::env::temp_dir().join(format!("bimo-hand-kill-spike-{}", std::process::id()))
}
