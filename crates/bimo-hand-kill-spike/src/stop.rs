//! Stop sequences with per-phase timing (Windows only).
//!
//! The original supervisor (crates/bimo-hand, c38) stops in two
//! levels — cooperative (CTRL_BREAK_EVENT, <= 2 s) then forced
//! (TerminateJobObject) — and verifies death until a 5 s total
//! budget. That is why the c38 numbers are all ~5.04 s: the verify
//! loop runs to the budget whenever a process survives, because
//! the survivor is the Windows Installer service process, which
//! TerminateJobObject cannot kill (it is not a job member).
//!
//! This module keeps the same cooperative window and the same 5 s
//! budget, but records every phase separately (cooperative /
//! forced / verify / retry) so the spike can tell a fixed wait
//! apart from a verify loop that runs to its budget. It offers:
//! * `stop_old` — the c38 method, TerminateJobObject only;
//! * `stop_tree` — PPID tree kill (deepest first), then
//!   TerminateJobObject as a second sweep, then a re-enumeration
//!   and one retry by PID for any survivors.

use crate::win32::{self, Handle};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const COOP_WINDOW_MS: u64 = 2000;
pub const MAX_STOP_MS: u64 = 5000;

pub struct StopResult {
  pub method: String,
  pub cooperative_ms: u64,
  pub forced_ms: u64,
  pub verify_ms: u64,
  pub retry_ms: u64,
  pub stop_ms: u64,
  pub tree_dead: bool,
  pub survivors: Vec<Value>,
  pub remaining_pids: Vec<u32>,
  pub job_sweep_ok: Option<bool>,
  pub job_sweep_error: u32,
  pub tree_kill: Vec<Value>,
  pub retry_attempted: bool,
}

impl StopResult {
  pub fn to_json(&self) -> Value {
    json!({
      "method": self.method,
      "cooperative_ms": self.cooperative_ms,
      "forced_ms": self.forced_ms,
      "verify_ms": self.verify_ms,
      "retry_ms": self.retry_ms,
      "stop_ms": self.stop_ms,
      "tree_dead": self.tree_dead,
      "survivors": self.survivors,
      "remaining_pids": self.remaining_pids,
      "job_sweep_ok": self.job_sweep_ok,
      "job_sweep_error": self.job_sweep_error,
      "tree_kill": self.tree_kill,
      "retry_attempted": self.retry_attempted,
    })
  }
}

/// Identify every pid in `pids` (+ `root`) that is still alive.
pub fn identify_survivors(root_pid: u32, pids: &[u32], job: Option<Handle>) -> (Vec<Value>, Vec<u32>) {
  let snap = win32::snapshot();
  let mut map: HashMap<u32, (u32, String)> = HashMap::new();
  for (pid, ppid, name) in &snap {
    map.insert(*pid, (*ppid, name.clone()));
  }
  let mut all: Vec<u32> = vec![root_pid];
  all.extend_from_slice(pids);
  all.sort_unstable();
  all.dedup();
  let mut survivors = Vec::new();
  let mut remaining = Vec::new();
  for pid in all {
    if let Some((ppid, name)) = map.get(&pid) {
      survivors.push(win32::identify(pid, *ppid, name, job).to_json());
      remaining.push(pid);
    }
  }
  (survivors, remaining)
}

/// Poll until every pid in `pids` (+ `root`) is gone or `deadline`
/// passes, then identify the survivors once.
fn verify(root_pid: u32, pids: &[u32], job: Option<Handle>, deadline: Instant) -> (bool, Vec<Value>, Vec<u32>, u64) {
  let start = Instant::now();
  loop {
    let snap = win32::snapshot();
    let alive: HashSet<u32> = snap.iter().map(|(p, _, _)| *p).collect();
    let any = alive.contains(&root_pid) || pids.iter().any(|p| alive.contains(p));
    if !any || Instant::now() >= deadline {
      break;
    }
    std::thread::sleep(Duration::from_millis(50));
  }
  let (survivors, remaining) = identify_survivors(root_pid, pids, job);
  (remaining.is_empty(), survivors, remaining, start.elapsed().as_millis() as u64)
}

/// c38 method: cooperative, then TerminateJobObject only.
pub fn stop_old(root_pid: u32, tree_pids: &[u32], job: Handle) -> StopResult {
  let stop_start = Instant::now();
  let (cooperative_ms, coop_died) = win32::cooperative_phase(root_pid, COOP_WINDOW_MS);
  let mut forced_ms = 0u64;
  let mut job_sweep_ok = None;
  let mut job_sweep_error = 0u32;
  let method;
  if coop_died {
    method = "cooperative".to_string();
  } else {
    method = "forced".to_string();
    let fstart = Instant::now();
    let (ok, err) = win32::terminate_job(job);
    job_sweep_ok = Some(ok);
    job_sweep_error = err;
    forced_ms = fstart.elapsed().as_millis() as u64;
  }
  let deadline = stop_start + Duration::from_millis(MAX_STOP_MS);
  let (tree_dead, survivors, remaining, verify_ms) =
    verify(root_pid, tree_pids, Some(job), deadline);
  StopResult {
    method,
    cooperative_ms,
    forced_ms,
    verify_ms,
    retry_ms: 0,
    stop_ms: stop_start.elapsed().as_millis() as u64,
    tree_dead,
    survivors,
    remaining_pids: remaining,
    job_sweep_ok,
    job_sweep_error,
    tree_kill: Vec::new(),
    retry_attempted: false,
  }
}

/// PPID tree kill: cooperative, then TerminateProcess deepest
/// first, then TerminateJobObject as a second sweep, then
/// re-enumeration and one retry by PID for survivors.
pub fn stop_tree(root_pid: u32, job: Handle) -> StopResult {
  let stop_start = Instant::now();
  let (cooperative_ms, coop_died) = win32::cooperative_phase(root_pid, COOP_WINDOW_MS);
  let mut forced_ms = 0u64;
  let mut job_sweep_ok = None;
  let mut job_sweep_error = 0u32;
  let mut tree_kill: Vec<Value> = Vec::new();
  let method;
  let mut tree_pids: Vec<u32> = Vec::new();
  if coop_died {
    method = "cooperative".to_string();
  } else {
    method = "forced".to_string();
    let fstart = Instant::now();
    tree_pids = win32::descendants(root_pid);
    let dep = win32::depths(root_pid, &tree_pids);
    let mut ordered = tree_pids.clone();
    ordered.sort_by_key(|p| std::cmp::Reverse(dep.get(p).copied().unwrap_or(0)));
    for pid in &ordered {
      let ok = win32::terminate_pid(*pid);
      tree_kill.push(json!({
        "pid": pid,
        "depth": dep.get(pid).copied().unwrap_or(0),
        "terminate_process_ok": ok,
      }));
    }
    let (ok, err) = win32::terminate_job(job);
    job_sweep_ok = Some(ok);
    job_sweep_error = err;
    forced_ms = fstart.elapsed().as_millis() as u64;
  }
  let deadline = stop_start + Duration::from_millis(MAX_STOP_MS);
  let (mut tree_dead, mut survivors, mut remaining, verify_ms) =
    verify(root_pid, &tree_pids, Some(job), deadline);
  let mut retry_ms = 0u64;
  let mut retry_attempted = false;
  if !tree_dead {
    retry_attempted = true;
    let rstart = Instant::now();
    let mut retry_kill: Vec<Value> = Vec::new();
    for pid in remaining.clone() {
      let ok = win32::terminate_pid(pid);
      retry_kill.push(json!({ "pid": pid, "terminate_process_ok": ok }));
    }
    tree_kill.extend(retry_kill);
    let (d2, s2, r2, v2) = verify(
      root_pid,
      &tree_pids,
      Some(job),
      rstart + Duration::from_millis(2000),
    );
    tree_dead = d2;
    survivors = s2;
    remaining = r2;
    retry_ms = rstart.elapsed().as_millis() as u64;
    let _ = v2;
  }
  StopResult {
    method,
    cooperative_ms,
    forced_ms,
    verify_ms,
    retry_ms,
    stop_ms: stop_start.elapsed().as_millis() as u64,
    tree_dead,
    survivors,
    remaining_pids: remaining,
    job_sweep_ok,
    job_sweep_error,
    tree_kill,
    retry_attempted,
  }
}
