//! Unified stop / abort (v2, cycle 41, section 8).
//!
//! There is exactly one kill path in bimo-hand: [`abort`]. Every stop
//! trigger goes through it -- `hand.stop`, TTL expiry, the dead-man
//! switch, and a guardian block -- and it branches only on
//! [`InstallerKind`]. There is no second kill path: the supervisor's
//! `stop_process_group` delegates to `abort`, and no caller terminates
//! a process, a job, or msiexec.exe on its own.
//!
//! * MSI: cancellation is `MsiInstallProduct` + an external UI handler
//!   returning IDCANCEL (see `msi`). `abort` only sets the shared cancel
//!   flag and waits for the rollback; it never kills msiexec.exe, never
//!   runs `net stop msiserver`, and never calls `MsiConfigureProductW`
//!   to cancel. `MsiConfigureProductW` is used for removal in phase A
//!   only (see `msi::uninstall_product`). `forced_ms` for MSI is the
//!   rollback wait: the time from the cancel flag being set until
//!   `MsiInstallProduct` returns.
//! * Non-MSI command: kill the process tree enumerated by PPID, then
//!   kill orphans found by the alternative naming mechanism (creation-
//!   time window + exe path). PPID enumeration does not cover processes
//!   born via `Win32_Process.Create` (COM/WMI): their parent is
//!   wmiprvse, not the command's tree. That is an explicit
//!   acknowledgement, not a claim that PPID covers COM.
//!
//! Budgets (design allocation, not measurement-derived limits): the
//! 1000/2000/500 ms split is a design allocation grounded on single
//! samples only -- MSI cancel 842 ms, tree kill 60 ms, verify 2-4 ms
//! (n = 1, runner only). The empty 1500 ms is the post-interim-cap
//! monitoring reserve (`POST_CAP_MONITOR_MS`).
//!
//! Success (v2 condition 1) is restoration to the pre-command state:
//! state restored + return 1602 (MSI) + the Global_MSI_Execute mutex
//! free + the service idle + no leftovers + no attributed survivor.
//! The kill-tree verification predicate is membership in the kill set:
//! any live process whose PID is in the enumerated tree PID set
//! (including PIDs that were dead when enumerated) is a survivor.
//!
//! If a revert exceeds the hard cap of 5000 ms, the command enters
//! the `stop-unconfirmed` state: the queue must not accept new install
//! commands until Global_MSI_Execute is free, and the supervisor keeps
//! monitoring until a final result is recorded.
use crate::msi;
use crate::win32;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// Hard cap for a revert/stop, in ms (v2 condition 2).
pub const HARD_CAP_MS: u64 = 5000;
/// Design allocation for the MSI cancel (rollback) phase, in ms.
pub const MSI_CANCEL_BUDGET_MS: u64 = 1000;
/// Design allocation for the tree-kill phase, in ms.
pub const TREE_KILL_BUDGET_MS: u64 = 2000;
/// Design allocation for the verification phase, in ms.
pub const VERIFY_BUDGET_MS: u64 = 500;
/// Post-interim-cap monitoring reserve, in ms.
pub const POST_CAP_MONITOR_MS: u64 = 1500;
/// Cooperative window before forcing a tree kill, in ms.
pub const COOP_WINDOW_MS: u64 = 2000;

/// What kind of installer / command is being aborted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallerKind {
    Msi,
    Command,
}

impl InstallerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InstallerKind::Msi => "msi",
            InstallerKind::Command => "command",
        }
    }
}

/// Which trigger asked for the stop. All of them go through `abort`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopTrigger {
    HandStop,
    Ttl,
    DeadMan,
    Guardian,
}

impl StopTrigger {
    pub fn as_str(self) -> &'static str {
        match self {
            StopTrigger::HandStop => "hand.stop",
            StopTrigger::Ttl => "ttl",
            StopTrigger::DeadMan => "dead-man",
            StopTrigger::Guardian => "guardian",
        }
    }
}

/// Target of an abort. `Msi` carries the shared cancel flag and the
/// outcome slot of the dedicated install thread; `Command` carries the
/// tree root and the alternative-naming window.
pub enum AbortTarget {
    Msi {
        cancel: Arc<AtomicBool>,
        outcome: Arc<Mutex<Option<msi::CancelOutcome>>>,
        product_code: Option<String>,
        name_substring: String,
        target_dir: String,
        pre_msiexec_pids: Vec<u32>,
    },
    Command {
        root_pid: u32,
        exe_path: String,
        window_start: SystemTime,
        install_dir: Option<String>,
    },
}

/// Outcome of a single `abort` call, in the unified JSON timing schema.
/// For MSI, `forced_ms` is explicitly the rollback wait.
pub struct AbortOutcome {
    pub status: String,
    pub trigger: String,
    pub installer_kind: String,
    pub stop_ms: u64,
    pub forced_ms: u64,
    pub cooperative_ms: u64,
    pub verify_ms: u64,
    pub return_code: Option<u32>,
    pub tree_dead: bool,
    pub survivors: Vec<Value>,
    pub remaining_pids: Vec<u32>,
    pub handles_released: bool,
    pub product_absent: Option<bool>,
    pub product_state: Option<i32>,
    pub mutex_free: Option<bool>,
    pub service_idle: Option<bool>,
    pub leftovers_empty: Option<bool>,
    pub stop_unconfirmed: bool,
    pub ui_calls: u64,
    pub note: String,
}

impl AbortOutcome {
    pub fn to_json(&self) -> Value {
        json!({
            "status": self.status,
            "trigger": self.trigger,
            "installer_kind": self.installer_kind,
            "stop_ms": self.stop_ms,
            "forced_ms": self.forced_ms,
            "cooperative_ms": self.cooperative_ms,
            "verify_ms": self.verify_ms,
            "return_code": self.return_code,
            "tree_dead": self.tree_dead,
            "survivors": self.survivors,
            "remaining_pids": self.remaining_pids,
            "handles_released": self.handles_released,
            "product_absent": self.product_absent,
            "product_state": self.product_state,
            "mutex_free": self.mutex_free,
            "service_idle": self.service_idle,
            "leftovers_empty": self.leftovers_empty,
            "stop_unconfirmed": self.stop_unconfirmed,
            "ui_calls": self.ui_calls,
            "note": self.note,
        })
    }
}

fn proc_json(p: &win32::Proc) -> Value {
    p.to_json()
}

fn survivors_in(pids: &[u32]) -> Vec<Value> {
    let snap = win32::snapshot();
    let mut out: Vec<Value> = Vec::new();
    for pid in pids {
        if win32::alive(*pid) {
            let ppid = snap.iter().find(|(p, _, _)| p == pid).map(|(_, pp, _)| *pp).unwrap_or(0);
            let exe = win32::exe_path(*pid).unwrap_or_default();
            let proc = win32::identify(*pid, ppid, &exe, None);
            out.push(proc_json(&proc));
        }
    }
    out
}

/// The single stop entry point. Every stop trigger calls this function
/// and no other function in the crate kills a process, a job, or an
/// MSI install.
pub fn abort(target: AbortTarget, trigger: StopTrigger) -> AbortOutcome {
    let start = Instant::now();
    match target {
        AbortTarget::Msi { cancel, outcome, product_code, name_substring, target_dir, pre_msiexec_pids } => {
            abort_msi(cancel, outcome, product_code, name_substring, target_dir, pre_msiexec_pids, trigger, start)
        }
        AbortTarget::Command { root_pid, exe_path, window_start, install_dir } => {
            abort_command(root_pid, exe_path, window_start, install_dir, trigger, start)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn abort_msi(
    cancel: Arc<AtomicBool>,
    outcome: Arc<Mutex<Option<msi::CancelOutcome>>>,
    product_code: Option<String>,
    name_substring: String,
    target_dir: String,
    pre_msiexec_pids: Vec<u32>,
    trigger: StopTrigger,
    start: Instant,
) -> AbortOutcome {
    // (1) Set the cancel flag: the external UI handler returns IDCANCEL.
    cancel.store(true, Ordering::SeqCst);
    // (2) Wait for the dedicated install thread to return, up to the
    // hard cap. forced_ms is the rollback wait, measured by the install
    // thread itself (cancel_ms in CancelOutcome).
    let mut got: Option<msi::CancelOutcome> = None;
    while start.elapsed() < Duration::from_millis(HARD_CAP_MS) {
        if let Ok(mut slot) = outcome.lock() {
            if slot.is_some() {
                got = slot.take();
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let stop_ms = start.elapsed().as_millis() as u64;
    let verify_start = Instant::now();
    let (return_code, forced_ms, handler_calls) = match got {
        Some(ref o) => (Some(o.return_code), o.cancel_ms, o.handler_calls),
        None => (None, stop_ms, 0),
    };
    // (3) Verify restoration to the pre-command state.
    let presence = msi::product_presence_by_name(&name_substring);
    let product_absent = presence.get("present").and_then(|v| v.as_bool()).map(|b| !b);
    let product_state = product_code.as_deref().map(msi::product_state);
    let mutex_free = win32::msi_execute_mutex_free();
    let service = win32::sc_query_msiserver();
    let service_idle = service.get("idle").and_then(|v| v.as_bool()).unwrap_or(mutex_free);
    let listing = msi::target_folder_listing(&target_dir);
    let leftovers_empty = listing.get("is_empty").and_then(|v| v.as_bool()).unwrap_or(true);
    // MSI service children: any msiexec process that was not already
    // present before the command (the idle host itself) is a survivor.
    let now_msiexec = win32::msiexec_processes();
    let mut service_survivors: Vec<Value> = Vec::new();
    for p in &now_msiexec {
        if !pre_msiexec_pids.contains(&p.pid) {
            service_survivors.push(proc_json(p));
        }
    }
    let verify_ms = verify_start.elapsed().as_millis() as u64;
    let restored = return_code == Some(msi::ERROR_INSTALL_USEREXIT)
        && product_absent == Some(true)
        && mutex_free
        && service_idle
        && leftovers_empty
        && service_survivors.is_empty();
    let stop_unconfirmed = got.is_none();
    let status = if stop_unconfirmed {
        "stop-unconfirmed".to_string()
    } else if restored {
        "stopped".to_string()
    } else {
        "failed".to_string()
    };
    AbortOutcome {
        status,
        trigger: trigger.as_str().to_string(),
        installer_kind: InstallerKind::Msi.as_str().to_string(),
        stop_ms,
        forced_ms,
        cooperative_ms: 0,
        verify_ms,
        return_code,
        tree_dead: service_survivors.is_empty(),
        survivors: service_survivors,
        remaining_pids: now_msiexec.iter().map(|p| p.pid).collect(),
        handles_released: leftovers_empty,
        product_absent,
        product_state,
        mutex_free: Some(mutex_free),
        service_idle: Some(service_idle),
        leftovers_empty: Some(leftovers_empty),
        stop_unconfirmed,
        ui_calls: handler_calls,
        note: format!("msi cancel via IDCANCEL; handler_calls={}; stop-unconfirmed means the queue must stay blocked until Global_MSI_Execute is free and the supervisor records a final result", handler_calls),
    }
}

fn abort_command(
    root_pid: u32,
    exe_path: String,
    window_start: SystemTime,
    install_dir: Option<String>,
    trigger: StopTrigger,
    start: Instant,
) -> AbortOutcome {
    // (1) Enumerate the kill set by PPID (including PIDs that are
    // already dead when enumerated -- membership in this set is the
    // verification predicate).
    let mut kill_set: Vec<u32> = vec![root_pid];
    kill_set.extend(win32::descendants(root_pid));
    kill_set.sort_unstable();
    kill_set.dedup();
    // (2) Cooperative phase: CTRL_BREAK to the process group. Children
    // were launched with CREATE_NEW_PROCESS_GROUP (supervisor), so the
    // signal reaches the group and not the supervisor itself.
    let (cooperative_ms, _exited) = win32::cooperative_phase(root_pid, COOP_WINDOW_MS);
    let forced_start = Instant::now();
    // (3) Forced phase: terminate every live member of the kill set,
    // deepest first, then the alternative-naming orphans (creation-time
    // window + exe path) that PPID enumeration cannot see.
    let mut to_kill: Vec<u32> = kill_set.clone();
    to_kill.reverse();
    for pid in &to_kill {
        if win32::alive(*pid) {
            win32::terminate_pid(*pid);
        }
    }
    let window_end = SystemTime::now();
    let orphans = win32::processes_by_exe_and_window(&exe_path, window_start, window_end);
    let mut orphan_pids: Vec<u32> = Vec::new();
    for o in &orphans {
        if !kill_set.contains(&o.pid) && win32::alive(o.pid) {
            win32::terminate_pid(o.pid);
            orphan_pids.push(o.pid);
        }
    }
    let forced_ms = forced_start.elapsed().as_millis() as u64;
    // (4) Verify, up to the verify budget.
    let verify_start = Instant::now();
    let mut all_pids: Vec<u32> = kill_set.clone();
    all_pids.extend(orphan_pids.iter().copied());
    all_pids.sort_unstable();
    all_pids.dedup();
    let mut survivors = survivors_in(&all_pids);
    while !survivors.is_empty() && verify_start.elapsed() < Duration::from_millis(VERIFY_BUDGET_MS) {
        std::thread::sleep(Duration::from_millis(25));
        survivors = survivors_in(&all_pids);
    }
    let verify_ms = verify_start.elapsed().as_millis() as u64;
    let stop_ms = start.elapsed().as_millis() as u64;
    let tree_dead = survivors.is_empty();
    let handles_released = match &install_dir {
        Some(dir) => crate::try_rename_dir(std::path::Path::new(dir)),
        None => true,
    };
    let stop_unconfirmed = stop_ms > HARD_CAP_MS;
    let status = if stop_unconfirmed {
        "stop-unconfirmed".to_string()
    } else if tree_dead {
        "stopped".to_string()
    } else {
        "failed".to_string()
    };
    AbortOutcome {
        status,
        trigger: trigger.as_str().to_string(),
        installer_kind: InstallerKind::Command.as_str().to_string(),
        stop_ms,
        forced_ms,
        cooperative_ms,
        verify_ms,
        return_code: None,
        tree_dead,
        survivors,
        remaining_pids: all_pids.iter().copied().filter(|p| win32::alive(*p)).collect(),
        handles_released,
        product_absent: None,
        product_state: None,
        mutex_free: None,
        service_idle: None,
        leftovers_empty: None,
        stop_unconfirmed,
        ui_calls: 0,
        note: format!("command abort: kill_set={} pids, orphans_by_creation_window={} pids", kill_set.len(), orphan_pids.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budgets_are_design_allocations() {
        assert_eq!(HARD_CAP_MS, 5000);
        assert_eq!(MSI_CANCEL_BUDGET_MS + TREE_KILL_BUDGET_MS + VERIFY_BUDGET_MS, 3500);
        assert_eq!(POST_CAP_MONITOR_MS, 1500);
        assert_eq!(MSI_CANCEL_BUDGET_MS + TREE_KILL_BUDGET_MS + VERIFY_BUDGET_MS + POST_CAP_MONITOR_MS, 5000);
    }
    #[test]
    fn trigger_names() {
        assert_eq!(StopTrigger::HandStop.as_str(), "hand.stop");
        assert_eq!(StopTrigger::Ttl.as_str(), "ttl");
        assert_eq!(StopTrigger::DeadMan.as_str(), "dead-man");
        assert_eq!(StopTrigger::Guardian.as_str(), "guardian");
    }
}
