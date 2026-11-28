//! The `update` command (Unit 3, Hand v1) — pure decision logic.
//!
//! Design: `track-a-unit3-hand-v1-update-design.md` (approved as amended
//! by council 28, cycle 71, chair literal review APPROVED). Every rule
//! below cites its council-28 condition; the module is pure (no Windows
//! calls) so its unit tests run on Linux and on the Windows runner.
//!
//! Council 28, condition 1 — freeze at acceptance:
//! `target_version` empty means "latest" as INPUT only; at acceptance it
//! resolves to a named version recorded in the command and in
//! `dedup_key`. An executed command always names a version; an empty
//! value never executes. `ttl_secs` blocks ACCEPTANCE only and never
//! kills a running execution. `nonce` is per-command (queue.rs); the
//! `dedup_key` stays reserved 24 h after completion (queue.rs).
//!
//! Council 28, condition 2 — `done` is a state, not an event:
//! `done` ⟺ (after == frozen target) ∧ (independent read: exe version
//! or ProductState) ∧ (winget exit code and installer log bound to the
//! command) ∧ (no partial state). `install.detected` is a supporting
//! witness only: its absence is incomplete evidence, not failure, and
//! its presence does not prove causation. The old formula (after !=
//! before + event present) is REPEALED.
//!
//! Council 28, condition 3 — revert proven at execution time:
//! the old version's availability is a STORED claim from registration,
//! re-read at execution but NOT re-verified live (council 34 cond. 3,
//! struck c80; a live `winget show` probe is open follow-up work tied
//! to the condition-2 dry run). Silent download to the old version must
//! be proven on the runner for the test package; uninstall+reinstall
//! counts as a revert only if it is proven to preserve settings/saves
//! or declares what it loses — otherwise `revert-unverifiable` and no
//! execution without Yassin's explicit approval (phone-notification
//! channel).
//! Automatic revert is allowed ONLY for the three named pre-execution
//! safe failure patterns; everything else is explicit (`revert <id>`),
//! never automatic on an unknown-cause failure.
//!
//! Council 28, condition 4 — v1 scope and interruption:
//! NO game updates in v1 (save verification undefined); NO automatic
//! restart ever (a restart request is the named state `needs_restart`,
//! never `done`); a kill mid-update reads the version and records the
//! named state `partial` (neither old nor new) — never settled as
//! `done`/`failed` until a named recovery path decides; other updates
//! for the same package freeze until the partial state resolves.
//!
//! Council 28, condition 5 — both paths proven or one disabled:
//! the official-installer path is either tested by a second named test
//! before adoption or DISABLED in v1. The guardian does NOT inspect a
//! winget payload in v1 — verification on the winget path is the
//! winget manifest hash + Authenticode signature (the same two checks
//! S1 applies to MSI); the gap is a NAMED RISK, not an assumption:
//! a compromised manifest entry is not detected by the guardian.
//! Test package (named): Notepad++.Notepad++, 8.9.8 → 8.9.9.1.
//!
//! Inherited (not a sixth condition): the kill proof on the runner is
//! a RED LINE (failure → (ج) automatically); the S4 stress test runs
//! BEFORE any code depending on S4 logic (done: run 14, stress `pass`);
//! the explicit constraint (§0) is quoted in any design depending on S4.
//!
//! > **Explicit constraint (§0, council 27 condition 3 — quoted
//! > literally):** "العمل التالي لا يفترض صحة الاستقرار تحت حدث
//! > متأخر حتى يُختبر؛ أي تصميم يعتمد على منطق S4 يذكر القيد حرفيا."
//! > This module depends on S4 logic (the `install.detected` witness),
//! > so the constraint applies to it in full: no assumption that the
//! > dynamic settle (4 s quiet window) holds under a late file event
//! > until tested — the stress test (run 14) passed on the narrow M5
//! > scope (injection OUTSIDE the product folder only); a late write
//! > INSIDE the product folder stays an open unknown on the arrival
//! > list.

use crate::queue::{dedup_key_for, new_command, Command};
use serde_json::{json, Value};

/// Disk-space margin for an update (design §3 step 1, named number):
/// expected size + 512 MB. Must equal `executor::DISK_MARGIN_BYTES`
/// (guarded by a test in executor.rs); the two constants are one rule.
pub const UPDATE_DISK_MARGIN_BYTES: u64 = 512 * 1024 * 1024;

/// winget exit code meaning "restart requested" (ERROR_SUCCESS_REBOOT_REQUIRED).
pub const WINGET_RESTART_REQUESTED: i32 = 3010;

/// Parsed, validated `update` arguments (execution time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateArgs {
    /// winget package id, e.g. `Notepad++.Notepad++`.
    pub package: String,
    /// Frozen target version — always named at execution (cond. 1).
    pub frozen_version: String,
    /// Version installed before the update (for the revert plan + the
    /// no-change check of auto-revert pattern (a)).
    pub old_version: Option<String>,
    /// Version read before execution (idempotency: == frozen → done).
    pub installed_version: Option<String>,
    /// Expected download/install size in bytes (disk pre-flight).
    pub size_bytes: Option<u64>,
}

/// Parse and validate `update` arguments from a queued command.
/// Errors name the reason; the caller maps it to the queue state.
pub fn parse_update_args(cmd: &Command) -> Result<UpdateArgs, String> {
    // Condition 4: games are OUT of v1 scope entirely.
    if cmd.args.get("game").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err("update-game-out-of-scope".to_string());
    }
    let package = cmd
        .args
        .get("package")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "update-no-package".to_string())?;
    // Condition 1: an executed command always names a version.
    let frozen_version = cmd
        .args
        .get("frozen_version")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "update-no-frozen-version".to_string())?;
    Ok(UpdateArgs {
        package,
        frozen_version,
        old_version: cmd
            .args
            .get("old_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        installed_version: cmd
            .args
            .get("installed_version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        size_bytes: cmd.args.get("size_bytes").and_then(|v| v.as_u64()),
    })
}

/// Freeze the target version at acceptance (cond. 1).
/// `input` is the command's `target_version` (None = "latest" as input);
/// `resolved_latest` is the version the acceptance step resolved from
/// the source. Returns the frozen version, or `target-unresolvable`
/// when neither names one (then the command is refused).
pub fn freeze_target_version(
    input: Option<&str>,
    resolved_latest: Option<&str>,
) -> Result<String, String> {
    if let Some(v) = input.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        return Ok(v.to_string());
    }
    if let Some(v) = resolved_latest.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        return Ok(v.to_string());
    }
    Err("target-unresolvable".to_string())
}

/// `dedup_key` for an update (design §2, literal form):
/// `update:<package>:<frozen-version>`. A different frozen version is
/// a different key; the same package+version replays as `duplicate`.
pub fn update_dedup_key(package: &str, frozen_version: &str) -> String {
    format!("update:{}:{}", package, frozen_version)
}

/// Build a new queued `update` command with the frozen version and the
/// design-form `dedup_key`. The revert plan is recorded at enqueue time,
/// before execution (see `revert.rs`); the caller supplies it.
pub fn new_update_command(
    id: &str,
    package: &str,
    frozen_version: &str,
    ttl_secs: u64,
    revert_plan: Value,
    size_bytes: Option<u64>,
    installed_version: Option<&str>,
) -> Command {
    let mut args = json!({
        "package": package,
        "frozen_version": frozen_version,
    });
    if let Some(size) = size_bytes {
        args["size_bytes"] = json!(size);
    }
    if let Some(installed) = installed_version {
        args["installed_version"] = json!(installed);
    }
    let mut cmd = new_command(id, "update", args, ttl_secs, revert_plan);
    // Override the generic v1:<kind>:<hash> key with the design form
    // (cond. 1: the frozen version is recorded in the dedup_key).
    cmd.dedup_key = update_dedup_key(package, frozen_version);
    // Keep the generic key derivable: the canonical-args hash must still
    // be unique per package+version — it is, because frozen_version is
    // part of args. (No separate assertion needed; dedup tests cover it.)
    let _ = dedup_key_for("update", &cmd.args);
    cmd
}

/// True when the command's TTL has expired AT ACCEPTANCE time.
/// Condition 1: TTL blocks acceptance only — it never kills a running
/// execution. The supervisor's exec monitor consults [`ttl_kill_exempt`]
/// before arming any TTL stop (council 34 cond. 3, wired c80); for
/// `update` no TTL stop is ever armed.
pub fn acceptance_expired(cmd: &Command, now_secs: u64) -> bool {
    crate::queue::is_expired(cmd, now_secs)
}

/// True when no TTL kill may be armed for a running command of this
/// kind. Condition 1 settles the open v2 question for `update`: TTL
/// never kills a running `update` execution.
pub fn ttl_kill_exempt(kind: &str) -> bool {
    kind == "update"
}

/// Evidence for the `done` verdict (cond. 2 — `done` is a state).
#[derive(Debug, Clone)]
pub struct DoneEvidence {
    /// Version read AFTER execution (winget list or exe version).
    pub after_version: Option<String>,
    /// Frozen target version (cond. 1).
    pub frozen_target: String,
    /// Independent read (exe file version or ProductState) — a read
    /// independent of the executor (winget list alone does not count).
    pub independent_read_ok: bool,
    /// winget exit code (0 = success).
    pub winget_exit_code: Option<i32>,
    /// winget exit code + installer log bound to this command.
    pub installer_log_bound: bool,
    /// Partial state (killed mid-update, version neither old nor new).
    pub partial: bool,
}

/// The `done` verdict (cond. 2). `Done` only when the full conjunction
/// holds; every other branch names its reason (never a bare `failed`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoneVerdict {
    Done,
    NotDone(&'static str),
}

pub fn done_verdict(ev: &DoneEvidence) -> DoneVerdict {
    if ev.partial {
        return DoneVerdict::NotDone("partial-state");
    }
    match &ev.after_version {
        Some(after) if after == &ev.frozen_target => {}
        Some(_) => return DoneVerdict::NotDone("version-mismatch"),
        None => return DoneVerdict::NotDone("version-unreadable"),
    }
    if !ev.independent_read_ok {
        return DoneVerdict::NotDone("no-independent-read");
    }
    match ev.winget_exit_code {
        Some(0) => {}
        Some(WINGET_RESTART_REQUESTED) => return DoneVerdict::NotDone("needs-restart"),
        Some(_) => return DoneVerdict::NotDone("winget-exit-nonzero"),
        None => return DoneVerdict::NotDone("winget-exit-unknown"),
    }
    if !ev.installer_log_bound {
        return DoneVerdict::NotDone("installer-log-unbound");
    }
    DoneVerdict::Done
}

/// Outcome of one `update` execution, as the worker reports it.
#[derive(Debug, Clone)]
pub struct UpdateOutcome {
    /// winget exit code; None when the process was killed / never ran.
    pub exit_code: Option<i32>,
    /// True when the supervisor stopped the execution (kill path).
    pub killed: bool,
    /// Version read after execution (winget list or exe version).
    pub read_version: Option<String>,
    /// Version installed before the update.
    pub old_version: String,
    /// Frozen target version.
    pub frozen_target: String,
    /// Independent read (exe version or ProductState) succeeded.
    pub independent_read_ok: bool,
    /// winget exit code + installer log bound to this command.
    pub installer_log_bound: bool,
}

/// Final queue state for an `update` execution (cond. 2 + cond. 4).
/// - `needs_restart`: winget asked for a restart (3010) — never `done`.
/// - `partial`: killed mid-update and the version reads neither old
///   nor new — never settled as `done`/`failed` until a named recovery
///   path decides; other updates for the package freeze meanwhile.
/// - `done` / `failed`: by the cond. 2 formula (via [`done_verdict`]).
pub fn update_final_state(o: &UpdateOutcome) -> &'static str {
    if o.exit_code == Some(WINGET_RESTART_REQUESTED) {
        return "needs_restart";
    }
    if o.killed {
        match &o.read_version {
            Some(v) if v == &o.old_version => return "failed",
            Some(v) if v == &o.frozen_target => {
                // Finished before the kill landed: the cond. 2 formula
                // still decides (a kill does not certify success).
                let ev = DoneEvidence {
                    after_version: o.read_version.clone(),
                    frozen_target: o.frozen_target.clone(),
                    independent_read_ok: o.independent_read_ok,
                    winget_exit_code: o.exit_code,
                    installer_log_bound: o.installer_log_bound,
                    partial: false,
                };
                return match done_verdict(&ev) {
                    DoneVerdict::Done => "done",
                    DoneVerdict::NotDone(_) => "partial",
                };
            }
            _ => return "partial",
        }
    }
    let ev = DoneEvidence {
        after_version: o.read_version.clone(),
        frozen_target: o.frozen_target.clone(),
        independent_read_ok: o.independent_read_ok,
        winget_exit_code: o.exit_code,
        installer_log_bound: o.installer_log_bound,
        partial: false,
    };
    match done_verdict(&ev) {
        DoneVerdict::Done => "done",
        DoneVerdict::NotDone(_) => "failed",
    }
}

/// A failure as the executor classifies it, for the auto-revert rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateFailure {
    /// winget exited non-zero; versions read after the attempt.
    WingetNonZero {
        version_after: Option<String>,
        version_before: Option<String>,
    },
    /// Download or hash check failed before any install step.
    DownloadOrHashBeforeInstall,
    /// The guardian refused before any install step.
    GuardianRefusedBeforeInstall,
    /// Anything else (unknown cause, kill, timeout, ...).
    Other(String),
}

/// Automatic revert is allowed ONLY for the three named pre-execution
/// safe failure patterns (cond. 3). Pattern (a) additionally requires
/// proof that nothing changed (after == before); unknown versions fail
/// safe to explicit revert. Everything else: explicit `revert <id>`.
pub fn auto_revert_allowed(f: &UpdateFailure) -> bool {
    match f {
        UpdateFailure::WingetNonZero {
            version_after,
            version_before,
        } => match (version_after, version_before) {
            (Some(after), Some(before)) => after == before,
            _ => false,
        },
        UpdateFailure::DownloadOrHashBeforeInstall => true,
        UpdateFailure::GuardianRefusedBeforeInstall => true,
        UpdateFailure::Other(_) => false,
    }
}

/// Availability of the revert target (cond. 3) — a STORED claim from
/// registration, re-read at execution but NOT re-verified live
/// (council 34 cond. 3, struck c80: no `winget show` probe runs at
/// execution; a live probe is open follow-up work tied to the
/// condition-2 dry run). Staleness surfaces at revert time as
/// `revert_failed` + escalation (see `revert::revert`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevertAvailability {
    /// The old version was still published when the plan was recorded
    /// (stored claim; not re-verified at execution).
    Available,
    /// A saved official installer of the old version, with its hash.
    SavedInstaller { path: String, sha256: String },
    /// Neither: the plan is `revert-unverifiable` — the command does
    /// NOT execute without Yassin's explicit approval (phone channel).
    Unverifiable,
}

pub fn revert_availability(plan: &Value) -> RevertAvailability {
    if plan
        .get("old_version_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return RevertAvailability::Available;
    }
    let path = plan
        .get("saved_installer_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let sha = plan
        .get("saved_installer_sha256")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if let (Some(path), Some(sha256)) = (path, sha) {
        if !path.is_empty() && sha256.len() == 64 {
            return RevertAvailability::SavedInstaller { path, sha256 };
        }
    }
    RevertAvailability::Unverifiable
}

/// winget argument line for the update execution (design §3 step 3).
/// The frozen version is always named at execution (cond. 1), so the
/// executable form is `install --version <frozen>` — never a bare
/// `upgrade` to a moving "latest".
pub fn winget_update_args(package: &str, frozen_version: &str) -> Vec<String> {
    vec![
        "install".to_string(),
        "--id".to_string(),
        package.to_string(),
        "--version".to_string(),
        frozen_version.to_string(),
        "--exact".to_string(),
        "--silent".to_string(),
    ]
}

/// winget argument line for the revert: reinstall the OLD version
/// (design §4). Executed through the supervisor like any command —
/// never in-process (winget has no in-process API).
pub fn winget_revert_args(package: &str, old_version: &str) -> Vec<String> {
    vec![
        "install".to_string(),
        "--id".to_string(),
        package.to_string(),
        "--version".to_string(),
        old_version.to_string(),
        "--exact".to_string(),
        "--silent".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::new_command;

    fn update_cmd(args: Value) -> Command {
        new_command("u1", "update", args, 3600, json!({}))
    }

    #[test]
    fn freeze_named_input_wins() {
        assert_eq!(
            freeze_target_version(Some("8.9.9.1"), Some("8.9.9.2")).unwrap(),
            "8.9.9.1"
        );
    }

    #[test]
    fn freeze_resolves_latest_when_input_empty() {
        assert_eq!(
            freeze_target_version(None, Some("8.9.9.1")).unwrap(),
            "8.9.9.1"
        );
        assert_eq!(freeze_target_version(Some("  "), Some("8.9.9.1")).unwrap(), "8.9.9.1");
    }

    #[test]
    fn freeze_unresolvable_is_refused() {
        assert_eq!(
            freeze_target_version(None, None),
            Err("target-unresolvable".to_string())
        );
        assert_eq!(
            freeze_target_version(Some(""), Some("  ")),
            Err("target-unresolvable".to_string())
        );
    }

    #[test]
    fn dedup_key_carries_frozen_version() {
        assert_eq!(
            update_dedup_key("Notepad++.Notepad++", "8.9.9.1"),
            "update:Notepad++.Notepad++:8.9.9.1"
        );
        assert_ne!(
            update_dedup_key("Notepad++.Notepad++", "8.9.9.1"),
            update_dedup_key("Notepad++.Notepad++", "8.9.8")
        );
    }

    #[test]
    fn new_update_command_sets_design_key() {
        let cmd = new_update_command(
            "u1",
            "Notepad++.Notepad++",
            "8.9.9.1",
            3600,
            json!({"winget_id": "Notepad++.Notepad++", "old_version": "8.9.8"}),
            Some(8_000_000),
            Some("8.9.8"),
        );
        assert_eq!(cmd.kind, "update");
        assert_eq!(cmd.dedup_key, "update:Notepad++.Notepad++:8.9.9.1");
        assert_eq!(cmd.args["frozen_version"], json!("8.9.9.1"));
        assert_eq!(cmd.args["size_bytes"], json!(8_000_000));
        assert!(!cmd.nonce.is_empty());
    }

    #[test]
    fn parse_rejects_games_missing_package_and_missing_frozen() {
        let game = update_cmd(json!({"package": "X.Game", "frozen_version": "1.0", "game": true}));
        assert_eq!(
            parse_update_args(&game),
            Err("update-game-out-of-scope".to_string())
        );
        let no_pkg = update_cmd(json!({"frozen_version": "1.0"}));
        assert_eq!(
            parse_update_args(&no_pkg),
            Err("update-no-package".to_string())
        );
        let no_frozen = update_cmd(json!({"package": "X.App"}));
        assert_eq!(
            parse_update_args(&no_frozen),
            Err("update-no-frozen-version".to_string())
        );
        let ok = update_cmd(json!({"package": "X.App", "frozen_version": "2.0"}));
        let args = parse_update_args(&ok).unwrap();
        assert_eq!(args.package, "X.App");
        assert_eq!(args.frozen_version, "2.0");
    }

    #[test]
    fn ttl_never_kills_a_running_update() {
        assert!(ttl_kill_exempt("update"));
        assert!(!ttl_kill_exempt("install"));
        assert!(!ttl_kill_exempt("download"));
    }

    fn full_evidence() -> DoneEvidence {
        DoneEvidence {
            after_version: Some("8.9.9.1".to_string()),
            frozen_target: "8.9.9.1".to_string(),
            independent_read_ok: true,
            winget_exit_code: Some(0),
            installer_log_bound: true,
            partial: false,
        }
    }

    #[test]
    fn done_verdict_needs_the_full_conjunction() {
        assert_eq!(done_verdict(&full_evidence()), DoneVerdict::Done);
        // Each missing conjunct fails with its own reason.
        let mut ev = full_evidence();
        ev.after_version = Some("8.9.8".to_string());
        assert_eq!(done_verdict(&ev), DoneVerdict::NotDone("version-mismatch"));
        let mut ev = full_evidence();
        ev.after_version = None;
        assert_eq!(done_verdict(&ev), DoneVerdict::NotDone("version-unreadable"));
        let mut ev = full_evidence();
        ev.independent_read_ok = false;
        assert_eq!(
            done_verdict(&ev),
            DoneVerdict::NotDone("no-independent-read")
        );
        let mut ev = full_evidence();
        ev.winget_exit_code = Some(1603);
        assert_eq!(
            done_verdict(&ev),
            DoneVerdict::NotDone("winget-exit-nonzero")
        );
        let mut ev = full_evidence();
        ev.winget_exit_code = Some(WINGET_RESTART_REQUESTED);
        assert_eq!(done_verdict(&ev), DoneVerdict::NotDone("needs-restart"));
        let mut ev = full_evidence();
        ev.winget_exit_code = None;
        assert_eq!(
            done_verdict(&ev),
            DoneVerdict::NotDone("winget-exit-unknown")
        );
        let mut ev = full_evidence();
        ev.installer_log_bound = false;
        assert_eq!(
            done_verdict(&ev),
            DoneVerdict::NotDone("installer-log-unbound")
        );
        let mut ev = full_evidence();
        ev.partial = true;
        assert_eq!(done_verdict(&ev), DoneVerdict::NotDone("partial-state"));
    }

    #[test]
    fn old_formula_would_have_passed_a_rollback() {
        // The repealed formula (after != before + event present) counts
        // a rollback to an OLDER version as success. The cond. 2
        // formula must not.
        let ev = DoneEvidence {
            after_version: Some("8.9.7".to_string()),
            frozen_target: "8.9.9.1".to_string(),
            independent_read_ok: true,
            winget_exit_code: Some(0),
            installer_log_bound: true,
            partial: false,
        };
        assert_eq!(done_verdict(&ev), DoneVerdict::NotDone("version-mismatch"));
    }

    fn outcome(exit: Option<i32>, killed: bool, read: Option<&str>) -> UpdateOutcome {
        UpdateOutcome {
            exit_code: exit,
            killed,
            read_version: read.map(|s| s.to_string()),
            old_version: "8.9.8".to_string(),
            frozen_target: "8.9.9.1".to_string(),
            independent_read_ok: true,
            installer_log_bound: true,
        }
    }

    #[test]
    fn final_state_restart_partial_and_done() {
        // Restart request is a named state, never done.
        assert_eq!(
            update_final_state(&outcome(Some(3010), false, Some("8.9.9.1"))),
            "needs_restart"
        );
        // Clean success.
        assert_eq!(
            update_final_state(&outcome(Some(0), false, Some("8.9.9.1"))),
            "done"
        );
        // Clean run, wrong version.
        assert_eq!(
            update_final_state(&outcome(Some(0), false, Some("8.9.8"))),
            "failed"
        );
        // Killed, nothing changed.
        assert_eq!(
            update_final_state(&outcome(None, true, Some("8.9.8"))),
            "failed"
        );
        // Killed, version neither old nor new.
        assert_eq!(
            update_final_state(&outcome(None, true, Some("8.9.9.0"))),
            "partial"
        );
        // Killed, version unreadable.
        assert_eq!(update_final_state(&outcome(None, true, None)), "partial");
        // Killed after the new version landed (with full evidence).
        assert_eq!(
            update_final_state(&outcome(Some(0), true, Some("8.9.9.1"))),
            "done"
        );
        // Killed after the new version landed but no independent read.
        let mut o = outcome(Some(0), true, Some("8.9.9.1"));
        o.independent_read_ok = false;
        assert_eq!(update_final_state(&o), "partial");
    }

    #[test]
    fn auto_revert_only_the_three_named_patterns() {
        assert!(auto_revert_allowed(&UpdateFailure::WingetNonZero {
            version_after: Some("8.9.8".to_string()),
            version_before: Some("8.9.8".to_string()),
        }));
        // Same pattern, but the version MOVED: not safe, explicit only.
        assert!(!auto_revert_allowed(&UpdateFailure::WingetNonZero {
            version_after: Some("8.9.9.0".to_string()),
            version_before: Some("8.9.8".to_string()),
        }));
        // Unknown versions fail safe to explicit.
        assert!(!auto_revert_allowed(&UpdateFailure::WingetNonZero {
            version_after: None,
            version_before: Some("8.9.8".to_string()),
        }));
        assert!(auto_revert_allowed(
            &UpdateFailure::DownloadOrHashBeforeInstall
        ));
        assert!(auto_revert_allowed(
            &UpdateFailure::GuardianRefusedBeforeInstall
        ));
        assert!(!auto_revert_allowed(&UpdateFailure::Other(
            "timeout".to_string()
        )));
    }

    #[test]
    fn revert_availability_three_branches() {
        assert_eq!(
            revert_availability(&json!({"old_version_available": true})),
            RevertAvailability::Available
        );
        let sha = "a".repeat(64);
        assert_eq!(
            revert_availability(&json!({
                "saved_installer_path": "C:\\dl\\npp-8.9.8.msi",
                "saved_installer_sha256": sha,
            })),
            RevertAvailability::SavedInstaller {
                path: "C:\\dl\\npp-8.9.8.msi".to_string(),
                sha256: sha,
            }
        );
        // Malformed hash (not 64 hex) does not count as a saved installer.
        assert_eq!(
            revert_availability(&json!({
                "saved_installer_path": "C:\\dl\\npp-8.9.8.msi",
                "saved_installer_sha256": "abc",
            })),
            RevertAvailability::Unverifiable
        );
        assert_eq!(
            revert_availability(&json!({})),
            RevertAvailability::Unverifiable
        );
    }

    #[test]
    fn winget_arg_lines_are_exact_and_silent() {
        assert_eq!(
            winget_update_args("Notepad++.Notepad++", "8.9.9.1"),
            vec!["install", "--id", "Notepad++.Notepad++", "--version", "8.9.9.1", "--exact", "--silent"]
        );
        assert_eq!(
            winget_revert_args("Notepad++.Notepad++", "8.9.8"),
            vec!["install", "--id", "Notepad++.Notepad++", "--version", "8.9.8", "--exact", "--silent"]
        );
    }
}
