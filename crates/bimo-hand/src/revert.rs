//! Revert (council condition 5, partly).
//!
//! Every command records a revert plan at enqueue time, before execution,
//! in its queue line. Reversibility is verified at registration where it
//! is checkable: install records a winget id or an uninstaller path;
//! organize records the original paths + checksums; download / convert
//! record the output path.
//!
//! Revert is AUTOMATIC only for safe proven-reversible cases (download:
//! delete the output; convert: delete the output). An EXPLICIT `revert
//! <id>` is needed for install and for every dangerous case. NEVER
//! automatic on an unknown-cause failure.
//!
//! A failed revert => state `revert_failed` + an escalation file
//! (`hand.revert-failed-<id>.json`) + an alert.

use crate::queue::Command;
use crate::{alert_event, file_sha256, utc_now_secs, write_json_file};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

/// Outcome of [`revert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevertOutcome {
    Reverted,
    Failed(String),
    NotReversible(String),
}

/// Check the revert plan at registration time, where checkable.
/// - download / convert: an `output` path is recorded.
/// - install: a winget id or an uninstaller path is recorded.
/// - organize: a `moves` list with original paths + checksums.
/// - transfer: `source` + `destination` (+ `source_checksum`).
pub fn verify_revert_plan(cmd: &Command) -> bool {
    let plan = &cmd.revert_plan;
    match cmd.kind.as_str() {
        "download" | "convert" => plan.get("output").and_then(|v| v.as_str()).is_some(),
        "install" => {
            plan.get("winget_id").and_then(|v| v.as_str()).is_some()
                || plan.get("uninstaller").and_then(|v| v.as_str()).is_some()
        }
        "organize" => match plan.get("moves").and_then(|v| v.as_array()) {
            Some(moves) => moves.iter().all(|m| {
                m.get("from").and_then(|v| v.as_str()).is_some()
                    && m.get("checksum").and_then(|v| v.as_str()).is_some()
            }),
            None => false,
        },
        "transfer" => {
            plan.get("source").and_then(|v| v.as_str()).is_some()
                && plan.get("destination").and_then(|v| v.as_str()).is_some()
        }
        _ => false,
    }
}

/// Write the escalation file for a failed revert and return its path.
pub fn write_revert_failed(data_dir: &Path, cmd: &Command, reason: &str) -> PathBuf {
    let path = data_dir.join(format!("hand.revert-failed-{}.json", cmd.id));
    let value = json!({
        "ts": utc_now_secs(),
        "id": cmd.id,
        "kind": cmd.kind,
        "reason": reason,
    });
    let _ = write_json_file(&path, &value);
    path
}

/// Run the revert for one command. A failure also writes the escalation
/// file and an alert (the caller marks the state `revert_failed`).
pub fn revert(cmd: &Command, data_dir: &Path) -> RevertOutcome {
    let outcome = match cmd.kind.as_str() {
        "download" | "convert" => revert_delete_output(cmd),
        "transfer" => revert_transfer(cmd),
        "organize" => {
            // v1 organize is propose-only: nothing ever moved, so there
            // is nothing to undo.
            RevertOutcome::Reverted
        }
        "install" => revert_install(cmd),
        other => RevertOutcome::NotReversible(format!("no revert for kind {}", other)),
    };
    if let RevertOutcome::Failed(reason) = &outcome {
        write_revert_failed(data_dir, cmd, reason);
        let _ = alert_event(
            data_dir,
            "revert-failed",
            json!({"id": cmd.id, "kind": cmd.kind, "reason": reason}),
        );
    }
    outcome
}

fn revert_delete_output(cmd: &Command) -> RevertOutcome {
    let output = cmd
        .revert_plan
        .get("output")
        .and_then(|v| v.as_str())
        .or_else(|| cmd.args.get("output").and_then(|v| v.as_str()));
    match output {
        None => RevertOutcome::Failed("no output path in revert plan".to_string()),
        Some(path) => {
            let p = Path::new(path);
            if p.exists() {
                match fs::remove_file(p) {
                    Ok(()) => RevertOutcome::Reverted,
                    Err(e) => RevertOutcome::Failed(format!("delete output: {}", e)),
                }
            } else {
                // Nothing to delete: the output is already gone.
                RevertOutcome::Reverted
            }
        }
    }
}

fn revert_transfer(cmd: &Command) -> RevertOutcome {
    let plan = &cmd.revert_plan;
    let source = plan.get("source").and_then(|v| v.as_str());
    let destination = plan.get("destination").and_then(|v| v.as_str());
    let expected = plan.get("source_checksum").and_then(|v| v.as_str());
    let (source, destination) = match (source, destination) {
        (Some(s), Some(d)) => (Path::new(s), Path::new(d)),
        _ => return RevertOutcome::Failed("transfer revert plan is incomplete".to_string()),
    };
    if destination.exists() && !source.exists() {
        // The transfer moved the file: move it back and verify.
        if fs::rename(destination, source).is_err() {
            return RevertOutcome::Failed("could not move file back to its original path".into());
        }
    } else if destination.exists() && source.exists() {
        // The transfer copied the file: drop the copy.
        if fs::remove_file(destination).is_err() {
            return RevertOutcome::Failed("could not delete the transferred copy".into());
        }
    } else {
        return RevertOutcome::Failed("neither the source nor the destination exists".into());
    }
    if let Some(expected) = expected {
        match file_sha256(source) {
            Ok(actual) if actual == expected => RevertOutcome::Reverted,
            Ok(actual) => RevertOutcome::Failed(format!(
                "checksum mismatch after revert: {} != {}",
                actual, expected
            )),
            Err(e) => RevertOutcome::Failed(format!("checksum after revert: {}", e)),
        }
    } else {
        RevertOutcome::Reverted
    }
}

fn revert_install(cmd: &Command) -> RevertOutcome {
    // A simulated broken uninstall record (the 8.3 proof) is an explicit
    // marker in the command arguments.
    if cmd
        .args
        .get("uninstaller_missing")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return RevertOutcome::Failed("uninstaller record is missing".to_string());
    }
    let uninstaller = cmd
        .revert_plan
        .get("uninstaller")
        .and_then(|v| v.as_str())
        .or_else(|| cmd.args.get("uninstaller").and_then(|v| v.as_str()));
    match uninstaller {
        None => RevertOutcome::Failed("no uninstaller recorded in the revert plan".into()),
        Some(path) => {
            if !Path::new(path).exists() {
                return RevertOutcome::Failed(format!(
                    "uninstaller record is missing: {}",
                    path
                ));
            }
            // v1 test apps record an installed marker file; removing it
            // is the revert for the simulated install.
            if let Some(marker) = cmd
                .args
                .get("installed_marker")
                .and_then(|v| v.as_str())
            {
                let _ = fs::remove_file(marker);
            }
            RevertOutcome::Reverted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::new_command;
    use crate::sha256_hex;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bimo-hand-rtest-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn download_revert_deletes_the_output() {
        let dir = test_dir("dl");
        let out = dir.join("out.bin");
        fs::write(&out, b"data").unwrap();
        let cmd = new_command(
            "dl1",
            "download",
            json!({"output": out.to_string_lossy()}),
            3600,
            json!({"output": out.to_string_lossy()}),
        );
        assert!(verify_revert_plan(&cmd));
        assert_eq!(revert(&cmd, &dir), RevertOutcome::Reverted);
        assert!(!out.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_revert_fails_when_the_uninstaller_record_is_missing() {
        let dir = test_dir("inst");
        let app = dir.join("test-app");
        fs::create_dir_all(&app).unwrap();
        let marker = app.join("installed.txt");
        fs::write(&marker, b"installed").unwrap();
        // The uninstall record is broken (simulated missing uninstaller).
        let cmd = new_command(
            "inst1",
            "install",
            json!({"uninstaller_missing": true, "installed_marker": marker.to_string_lossy()}),
            3600,
            json!({"uninstaller": app.join("uninstall.txt").to_string_lossy()}),
        );
        assert!(verify_revert_plan(&cmd));
        assert_eq!(
            revert(&cmd, &dir),
            RevertOutcome::Failed("uninstaller record is missing".to_string())
        );
        assert!(dir.join("hand.revert-failed-inst1.json").exists());
        assert!(marker.exists(), "a failed revert must not delete the app");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn transfer_revert_returns_the_file_to_its_original_path() {
        let dir = test_dir("tr");
        let src = dir.join("orig.bin");
        let dst = dir.join("moved.bin");
        fs::write(&src, b"payload").unwrap();
        let checksum = sha256_hex(b"payload");
        fs::rename(&src, &dst).unwrap();
        let cmd = new_command(
            "tr1",
            "transfer",
            json!({}),
            3600,
            json!({
                "source": src.to_string_lossy(),
                "destination": dst.to_string_lossy(),
                "source_checksum": checksum,
            }),
        );
        assert!(verify_revert_plan(&cmd));
        assert_eq!(revert(&cmd, &dir), RevertOutcome::Reverted);
        assert!(src.exists());
        assert!(!dst.exists());
        assert_eq!(file_sha256(&src).unwrap(), checksum);
        let _ = fs::remove_dir_all(&dir);
    }
}
