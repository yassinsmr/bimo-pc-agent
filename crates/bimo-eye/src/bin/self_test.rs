//! Eye-core self-test (spec section 8): runs the whole core in a
//! throwaway work dir and verifies the JSONL log end to end.
//!
//! Scenario:
//!   1. start the eye on temp Downloads/Desktop/Documents folders
//!   2. create `setup.exe` in Downloads → expect `file.completed` +
//!      `install.detected` (confidence low) + `file.hash`
//!   3. create `notes.txt` on Desktop → expect `file.completed`
//!   4. (Windows only) open Notepad for ~8 s → expect `proc.seen`
//!      plus, since the cycle-21 merge, `app.open` / `app.focus` /
//!      `app.close` for notepad.exe from the merged window hook
//!   5. create `eye.stop` → expect `agent.stop` (eye.stop-file) and NO
//!      events for a file created while stopped; remove it → expect a
//!      resumed `agent.start`
//!   6. stop the eye, verify the log: hash chain valid, sequence
//!      continuous, every expected event present, every line
//!      carrying `"schema": 1`.
//!
//! Writes `eye-self-test.json` (`--out`) and exits 0 on pass, 1 on fail.
//! Honest limits are recorded in the JSON `notes`, never hidden:
//! a headless failure is a note, not a silent pass.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bimo_eye::eye::{start, verify_log, EyeConfig};
use serde_json::json;

struct Check {
    name: &'static str,
    status: &'static str, // pass | fail | skip
    detail: String,
}

/// Text fields a check may match against: files carry `path`
/// (renames also `from`/`to`), processes carry `exe`. Matching only
/// `path` silently fails every process check — that bug cost the
/// first Windows run its only failing check (cycle 14).
fn event_text(e: &serde_json::Value) -> String {
    let mut s = String::new();
    for k in ["path", "exe", "from", "to"] {
        if let Some(v) = e.get(k).and_then(|v| v.as_str()) {
            s.push_str(v);
            s.push(' ');
        }
    }
    s.to_lowercase()
}

fn has_event(events: &[serde_json::Value], ty: &str, path_sub: Option<&str>) -> bool {
    events.iter().any(|e| {
        let t = e.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if t != ty {
            return false;
        }
        match path_sub {
            None => true,
            Some(sub) => event_text(e).contains(&sub.to_lowercase()),
        }
    })
}

fn has_event_reason(events: &[serde_json::Value], ty: &str, reason: &str) -> bool {
    events.iter().any(|e| {
        let t = e.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let r = e.get("reason").and_then(|v| v.as_str()).unwrap_or("");
        t == ty && r == reason
    })
}

fn main() { eprintln!("[trace] main start");
    let args: Vec<String> = std::env::args().collect();
    let mut out = PathBuf::from("eye-self-test.json");
    let mut work = std::env::temp_dir().join(format!(
        "bimo-eye-self-test-{}",
        std::process::id()
    ));
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                if i < args.len() {
                    out = PathBuf::from(&args[i]);
                }
            }
            "--work" => {
                i += 1;
                if i < args.len() {
                    work = PathBuf::from(&args[i]);
                }
            }
            _ => {}
        }
        i += 1;
    }

    let started = Instant::now();
    let mut checks: Vec<Check> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut fail = false;

    // Council condition 2 — prove the fail-closed path BEFORE the eye
    // starts. The test seam (BIMO_EYE_FORCE_CRYPTO_FAIL=1) simulates a
    // DPAPI failure on any platform; the same branches run for a real
    // failure. Plaintext in this throwaway test dir is an explicit
    // opt-in, restored before the eye starts.
    //
    // NOTE (cycle 15 fix): the opt-in assertion must be checked WHILE
    // the failure is still simulated. On Windows with a working DPAPI,
    // detect_mode() returns Dpapi once the seam is removed — asserting
    // Plain after removing it is wrong and failed the Windows run.
    std::env::remove_var("BIMO_EYE_FORCE_CRYPTO_FAIL");
    std::env::set_var("BIMO_EYE_PLAINTEXT_OK", "1");
    let fail_closed_ok = {
        use bimo_eye::crypto::{detect_mode, protect_line, CryptoMode};
        std::env::set_var("BIMO_EYE_FORCE_CRYPTO_FAIL", "1");
        std::env::remove_var("BIMO_EYE_PLAINTEXT_OK");
        let refused = detect_mode().is_err()
            && protect_line("{\"type\":\"x\"}", CryptoMode::Dpapi).is_err();
        // Failure STILL simulated, opt-in now set: detection must yield
        // Plain explicitly — on every platform, including Windows.
        std::env::set_var("BIMO_EYE_PLAINTEXT_OK", "1");
        let opt_in_ok = detect_mode().map(|m| m == CryptoMode::Plain).unwrap_or(false);
        std::env::remove_var("BIMO_EYE_FORCE_CRYPTO_FAIL");
        refused && opt_in_ok
    };

    let downloads = work.join("Downloads");
    let desktop = work.join("Desktop");
    let documents = work.join("Documents");
    let data_dir = work.join("eye-data");
    for d in [&downloads, &desktop, &documents, &data_dir] {
        if let Err(e) = std::fs::create_dir_all(d) {
            eprintln!("cannot create work dir {}: {e}", d.display());
            std::process::exit(2);
        }
    }

    // Cycle-31 close-out: seed prior eye data + eye.wipe BEFORE the
    // eye starts, so the start-time wipe has something to delete.
    {
        let _ = std::fs::write(data_dir.join("eye-events.jsonl"), b"{\"type\":\"old\"}\n");
        let _ = std::fs::create_dir_all(data_dir.join("shots"));
        let _ = std::fs::write(data_dir.join("shots").join("shot-000001.jpg"), b"old shot");
        let _ = std::fs::write(data_dir.join("heartbeat.json"), b"{\"ts\":\"old\"}");
        let _ = std::fs::write(data_dir.join("eye.wipe"), b"wipe");
    }
    let cfg = EyeConfig {
        watch_dirs: vec![downloads.clone(), desktop.clone(), documents.clone()],
        data_dir: data_dir.clone(),
        debounce_secs: 2,
        snapshot_secs: 3,
        reconcile_secs: 3,
        heartbeat_secs: 5,
        game_mode: false,
    };
    let handle = match start(cfg) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("eye failed to start: {e}");
            write_report(&out, "fail", "unknown", 0, vec![Check {
                name: "eye starts",
                status: "fail",
                detail: e,
            }], vec![], (0, 0.0), started.elapsed());
            std::process::exit(1);
        }
    };

    // 1. settle
    std::thread::sleep(Duration::from_millis(1500));

    // 2. fake installer in Downloads
    let setup = downloads.join("setup.exe");
    write_file(&setup, &[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
    std::thread::sleep(Duration::from_secs(4));

    // 3. plain file on Desktop
    let notes_file = desktop.join("notes.txt");
    write_file(&notes_file, b"hello from the eye self-test\n");
    std::thread::sleep(Duration::from_secs(4));

    // 3b. Council condition 4 — a file that changes AFTER it was
    // hashed must be re-hashed: append to setup.exe and wait for the
    // watcher to report a new completion + a new file.hash.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&setup)
            .expect("reopen setup.exe");
        f.write_all(b"changed-after-first-hash")
            .expect("append to setup.exe");
        drop(f);
    }
    std::thread::sleep(Duration::from_secs(5));

    // 4. Notepad (Windows only) — kept open 8 s so the 3 s snapshotter
    //    ticks see it at least twice.
    #[cfg(windows)]
    let notepad_started = {
        match std::process::Command::new("notepad.exe").spawn() {
            Ok(mut child) => {
                std::thread::sleep(Duration::from_secs(8));
                let _ = child.kill();
                let _ = child.wait();
                true
            }
            Err(e) => {
                notes.push(format!(
                    "notepad did not start on this runner ({e}); proc.seen check skipped, not failed"
                ));
                false
            }
        }
    };
    #[cfg(not(windows))]
    let notepad_started = false;
    #[cfg(not(windows))]
    notes.push(
        "not a Windows build: proc.seen check skipped, not failed".to_string(),
    );

    // 4b. Shot (cycle 28, feature `eye-shots`, Windows only): request
    // one shot and give the session up to ~25 s (a frame can take
    // 20 s on a static desktop). The verdict is read from the log at
    // the end: `shot.taken` = pass; `shot.failed` with no frame =
    // skip (headless runner — deferred, not failed); anything else =
    // fail.
    #[cfg(all(feature = "eye-shots", windows))]
    {
        if let Err(e) = handle.request_shot("self-test") {
            notes.push(format!("shot request failed: {e}"));
        }
        std::thread::sleep(Duration::from_secs(25));
    }

    eprintln!("[trace] before deferred alert-shot request"); // 4c. Game mode (cycle 31): an alert shot while gaming is
    // deferred, then runs when gaming ends.
    #[cfg(all(feature = "eye-shots", windows))]
    let deferred_shot_ok = {
        let before = count_type_in_log(&data_dir, "shot.taken");
        let gamemode_file = data_dir.join("eye.gamemode");
        let req_ok = std::fs::write(&gamemode_file, b"game").is_ok()
            && handle.request_shot("alert:self-test-deferred").is_ok();
        std::thread::sleep(Duration::from_secs(3));
        let _ = std::fs::remove_file(&gamemode_file);
        std::thread::sleep(Duration::from_secs(25));
        let after = count_type_in_log(&data_dir, "shot.taken");
        req_ok && after > before
    };
    eprintln!("[trace] after deferred alert-shot request"); // Let the hash worker catch up.
    std::thread::sleep(Duration::from_secs(3));

    // 5. stop-file test: while stopped, a new file must NOT be logged.
    // Council condition 5 — the stop must leave a trace OUTSIDE the
    // log: heartbeat.json disappears and eye.stopped appears; on
    // resume the heartbeat file comes back with a fresh timestamp.
    let heartbeat_file = data_dir.join("heartbeat.json");
    let stopped_marker = data_dir.join("eye.stopped");
    let heartbeat_before_stop = file_mtime(&heartbeat_file);
    let stop_file = data_dir.join("eye.stop");
    let _ = std::fs::write(&stop_file, b"stop");
    std::thread::sleep(Duration::from_secs(3));
    let heartbeat_gone_while_stopped =
        !heartbeat_file.exists() && stopped_marker.exists();
    let blocked = desktop.join("blocked.txt");
    write_file(&blocked, b"this must not appear in the log\n");
    std::thread::sleep(Duration::from_secs(3));
    let _ = std::fs::remove_file(&stop_file);
    std::thread::sleep(Duration::from_secs(7));
    let heartbeat_back_after_resume = match (
        heartbeat_before_stop,
        file_mtime(&heartbeat_file),
    ) {
        (Some(before), Some(after)) => after > before,
        (None, Some(_)) => true, // no heartbeat before, one now: resumed
        _ => false,
    };

    eprintln!("[trace] before handle.stop()"); handle.stop(); eprintln!("[trace] after handle.stop()");

    // 6. verify the log
    let (rss_kb, cpu_seconds) = sample_resources();
    eprintln!("[trace] before verify_log"); let report = verify_log(&data_dir); eprintln!("[trace] after verify_log");
    let (events, chain_valid, crypto) = match &report {
        Ok(rep) => {
            let crypto = rep
                .events
                .iter()
                .find(|e| {
                    e.get("type").and_then(|v| v.as_str()) == Some("agent.start")
                })
                .and_then(|e| e.get("crypto"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            (rep.events.clone(), rep.valid, crypto)
        }
        Err(e) => {
            notes.push(format!("log verification itself failed: {e}"));
            (Vec::new(), false, "unknown".to_string())
        }
    };

    let mut check = |name: &'static str, ok: bool, detail: String| {
        if !ok {
            fail = true;
        }
        checks.push(Check {
            name,
            status: if ok { "pass" } else { "fail" },
            detail,
        });
    };

    check(
        "agent.start present",
        has_event(&events, "agent.start", None),
        "the eye must record its start".to_string(),
    );
    check(
        "file.completed setup.exe",
        has_event(&events, "file.completed", Some("setup.exe")),
        "debounced completion of the fake installer".to_string(),
    );
    let install_ok = events.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("install.detected")
            && e.get("path")
                .and_then(|v| v.as_str())
                .map(|p| p.to_lowercase().contains("setup.exe"))
                .unwrap_or(false)
            && e.get("confidence").and_then(|v| v.as_str()) == Some("low")
    });
    check(
        "install.detected setup.exe confidence low",
        install_ok,
        "installer inference must stay low-confidence".to_string(),
    );
    check(
        "crypto fails closed (simulated DPAPI failure)",
        fail_closed_ok,
        "without opt-in, detection refuses and protect_line errors; with opt-in, plaintext is explicit".to_string(),
    );
    check(
        "file.hash setup.exe",
        has_event(&events, "file.hash", Some("setup.exe")),
        "background hash worker must hash the installer".to_string(),
    );
    // Council condition 4: a later change must produce a NEW hash.
    // Diagnostic (cycle 15): count completions too — if the second
    // hash is missing, this tells us whether the watcher never
    // reported the change (1 completion) or the worker lost it.
    let setup_completions = events
        .iter()
        .filter(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("file.completed")
                && e.get("path")
                    .and_then(|v| v.as_str())
                    .map(|p| p.to_lowercase().contains("setup.exe"))
                    .unwrap_or(false)
        })
        .count();
    check(
        "second completion observed for setup.exe",
        setup_completions >= 2,
        format!("{setup_completions} file.completed events for setup.exe; the change must be reported"),
    );
    let setup_hashes: Vec<&str> = events
        .iter()
        .filter_map(|e| {
            if e.get("type").and_then(|v| v.as_str()) != Some("file.hash") {
                return None;
            }
            let p = e.get("path").and_then(|v| v.as_str())?;
            if !p.to_lowercase().contains("setup.exe") {
                return None;
            }
            e.get("sha256").and_then(|v| v.as_str())
        })
        .collect();
    check(
        "file re-hashed after later change",
        setup_hashes.len() >= 2 && setup_hashes.first() != setup_hashes.last(),
        format!(
            "{} file.hash events for setup.exe; first hash must differ from last",
            setup_hashes.len()
        ),
    );
    check(
        "file.completed notes.txt",
        has_event(&events, "file.completed", Some("notes.txt")),
        "debounced completion of a plain file".to_string(),
    );
    check(
        "eye.heartbeat present",
        has_event(&events, "eye.heartbeat", None),
        "at least one heartbeat in ~25 s with a 5 s interval".to_string(),
    );
    check(
        "hash chain valid",
        chain_valid,
        match &report {
            Ok(rep) => rep
                .reason
                .clone()
                .unwrap_or_else(|| format!("{} lines verified", rep.lines)),
            Err(e) => e.clone(),
        },
    );
    check(
        "agent.stop eye.stop-file present",
        has_event_reason(&events, "agent.stop", "eye.stop-file"),
        "the stop file must stop the eye and be recorded".to_string(),
    );
    check(
        "file created while stopped is NOT logged",
        !has_event(&events, "file.completed", Some("blocked.txt"))
            && !has_event(&events, "file.created", Some("blocked.txt")),
        "blocked.txt must not appear while eye.stop exists".to_string(),
    );
    check(
        "eye resumes after stop file removed",
        events.iter().any(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("agent.start")
                && e.get("scope_note")
                    .and_then(|v| v.as_str())
                    .map(|s| s.contains("resumed"))
                    .unwrap_or(false)
        }),
        "removing eye.stop must resume the eye".to_string(),
    );
    // Council condition 5: the stop must be detectable outside the log.
    check(
        "heartbeat file present before stop",
        heartbeat_before_stop.is_some(),
        "heartbeat.json must exist while the eye runs".to_string(),
    );
    check(
        "stop leaves an outside-the-log trace",
        heartbeat_gone_while_stopped,
        "while stopped: heartbeat.json gone and eye.stopped present".to_string(),
    );
    check(
        "heartbeat file fresh again after resume",
        heartbeat_back_after_resume,
        "heartbeat.json must return with a newer timestamp after the stop file is removed"
            .to_string(),
    );
    // Cycle-21 merge: every log line must carry schema 1 (spec §3).
    // NOTE (borrow rule, E0499): the `check` closure borrows `checks`
    // mutably, so NO `check` call may follow a direct `checks.push`
    // in the same flow. The file's only direct pushes live in the
    // `else` branch of the Notepad block below (the last closure use
    // is inside its exclusive `if` branch) — window checks therefore
    // live INSIDE that `if` branch, and the schema check lives here,
    // before any push.
    let schema_ok = events
        .iter()
        .all(|e| e.get("schema").and_then(|v| v.as_u64()) == Some(1));
    check(
        "every log line carries schema 1",
        schema_ok,
        format!("{} events checked", events.len()),
    );
    check(
        "eye.reconciled present (reconciler thread runs)",
        has_event(&events, "eye.reconciled", None),
        "the periodic folder reconciler must emit a summary event".to_string(),
    );
    check(
        "eye.wiped present with the seeded files counted",
        events.iter().any(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("eye.wiped")
                && e.get("removed_files").and_then(|v| v.as_u64()).unwrap_or(0) >= 3
        }),
        "the start-time wipe must report the seeded old log + shot + heartbeat".to_string(),
    );
    check(
        "seeded plain shot file is gone after wipe",
        !data_dir.join("shots").join("shot-000001.jpg").exists(),
        "eye.wipe must delete prior shot files".to_string(),
    );
    if !cfg!(windows) {
        notes.push(
            "not a Windows build: window-event checks skipped, not failed (hook is Windows-only)"
                .to_string(),
        );
    }
    if cfg!(windows) {
        if notepad_started {
            check(
                "snapshotter alive (any proc.seen)",
                has_event(&events, "proc.seen", None),
                "the snapshotter must report at least one process; a dead snapshotter must not hide behind a missed Notepad".to_string(),
            );
            check(
                "proc.seen notepad.exe",
                has_event(&events, "proc.seen", Some("notepad.exe")),
                "snapshotter must see Notepad while it runs".to_string(),
            );
            // Cycle-21 merge: window events from the merged hook
            // (same Notepad run). These calls MUST live in this `if`
            // branch — see the borrow-rule note above the schema check.
            check(
                "app.open notepad.exe (window hook)",
                has_event(&events, "app.open", Some("notepad.exe")),
                "the merged window hook must record Notepad opening".to_string(),
            );
            check(
                "app.focus notepad.exe (window hook)",
                has_event(&events, "app.focus", Some("notepad.exe")),
                "the merged window hook must record Notepad taking focus".to_string(),
            );
            check(
                "app.close notepad.exe (window hook)",
                has_event(&events, "app.close", Some("notepad.exe")),
                "the merged window hook must record Notepad closing".to_string(),
            );
        } else {
            checks.push(Check {
                name: "proc.seen notepad.exe",
                status: "skip",
                detail: "notepad did not start on this runner".to_string(),
            });
            checks.push(Check {
                name: "app.open/app.focus/app.close notepad.exe",
                status: "skip",
                detail: "notepad did not start on this runner".to_string(),
            });
        }
    }
    // Cycle 28: shot integration — judged from the log, not from the
    // request call. Direct pushes (see the borrow-rule note above the
    // schema check): no `check` call may follow this block.
    #[cfg(all(feature = "eye-shots", windows))]
    {
        let shot = events.iter().find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("shot.taken")
        });
        let failed = events.iter().find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("shot.failed")
        });
        let (status, detail): (&'static str, String) = match (shot, failed) {
            (Some(ev), _) => {
                let w = ev.get("width").and_then(|v| v.as_u64()).unwrap_or(0);
                let h = ev.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                let q = ev.get("quality").and_then(|v| v.as_str()).unwrap_or("");
                let no_title = ev.get("title").is_none();
                if w > 0 && w <= 1920 && (q == "80" || q == "wic-default-fallback") && no_title
                {
                    (
                        "pass",
                        format!(
                            "shot.taken in the eye log: {w}x{h}, quality {q}, no title field"
                        ),
                    )
                } else {
                    (
                        "fail",
                        format!(
                            "shot.taken event is malformed: width {w}, quality '{q}', title present: {}",
                            !no_title
                        ),
                    )
                }
            }
            (None, Some(ev)) => {
                let reason = ev
                    .get("reason")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if reason.contains("no frame") || reason.contains("Monitor::primary") {
                    (
                        "skip",
                        "headless runner: no frame within 20 s — deferred to the Legion, not a design failure".to_string(),
                    )
                } else {
                    ("fail", format!("shot.failed: {reason}"))
                }
            }
            (None, None) => (
                "fail",
                "neither shot.taken nor shot.failed in the log — the shot producer never answered"
                    .to_string(),
            ),
        };
        if status == "fail" {
            fail = true;
        }
        checks.push(Check {
            name: "shot.taken via eye log (feature eye-shots)",
            status,
            detail,
        });
        // Cycle 31: game-mode deferral — shot.deferred must be in the
        // log, and the deferred shot must have run after gaming ended
        // (unless headless: then it fails with no-frame, recorded).
        let deferred_seen = events.iter().any(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("shot.deferred")
                && e.get("reason").and_then(|v| v.as_str()) == Some("alert:self-test-deferred")
        });
        if !deferred_seen {
            fail = true;
        }
        checks.push(Check {
            name: "alert shot deferred while gaming (shot.deferred)",
            status: if deferred_seen { "pass" } else { "fail" },
            detail: "alert:* request during game mode must emit shot.deferred, not execute".to_string(),
        });
        let no_frame_failed = events.iter().any(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("shot.failed")
                && e.get("reason")
                    .and_then(|v| v.as_str())
                    .map(|r| r.contains("no frame"))
                    .unwrap_or(false)
        });
        let (def_status, def_detail): (&'static str, String) = if deferred_shot_ok {
            (
                "pass",
                "deferred alert shot executed after game mode cleared (one more shot.taken)".to_string(),
            )
        } else if no_frame_failed {
            (
                "skip",
                "headless runner: deferred shot got no frame — deferred to the Legion".to_string(),
            )
        } else {
            (
                "fail",
                "deferred alert shot never executed after game mode cleared".to_string(),
            )
        };
        if def_status == "fail" {
            fail = true;
        }
        checks.push(Check {
            name: "deferred alert shot executes after gaming",
            status: def_status,
            detail: def_detail,
        });
        // Cycle 31: toast probe — an alert shot executed (or failed)
        // must have attempted a toast; the probe file proves it.
        let probe = std::fs::read_to_string(data_dir.join("toast.probe"))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
        let (probe_status, probe_detail): (&'static str, String) =
            match probe
                .as_ref()
                .and_then(|v| v.get("attempted"))
                .and_then(|v| v.as_bool())
            {
                Some(true) => {
                    let ok = probe
                        .as_ref()
                        .and_then(|v| v.get("ok"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let err = probe
                        .as_ref()
                        .and_then(|v| v.get("error"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    (
                        "pass",
                        format!("toast attempted: ok={ok}, error='{err}'"),
                    )
                }
                _ => (
                    "fail",
                    "no toast attempt recorded despite an alert shot".to_string(),
                ),
            };
        if probe_status == "fail" {
            fail = true;
        }
        checks.push(Check {
            name: "toast probe recorded for alert shot",
            status: probe_status,
            detail: probe_detail,
        });
    }
    #[cfg(not(all(feature = "eye-shots", windows)))]
    notes.push(
        "shots not wired in this build: shot check skipped (feature `eye-shots` + Windows required)"
            .to_string(),
    );
    if crypto == "plain" {
        notes.push(
            "crypto is plain: explicit opt-in BIMO_EYE_PLAINTEXT_OK=1 recorded in the log (council condition 2); DPAPI stays an arrival-day item"
                .to_string(),
        );
    }

    let verdict = if fail { "fail" } else { "pass" };
    eprintln!("[trace] before write_report"); write_report(
        &out,
        verdict,
        &crypto,
        events.len(),
        checks,
        notes,
        (rss_kb, cpu_seconds),
        started.elapsed(),
    );
    println!("eye self-test: {verdict} ({} events)", events.len());
    std::process::exit(if fail { 1 } else { 0 });
}

#[cfg(all(feature = "eye-shots", windows))]
fn count_type_in_log(data_dir: &Path, ty: &str) -> usize {
    let path = data_dir.join("eye-events.jsonl");
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines().filter(|l| l.contains(ty)).count()
}

fn write_file(path: &Path, data: &[u8]) {
    let mut f = std::fs::File::create(path).expect("create test file");
    f.write_all(data).expect("write test file");
    drop(f);
}

fn file_mtime(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

#[cfg(windows)]
fn sample_resources() -> (u64, f64) {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    unsafe {
        let h = GetCurrentProcess();
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let rss = if GetProcessMemoryInfo(h, &mut pmc, pmc.cb).is_ok() {
            pmc.WorkingSetSize as u64 / 1024
        } else {
            0
        };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let cpu = if GetProcessTimes(h, &mut creation, &mut exit, &mut kernel, &mut user)
            .is_ok()
        {
            let k = ((kernel.dwHighDateTime as u64) << 32) | kernel.dwLowDateTime as u64;
            let u = ((user.dwHighDateTime as u64) << 32) | user.dwLowDateTime as u64;
            (k + u) as f64 / 10_000_000.0
        } else {
            0.0
        };
        (rss, cpu)
    }
}

#[cfg(not(windows))]
fn sample_resources() -> (u64, f64) {
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| {
                    l.split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                })
        })
        .unwrap_or(0);
    let cpu = std::fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            let parts: Vec<&str> = s.split_whitespace().collect();
            let utime: f64 = parts.get(13)?.parse().ok()?;
            let stime: f64 = parts.get(14)?.parse().ok()?;
            Some((utime + stime) / 100.0)
        })
        .unwrap_or(0.0);
    (rss, cpu)
}

#[allow(clippy::too_many_arguments)]
fn write_report(
    out: &Path,
    verdict: &str,
    crypto: &str,
    events_total: usize,
    checks: Vec<Check>,
    notes: Vec<String>,
    resources: (u64, f64),
    elapsed: Duration,
) {
    let checks_json: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "status": c.status,
                "detail": c.detail,
            })
        })
        .collect();
    let report = json!({
        "verdict": verdict,
        "crypto": crypto,
        "chain_valid": checks.iter().any(|c| c.name == "hash chain valid" && c.status == "pass"),
        "events_total": events_total,
        "checks": checks_json,
        "notes": notes,
        "resources": {
            "rss_kb": resources.0,
            "cpu_seconds": resources.1,
            "elapsed_seconds": elapsed.as_secs_f64(),
        },
        "honest_limits": [
            "runner numbers do not prove device performance (flawhunt 11-z)",
            "no real fullscreen game on the runner; game capture is decided on the Legion (second gate)",
            "Defender realtime was off on the runner in the spike; no Defender check runs here",
        ],
    });
    let text = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|_| "{\"verdict\":\"fail\"}".to_string());
    if let Err(e) = std::fs::write(out, text) {
        eprintln!("cannot write report {}: {e}", out.display());
    }
}
