//! Eye-core self-test (spec section 8): runs the whole core in a
//! throwaway work dir and verifies the JSONL log end to end.
//!
//! Scenario:
//!   1. start the eye on temp Downloads/Desktop/Documents folders
//!   2. create `setup.exe` in Downloads → expect `file.completed` +
//!      `install.detected` (confidence low) + `file.hash`
//!   3. create `notes.txt` on Desktop → expect `file.completed`
//!   4. (Windows only) open Notepad for ~8 s → expect `proc.seen`
//!   5. create `eye.stop` → expect `agent.stop` (eye.stop-file) and NO
//!      events for a file created while stopped; remove it → expect a
//!      resumed `agent.start`
//!   6. stop the eye, verify the log: hash chain valid, sequence
//!      continuous, every expected event present.
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

fn main() {
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
    std::env::remove_var("BIMO_EYE_FORCE_CRYPTO_FAIL");
    std::env::set_var("BIMO_EYE_PLAINTEXT_OK", "1");
    let fail_closed_ok = {
        use bimo_eye::crypto::{detect_mode, protect_line, CryptoMode};
        std::env::set_var("BIMO_EYE_FORCE_CRYPTO_FAIL", "1");
        std::env::remove_var("BIMO_EYE_PLAINTEXT_OK");
        let refused = detect_mode().is_err()
            && protect_line("{\"type\":\"x\"}", CryptoMode::Dpapi).is_err();
        std::env::remove_var("BIMO_EYE_FORCE_CRYPTO_FAIL");
        std::env::set_var("BIMO_EYE_PLAINTEXT_OK", "1");
        let opt_in_ok = detect_mode().map(|m| m == CryptoMode::Plain).unwrap_or(false);
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

    let cfg = EyeConfig {
        watch_dirs: vec![downloads.clone(), desktop.clone(), documents.clone()],
        data_dir: data_dir.clone(),
        debounce_secs: 2,
        snapshot_secs: 3,
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

    // Let the hash worker catch up.
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

    handle.stop();

    // 6. verify the log
    let (rss_kb, cpu_seconds) = sample_resources();
    let report = verify_log(&data_dir);
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
        } else {
            checks.push(Check {
                name: "proc.seen notepad.exe",
                status: "skip",
                detail: "notepad did not start on this runner".to_string(),
            });
        }
    }
    if crypto == "plain" {
        notes.push(
            "crypto is plain: explicit opt-in BIMO_EYE_PLAINTEXT_OK=1 recorded in the log (council condition 2); DPAPI stays an arrival-day item"
                .to_string(),
        );
    }

    let verdict = if fail { "fail" } else { "pass" };
    write_report(
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
