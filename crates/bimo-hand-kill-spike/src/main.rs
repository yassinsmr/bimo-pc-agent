//! `bimo-hand-kill-spike` — measurement-only spike (cycle 39).
//!
//! The c38 hand self-test failed proofs 8.1 and 8.2: after
//! TerminateJobObject, PID 4568 stayed alive and stop_ms was
//! 5040 / 5047 (over the 5000 ms budget). This spike measures
//! whether a different kill does better, in four stages run in a
//! temp folder, writing `hand-kill-spike.json`:
//!
//! * stage 0 — reproduce 8.1 exactly (old method, TerminateJobObject
//!   only) and name every survivor with exe path, PPID, session,
//!   user (SYSTEM vs user) and IsProcessInJob;
//! * stage 1 — same scenario with the PPID tree kill;
//! * stage 2 — MSI cancel via MsiInstallProduct + an external UI
//!   handler returning IDCANCEL on the stop signal;
//! * stage 3 — the 8.2 transfer (1 GB, kill past 25%) with the
//!   PPID tree kill.
//!
//! Exit code 0 means the JSON was written, whatever the stage
//! verdicts are: this spike measures, it does not gate. Exit
//! code 1 means the JSON itself could not be written.
//!
//! Usage: `bimo-hand-kill-spike --out hand-kill-spike.json`
//! Hidden helper mode (used by stage 3, do not call by hand):
//! `bimo-hand-kill-spike --slow-copy <src> <dst> <progress>`.
//!
//! On non-Windows the binary still builds and writes an
//! inconclusive JSON: the spike requires Windows.

#[cfg(windows)]
mod msi;
#[cfg(windows)]
mod stages;
#[cfg(windows)]
mod stages2;
#[cfg(windows)]
mod stop;
#[cfg(windows)]
mod win32;

fn main() {
  let args: Vec<String> = std::env::args().collect();
  if args.get(1).map(|s| s.as_str()) == Some("--slow-copy") {
    if args.len() < 5 {
      eprintln!("usage: --slow-copy <src> <dst> <progress>");
      std::process::exit(2);
    }
    #[cfg(windows)]
    std::process::exit(stages2::slow_copy(&args[2], &args[3], &args[4]));
    #[cfg(not(windows))]
    {
      eprintln!("--slow-copy requires Windows");
      std::process::exit(1);
    }
  }
  let mut out = "hand-kill-spike.json".to_string();
  let mut i = 1;
  while i < args.len() {
    if args[i] == "--out" && i + 1 < args.len() {
      out = args[i + 1].clone();
      i += 2;
    } else {
      i += 1;
    }
  }
  #[cfg(windows)]
  std::process::exit(stages2::run_all(&out));
  #[cfg(not(windows))]
  {
    let doc = serde_json::json!({
      "spike": "unit3-kill-spike-c39",
      "branch": "unit3-kill-spike-c39",
      "base": "a0354f8",
      "runner_note": "does not prove device performance",
      "stages": {
        "stage0": { "status": "inconclusive", "measured": { "error": "requires Windows" } },
        "stage1": { "status": "inconclusive", "measured": { "error": "requires Windows" } },
        "stage2": { "status": "inconclusive", "measured": { "error": "requires Windows" } },
        "stage3": { "status": "inconclusive", "measured": { "error": "requires Windows" } },
      },
    });
    match std::fs::write(&out, serde_json::to_string_pretty(&doc).unwrap_or_default()) {
      Ok(()) => std::process::exit(0),
      Err(e) => {
        eprintln!("failed to write {}: {}", out, e);
        std::process::exit(1);
      }
    }
  }
}
