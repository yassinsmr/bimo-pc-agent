// ثنائي اختبار مؤقت (SPIKE) — يُحذف بعد إثبات مهلة join في stop().
// يبدأ العين بنفس نمط self_test، وينتظر 5 ثوانٍ، ثم يستدعي stop() ويقيس مدتها.
// مع BIMO_EYE_HANG_CONTROL=1 يعلّق خيط control للأبد بعد خروج حلقته، فيجب
// أن تبلغ stop() المهلة (10 ثوانٍ لخيط control ثم 10 ثوانٍ للكاتب) وتعود
// خلال 10-30 ثانية بدل أن تنتظر إلى ما لا نهاية.
// تتحقق العملية الأب (هذه العملية) من أربعة شروط: مدة stop() بين 10 و30 ثانية،
// وظهور سطر "[trace] join control timed out after 10s; proceeding" في السجل،
// وظهور سطر "[trace] stop() end"، وخروج العملية الفرعية بالرمز 0.
// تكتب النتيجة في ملف JSON (الخيار --out) وسجل وحدة التحكم في ملف (الخيار --log).
// ملاحظة: لا نتحقق من حدث agent.stop النهائي للكاتب؛ فقد يبقى الكاتب منفصلًا
// بعد مهلته الخاصة، وهذا متوقع.

use bimo_eye::eye::{start, EyeConfig};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "BIMO_EYE_SPIKE_CHILD";
const TIMEOUT_LINE: &str = "[trace] join control timed out after 10s; proceeding";
const STOP_END_LINE: &str = "[trace] stop() end";

fn parse_args() -> (PathBuf, PathBuf, PathBuf) {
    let mut out = PathBuf::from("join-timeout-spike.json");
    let mut log = PathBuf::from("join-timeout-spike.log");
    let mut work =
        std::env::temp_dir().join(format!("bimo-eye-join-timeout-spike-{}", std::process::id()));
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => {
                if let Some(v) = it.next() {
                    out = PathBuf::from(v);
                }
            }
            "--log" => {
                if let Some(v) = it.next() {
                    log = PathBuf::from(v);
                }
            }
            "--work" => {
                if let Some(v) = it.next() {
                    work = PathBuf::from(v);
                }
            }
            _ => {}
        }
    }
    (out, log, work)
}

fn run_child(work: &Path) -> i32 {
    let data_dir = work.join("eye-data");
    let downloads = work.join("Downloads");
    let desktop = work.join("Desktop");
    let documents = work.join("Documents");
    for d in [&downloads, &desktop, &documents, &data_dir] {
        if let Err(e) = std::fs::create_dir_all(d) {
            eprintln!("[spike] cannot create {}: {e}", d.display());
            return 1;
        }
    }
    let cfg = EyeConfig {
        watch_dirs: vec![downloads, desktop, documents],
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
            eprintln!("[spike] eye start failed: {e}");
            return 1;
        }
    };
    println!("[spike] eye started; eye log: {}", handle.log_path.display());
    std::thread::sleep(Duration::from_secs(5));
    let t0 = Instant::now();
    handle.stop();
    let secs = t0.elapsed().as_secs_f64();
    println!("[spike] stop() took {secs:.3}s");
    let duration_path = work.join("stop-duration-secs.txt");
    if let Err(e) = std::fs::write(&duration_path, format!("{secs:.3}")) {
        eprintln!("[spike] cannot write {}: {e}", duration_path.display());
        return 1;
    }
    0
}

fn run_parent(out: &Path, log: &Path, work: &Path) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("[spike] cannot locate own exe: {e}");
            return 1;
        }
    };
    let log_file = match std::fs::File::create(log) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[spike] cannot create {}: {e}", log.display());
            return 1;
        }
    };
    let log_file_err = match log_file.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[spike] cannot clone log file: {e}");
            return 1;
        }
    };
    let mut child = match Command::new(&exe)
        .arg("--out")
        .arg(out)
        .arg("--log")
        .arg(log)
        .arg("--work")
        .arg(work)
        .env(CHILD_ENV, "1")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[spike] cannot spawn child: {e}");
            return 1;
        }
    };
    let status = match child.wait() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[spike] cannot wait for child: {e}");
            return 1;
        }
    };
    let child_code = status.code().unwrap_or(-1);
    let log_text = std::fs::read_to_string(log).unwrap_or_default();
    let duration_path = work.join("stop-duration-secs.txt");
    let stop_secs: Option<f64> = std::fs::read_to_string(&duration_path)
        .ok()
        .and_then(|s| s.trim().parse().ok());
    let in_range = stop_secs.map(|s| (10.0..=30.0).contains(&s)).unwrap_or(false);
    let timeout_line = log_text.contains(TIMEOUT_LINE);
    let stop_end = log_text.contains(STOP_END_LINE);
    let pass = in_range && timeout_line && stop_end && child_code == 0;
    let result = serde_json::json!({
        "spike": "join-timeout",
        "pass": pass,
        "stop_secs": stop_secs,
        "stop_secs_in_10_30": in_range,
        "timeout_line_present": timeout_line,
        "stop_end_present": stop_end,
        "child_exit_code": child_code,
        "log": log.display().to_string(),
        "work": work.display().to_string(),
    });
    let text =
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| String::from("{}"));
    if let Err(e) = std::fs::write(out, &text) {
        eprintln!("[spike] cannot write {}: {e}", out.display());
        return 1;
    }
    if pass {
        println!(
            "[spike] PASS: stop() took {:.3}s (10-30s), timeout line present, stop() end present, child exit 0",
            stop_secs.unwrap_or(-1.0)
        );
        0
    } else {
        println!("[spike] FAIL: stop_secs={stop_secs:?}, in_10_30={in_range}, timeout_line={timeout_line}, stop_end={stop_end}, child_exit={child_code}");
        println!("[spike] result: {text}");
        1
    }
}

fn main() {
    let (out, log, work) = parse_args();
    let code = if std::env::var(CHILD_ENV).as_deref() == Ok("1") {
        run_child(&work)
    } else {
        run_parent(&out, &log, &work)
    };
    std::process::exit(code);
}
