//! Periodic process snapshot (council condition 1 — closes the blind
//! spot on silent installs): `Toolhelp32Snapshot` every N seconds,
//! diffed against the previous list, emitting `proc.seen` / `proc.gone`.
//! No admin rights needed. On non-Windows builds this is a no-op that
//! reports itself as unsupported.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::EyeEvent;

/// True on platforms where the snapshotter can actually list processes.
pub fn snapshot_supported() -> bool {
    cfg!(windows)
}

/// Start the snapshotter thread. `dropped` counts routine `proc.*`
/// events lost when the bounded queue is full (log honesty, council
/// condition 4): the writer turns the count into a `log.gap` event
/// instead of staying silent about the loss.
pub fn start_snapshotter(
    tx: SyncSender<EyeEvent>,
    interval: Duration,
    paused: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    dropped: Arc<AtomicU64>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut previous: HashMap<u32, String> = HashMap::new();
        let mut first = true;
        while !stop.load(Ordering::Relaxed) {
            if !paused.load(Ordering::Relaxed) {
                let current = list_processes();
                if first {
                    // First tick is a baseline, not a flood of "seen".
                    for (pid, exe) in &current {
                        let _ = tx.send(EyeEvent::ProcSeen {
                            pid: *pid,
                            exe: exe.clone(),
                        });
                    }
                    first = false;
                } else {
                    for (pid, exe) in &current {
                        if !previous.contains_key(pid) {
                            if tx
                                .try_send(EyeEvent::ProcSeen {
                                    pid: *pid,
                                    exe: exe.clone(),
                                })
                                .is_err()
                            {
                                dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    for (pid, exe) in &previous {
                        if !current.contains_key(pid) {
                            if tx
                                .try_send(EyeEvent::ProcGone {
                                    pid: *pid,
                                    exe: exe.clone(),
                                })
                                .is_err()
                            {
                                dropped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                previous = current;
            }
            // Sleep in small slices so `stop` reacts fast.
            let mut slept = Duration::ZERO;
            while slept < interval && !stop.load(Ordering::Relaxed) {
                let step = Duration::from_millis(200).min(interval - slept);
                std::thread::sleep(step);
                slept += step;
            }
        }
    })
}

#[cfg(windows)]
fn list_processes() -> HashMap<u32, String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = HashMap::new();
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return out,
        };
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let exe = String::from_utf16_lossy(&entry.szExeFile[..end]);
                out.insert(entry.th32ProcessID, exe);
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

#[cfg(not(windows))]
fn list_processes() -> HashMap<u32, String> {
    HashMap::new()
}
