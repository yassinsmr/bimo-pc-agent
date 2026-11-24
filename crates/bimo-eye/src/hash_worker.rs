//! Background hash worker (spec section 4, council condition 3):
//! SHA-256 of executables / installers / archives only, asynchronously,
//! capped at ~2 GB. Larger files are skipped with a named message in
//! the log ("hash skipped: too large") — never hashed, never blocking
//! the writer. Stopped entirely while game mode is on.
//!
//! Log honesty (eye-core council condition 4): a hash is only ever a
//! decision on a STABLE, closed file. Before hashing, the worker stats
//! the file twice 500 ms apart; if size or mtime moved, the hash is
//! deferred ("hash deferred: file still changing") and the file is
//! re-queued (max 3 attempts, then skipped with a named warning).
//! A file that changes AFTER it was hashed is re-hashed: the watcher
//! emits a new `file.completed` on every later Modify, and the writer
//! forwards it here again, so the log carries the new hash next to
//! the old one instead of silently keeping a stale value.

use std::collections::VecDeque;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;

use sha2::{Digest, Sha256};

use crate::EyeEvent;

/// Default cap from the council condition: ~2 GiB.
pub const HASH_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Stability window (council condition 4): size + mtime must be
/// unchanged across this gap before a hash is trusted.
const STABILITY_WAIT_MS: u64 = 500;

/// Max re-queue attempts for a still-changing file.
const MAX_STABILITY_ATTEMPTS: u8 = 3;

const HASHABLE_EXT: [&str; 6] = ["exe", "msi", "zip", "7z", "rar", "iso"];

pub fn is_hashable(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| HASHABLE_EXT.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
}

/// (size, mtime) fingerprint used for the stability check.
fn file_fingerprint(path: &PathBuf) -> Option<(u64, std::time::SystemTime)> {
    std::fs::metadata(path)
        .ok()
        .map(|m| (m.len(), m.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)))
}

/// True only if the file did not move (size and mtime) across the
/// stability window. Pure enough to unit-test.
pub fn file_is_stable(path: &PathBuf) -> bool {
    let before = match file_fingerprint(path) {
        Some(f) => f,
        None => return false, // gone — nothing stable to hash
    };
    std::thread::sleep(std::time::Duration::from_millis(STABILITY_WAIT_MS));
    match file_fingerprint(path) {
        Some(after) => after == before,
        None => false,
    }
}

/// Start the hash worker thread. It reads paths from `rx` and reports
/// `file.hash` events (or a skip warning) on `tx`.
pub fn start_hash_worker(
    rx: Receiver<PathBuf>,
    tx: SyncSender<EyeEvent>,
    game_mode: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        // Deferred files (still changing at hash time) retry THEMSELVES
        // here after 1 s — the retry must never depend on the watcher
        // emitting another `file.completed`, which may never come
        // (cycle 15: the Windows run hashed setup.exe once only because
        // the deferred second hash had no retry of its own).
        // Entry: (path, retry-at, attempts-so-far).
        let mut pending: VecDeque<(PathBuf, std::time::Instant, u8)> =
            VecDeque::new();
        while !stop.load(Ordering::Relaxed) {
            // A due retry takes precedence over the channel.
            let mut next: Option<(PathBuf, u8)> = None;
            if let Some((_, due, _)) = pending.front() {
                if *due <= std::time::Instant::now() {
                    let (p, _, n) = pending.pop_front().unwrap();
                    next = Some((p, n));
                }
            }
            let (path, mut attempts) = match next {
                Some(v) => v,
                None => match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                    Ok(p) => (p, 0u8),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                },
            };
            if game_mode.load(Ordering::Relaxed) {
                continue; // hashing is off while gaming (condition 12)
            }
            if !is_hashable(&path) {
                continue;
            }
            let size = match std::fs::metadata(&path) {
                Ok(m) => m.len(),
                Err(_) => continue, // file already gone — nothing to hash
            };
            if size > HASH_CAP_BYTES {
                let _ = tx.send(EyeEvent::Warning {
                    message: format!(
                        "hash skipped: too large: {} ({} bytes)",
                        path.display(),
                        size
                    ),
                });
                continue;
            }
            // Stability gate (council condition 4): hash only a file
            // that stopped changing; otherwise defer and retry from
            // our own queue — never from the watcher's next event.
            if !file_is_stable(&path) {
                attempts += 1;
                if attempts < MAX_STABILITY_ATTEMPTS {
                    let _ = tx.send(EyeEvent::Warning {
                        message: format!(
                            "hash deferred: file still changing: {} (attempt {attempts}/{MAX_STABILITY_ATTEMPTS})",
                            path.display()
                        ),
                    });
                    pending.push_back((
                        path,
                        std::time::Instant::now() + std::time::Duration::from_secs(1),
                        attempts,
                    ));
                    continue;
                }
                let _ = tx.send(EyeEvent::Warning {
                    message: format!(
                        "hash skipped: still changing after {MAX_STABILITY_ATTEMPTS} checks: {}",
                        path.display()
                    ),
                });
                continue;
            }
            match hash_file(&path) {
                Ok(sha) => {
                    let _ = tx.send(EyeEvent::FileHash {
                        path,
                        sha256: sha,
                    });
                }
                Err(e) => {
                    let _ = tx.send(EyeEvent::Warning {
                        message: format!("hash failed for {}: {e}", path.display()),
                    });
                }
            }
        }
    })
}

fn hash_file(path: &PathBuf) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn stable_file_passes_and_changing_file_fails() {
        let dir = std::env::temp_dir().join(format!(
            "bimo-eye-stability-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("stable.bin");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"steady content").unwrap();
        }
        assert!(file_is_stable(&path), "untouched file must be stable");

        // A file being appended to from another thread must NOT be
        // called stable: the writer appends during the 500 ms window.
        let moving = dir.join("moving.bin");
        {
            let mut f = std::fs::File::create(&moving).unwrap();
            f.write_all(b"start").unwrap();
        }
        let moving2 = moving.clone();
        let writer = std::thread::spawn(move || {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&moving2)
                .unwrap();
            for _ in 0..10 {
                let _ = f.write_all(b"more");
                let _ = f.flush();
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        assert!(
            !file_is_stable(&moving),
            "a file changing during the window must not be stable"
        );
        let _ = writer.join();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
