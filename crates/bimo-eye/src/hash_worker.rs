//! Background hash worker (spec section 4, council condition 3):
//! SHA-256 of executables / installers / archives only, asynchronously,
//! capped at ~2 GB. Larger files are skipped with a named message in
//! the log ("hash skipped: too large") — never hashed, never blocking
//! the writer. Stopped entirely while game mode is on.

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

const HASHABLE_EXT: [&str; 6] = ["exe", "msi", "zip", "7z", "rar", "iso"];

pub fn is_hashable(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| HASHABLE_EXT.contains(&e.to_lowercase().as_str()))
        .unwrap_or(false)
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
        while !stop.load(Ordering::Relaxed) {
            let path = match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(p) => p,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
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
