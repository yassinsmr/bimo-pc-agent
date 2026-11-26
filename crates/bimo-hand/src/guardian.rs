//! The guardian gate (council condition 2).
//!
//! `verdict(path) -> Clear | Block(reason) | Unknown`. v1 is a fingerprint
//! blocklist: the EICAR content string and the file SHA-256. Any file whose
//! fingerprint matches known confirmed malware NEVER runs.
//!
//! FAIL-CLOSED: when the guardian is absent or unresponsive, the hand
//! executes NOTHING and commands stay `queued` with reason
//! `guardian_unavailable` — no silent skip.
//!
//! Containment (named technique): a Job Object with no breakaway + an
//! active-process limit of 32 + execution only from the command's working
//! directory. Proof (8.5): a child in the job spawns a grandchild, and the
//! grandchild IS in the job (`IsProcessInJob` true) — no escape.
//!
//! A3 branch (owner decision 2026-11-26): when a game binary ITSELF is
//! confirmed malicious (fingerprint match), the hand stops and presents the
//! three options (clean swap / do not run / run by the owner's decision) as
//! state `needs_approval` — NO silent cleaning and NO silent swap. In v1
//! the presentation is the queue state + an alert file; the choice UI
//! comes later.
//!
//! Honest description: best-effort user-mode detection and containment;
//! the only hard guarantee is the fingerprint check.

use crate::{file_sha256, sha256_hex};
use std::fs;
use std::path::{Path, PathBuf};

/// The standard 68-byte EICAR antivirus test string. NOT malware — the
/// industry-standard test file. `EICAR_SHA256` is its known SHA-256.
pub const EICAR: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
pub const EICAR_SHA256: &str =
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0e9b";

/// The guardian's verdict on one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The fingerprint list does not match; the file may proceed.
    Clear,
    /// Fingerprint match: never execute. The reason names the match.
    Block(String),
    /// The guardian (or the file) could not be checked: fail closed.
    Unknown(String),
}

/// The guardian. `base` is an optional path the guardian depends on; when
/// it is set and does not exist, the guardian is absent (proof 8.7).
/// `Guardian::default()` is the built-in fingerprint list, always present.
#[derive(Debug, Clone)]
pub struct Guardian {
    pub base: Option<PathBuf>,
}

impl Default for Guardian {
    fn default() -> Self {
        Guardian { base: None }
    }
}

impl Guardian {
    pub fn with_base(base: &Path) -> Self {
        Guardian {
            base: Some(base.to_path_buf()),
        }
    }

    pub fn is_available(&self) -> bool {
        match &self.base {
            None => true,
            Some(p) => p.exists(),
        }
    }

    /// The fingerprint verdict for one file.
    pub fn verdict(&self, path: &Path) -> Verdict {
        if !self.is_available() {
            return Verdict::Unknown("guardian_unavailable".to_string());
        }
        if !path.exists() {
            return Verdict::Unknown("file_not_found".to_string());
        }
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) => return Verdict::Unknown(format!("read_failed: {}", e)),
        };
        if contains_eicar(&bytes) {
            return Verdict::Block("eicar".to_string());
        }
        if sha256_hex(&bytes) == EICAR_SHA256 {
            return Verdict::Block("eicar".to_string());
        }
        Verdict::Clear
    }

    /// The gate the executor must pass before any execution. Returns
    /// `Ok(())` only on `Clear`; a block or an unknown guardian is an
    /// error naming the reason (`blocked_eicar` /
    /// `guardian_unavailable`).
    pub fn gate(&self, path: &Path) -> Result<(), String> {
        match self.verdict(path) {
            Verdict::Clear => Ok(()),
            Verdict::Block(reason) => Err(format!("blocked_{}", reason)),
            Verdict::Unknown(reason) => Err(reason),
        }
    }
}

fn contains_eicar(bytes: &[u8]) -> bool {
    if bytes.len() < EICAR.len() {
        return false;
    }
    bytes.windows(EICAR.len()).any(|w| w == EICAR)
}

/// Copy a blocked file into the quarantine directory untouched, verifying
/// the checksum before and after. The original is never executed.
pub fn quarantine_copy(src: &Path, quarantine_dir: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(quarantine_dir).map_err(|e| e.to_string())?;
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let dest = quarantine_dir.join(name);
    let before = file_sha256(src)?;
    fs::copy(src, &dest).map_err(|e| e.to_string())?;
    let after = file_sha256(&dest)?;
    if before != after {
        return Err("quarantine copy checksum mismatch".to_string());
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bimo-hand-gtest-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn eicar_is_blocked_and_a_clean_file_is_clear() {
        let g = Guardian::default();
        let eicar_path = write_temp("eicar.com", EICAR);
        assert_eq!(g.verdict(&eicar_path), Verdict::Block("eicar".to_string()));
        assert!(g.gate(&eicar_path).is_err());
        let clean_path = write_temp("clean.bin", b"hello, this is a clean file");
        assert_eq!(g.verdict(&clean_path), Verdict::Clear);
        assert!(g.gate(&clean_path).is_ok());
        let _ = fs::remove_dir_all(eicar_path.parent().unwrap());
        let _ = fs::remove_dir_all(clean_path.parent().unwrap());
    }

    #[test]
    fn absent_guardian_is_unknown_fail_closed() {
        let dead = std::env::temp_dir().join("bimo-hand-guardian-dead-path-xyz");
        let g = Guardian::with_base(&dead);
        assert!(!g.is_available());
        let clean_path = write_temp("clean2.bin", b"clean");
        assert_eq!(
            g.verdict(&clean_path),
            Verdict::Unknown("guardian_unavailable".to_string())
        );
        assert_eq!(g.gate(&clean_path), Err("guardian_unavailable".to_string()));
        let _ = fs::remove_dir_all(clean_path.parent().unwrap());
    }

    #[test]
    fn eicar_constant_is_68_bytes() {
        assert_eq!(EICAR.len(), 68);
        assert_eq!(sha256_hex(EICAR), EICAR_SHA256);
    }
}
