//! Local encryption of the event log (council condition 8 +
//! eye-core council condition 2: DPAPI fails CLOSED).
//!
//! Windows: every log line is protected with DPAPI (`CryptProtectData`,
//! current-user scope) — no password, no key stored in the code. The
//! disk line is `{"enc":"dpapi","data":"<hex ciphertext>"}`.
//!
//! Fail-closed (council condition 2, cycle 15): there is NO silent
//! fallback to plaintext anymore. If DPAPI is unavailable the eye
//! refuses to start writing sensitive lines, unless the operator
//! explicitly opts into plaintext with the environment variable
//! `BIMO_EYE_PLAINTEXT_OK=1` — and that opt-in is itself recorded as
//! a warning event in the log, so plaintext is never silent either.
//!
//! PRIORITY (cycle 55, council 12): the opt-in is checked FIRST, so
//! an explicit `BIMO_EYE_PLAINTEXT_OK=1` means plaintext EVEN where
//! DPAPI works. The old story — "opt-in only when DPAPI fails" —
//! is over: it made the opt-in useless on every machine with working
//! DPAPI (slice run 1: the eye was launched opted-in and the log
//! still came out encrypted). The guarantee narrows from a hard floor
//! (DPAPI always, no exception) to a procedural one (plaintext only
//! by an explicit, recorded opt-in) — that narrowing is documented
//! here deliberately, and the variable must only ever be set inside
//! a step (process scope) of a throwaway-runner workflow, never
//! machine/job-wide and never on the Legion path (permanent rule,
//! council 12). A mid-run DPAPI failure makes `protect_line` return
//! an error and the writer stops (the log is the product; a
//! half-written log that silently went plain is worse than a
//! stopped eye).
//!
//! Test seam: `BIMO_EYE_FORCE_CRYPTO_FAIL=1` simulates a DPAPI
//! failure on any platform (the same branches a real failure takes).
//! It exists so the self-test can prove the fail-closed path without
//! breaking a real Windows profile. Never set it in production.

use serde_json::Value;

/// Which protection the writer is actually using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    Dpapi,
    Plain,
}

impl CryptoMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoMode::Dpapi => "dpapi",
            CryptoMode::Plain => "plain",
        }
    }
}

/// Explicit plaintext opt-in, read from the environment.
/// Plaintext is only ever used when the operator asked for it.
pub fn plaintext_opt_in() -> bool {
    std::env::var("BIMO_EYE_PLAINTEXT_OK").map(|v| v == "1").unwrap_or(false)
}

/// Test seam: force every crypto operation to fail, as if DPAPI were
/// unavailable. Used by the self-test to prove the fail-closed path.
fn crypto_force_fail() -> bool {
    std::env::var("BIMO_EYE_FORCE_CRYPTO_FAIL")
        .map(|v| v == "1")
        .unwrap_or(false)
}

/// The mode this machine will use — or an error refusing to write.
///
/// Windows: probe DPAPI once with a tiny test blob. Anywhere else
/// (Linux/macOS dev builds) DPAPI does not exist, so the probe always
/// fails and the same branches apply. On failure the result is
/// `Plain` ONLY with an explicit opt-in, otherwise `Err` with a clear
/// message naming the refusal.
pub fn detect_mode() -> Result<CryptoMode, String> {
    // Explicit operator opt-in wins over DPAPI availability (cycle 55:
    // slice run 1 proved the old order wrong — the eye was launched
    // with BIMO_EYE_PLAINTEXT_OK=1 on a runner where DPAPI works, and
    // the log still came out DPAPI-encrypted, so no witness check
    // could read it). The opt-in is explicit and is itself recorded
    // as a warning event in the log, so plaintext is never silent.
    // Without the opt-in the old behavior is unchanged: DPAPI if it
    // works, refuse otherwise. Fail-closed is preserved.
    if plaintext_opt_in() {
        return Ok(CryptoMode::Plain);
    }
    if crypto_force_fail() {
        return Err("DPAPI unavailable (simulated failure): refusing to write \
                 sensitive log lines in plaintext; set BIMO_EYE_PLAINTEXT_OK=1 \
                 to opt in explicitly"
            .to_string());
    }
    #[cfg(windows)]
    {
        match dpapi_protect(b"bimo-eye-probe") {
            Some(_) => Ok(CryptoMode::Dpapi),
            None => Err("DPAPI unavailable on this machine: refusing to write \
                         sensitive log lines in plaintext; set \
                         BIMO_EYE_PLAINTEXT_OK=1 to opt in explicitly"
                .to_string()),
        }
    }
    #[cfg(not(windows))]
    {
        // No DPAPI off Windows: same rule — plaintext only by opt-in
        // (already returned Plain above), otherwise refuse.
        Err("DPAPI does not exist on this platform: refusing to write \
             sensitive log lines in plaintext; set BIMO_EYE_PLAINTEXT_OK=1 \
             to opt in explicitly"
            .to_string())
    }
}

/// Protect one log line for disk. Returns the exact line to write, or
/// an error — a failed protection is NEVER silently replaced by the
/// plaintext line (council condition 2).
pub fn protect_line(line: &str, mode: CryptoMode) -> Result<String, String> {
    match mode {
        CryptoMode::Plain => Ok(line.to_string()),
        CryptoMode::Dpapi => {
            // The seam simulates a DPAPI failure — it only affects the
            // DPAPI path, never plaintext (there is no DPAPI to fail
            // there).
            if crypto_force_fail() {
                return Err(
                    "crypto failure (simulated): refusing to write the line in plaintext"
                        .to_string(),
                );
            }
            #[cfg(windows)]
            {
                match dpapi_protect(line.as_bytes()) {
                    Some(ct) => {
                        let v = serde_json::json!({
                            "enc": "dpapi",
                            "data": hex_encode(&ct),
                        });
                        serde_json::to_string(&v)
                            .map_err(|e| format!("cannot serialise protected line: {e}"))
                    }
                    // DPAPI failed mid-run: fail closed, do not write plain.
                    None => Err(
                        "CryptProtectData failed mid-run: refusing to write the line in plaintext"
                            .to_string(),
                    ),
                }
            }
            #[cfg(not(windows))]
            {
                Err("dpapi mode selected on a non-Windows build".to_string())
            }
        }
    }
}

/// Reverse `protect_line`: returns the plaintext JSON line, or an error
/// string naming why this disk line cannot be read.
pub fn unprotect_line(disk: &str) -> Result<String, String> {
    let v: Value = match serde_json::from_str(disk) {
        Ok(v) => v,
        Err(_) => return Ok(disk.to_string()), // not JSON at all: raw line
    };
    let is_enc = v
        .get("enc")
        .and_then(|e| e.as_str())
        .map(|s| s == "dpapi")
        .unwrap_or(false);
    if !is_enc {
        return Ok(disk.to_string());
    }
    let hex = v
        .get("data")
        .and_then(|d| d.as_str())
        .ok_or_else(|| "dpapi line without data".to_string())?;
    #[cfg(windows)]
    {
        let ct = hex_decode(hex).ok_or_else(|| "dpapi line with bad hex".to_string())?;
        dpapi_unprotect(&ct)
            .and_then(|pt| String::from_utf8(pt).map_err(|_| "dpapi plaintext not utf8".to_string()))
    }
    #[cfg(not(windows))]
    {
        let _ = hex;
        Err("dpapi line cannot be read on a non-Windows build".to_string())
    }
}

pub fn hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(windows)]
fn dpapi_protect(data: &[u8]) -> Option<Vec<u8>> {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };
    use windows::core::PCWSTR;
    unsafe {
        let blob_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut blob_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        CryptProtectData(
            &blob_in,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut blob_out,
        )
        .ok()?;
        if blob_out.pbData.is_null() || blob_out.cbData == 0 {
            return None;
        }
        let out =
            std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec();
        let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            blob_out.pbData as *mut core::ffi::c_void,
        )));
        Some(out)
    }
}

#[cfg(windows)]
fn dpapi_unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };
    unsafe {
        let blob_in = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut blob_out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        CryptUnprotectData(
            &blob_in,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut blob_out,
        )
        .map_err(|e| format!("CryptUnprotectData failed: {e}"))?;
        if blob_out.pbData.is_null() || blob_out.cbData == 0 {
            return Err("CryptUnprotectData returned empty blob".to_string());
        }
        let out =
            std::slice::from_raw_parts(blob_out.pbData, blob_out.cbData as usize).to_vec();
        let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            blob_out.pbData as *mut core::ffi::c_void,
        )));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the env-mutating tests (cycle 22): Rust runs tests
    /// in parallel threads of ONE process, and `detect_mode` reads
    /// process-wide env vars. Without this lock the two tests race —
    /// `fail_closed_without_opt_in` can observe `BIMO_EYE_PLAINTEXT_OK=1`
    /// set by its sibling mid-test and fail spuriously (windows-eye
    /// run 26: passed in run 24, failed in run 26, same code).
    /// The guard is held for the whole test body, including cleanup.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_seam_env() {
        std::env::remove_var("BIMO_EYE_FORCE_CRYPTO_FAIL");
        std::env::remove_var("BIMO_EYE_PLAINTEXT_OK");
    }

    #[test]
    fn fail_closed_without_opt_in() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seam_env();
        std::env::set_var("BIMO_EYE_FORCE_CRYPTO_FAIL", "1");
        // Simulated DPAPI failure, no opt-in: detection must refuse.
        assert!(detect_mode().is_err());
        // And a single line must refuse too, never fall back to plain.
        assert!(protect_line("{\"type\":\"x\"}", CryptoMode::Dpapi).is_err());
        clear_seam_env();
    }

    #[test]
    fn opt_in_allows_plain_explicitly() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_seam_env();
        std::env::set_var("BIMO_EYE_FORCE_CRYPTO_FAIL", "1");
        std::env::set_var("BIMO_EYE_PLAINTEXT_OK", "1");
        assert_eq!(detect_mode().unwrap(), CryptoMode::Plain);
        assert_eq!(
            protect_line("{\"type\":\"x\"}", CryptoMode::Plain).unwrap(),
            "{\"type\":\"x\"}"
        );
        clear_seam_env();
    }
}
