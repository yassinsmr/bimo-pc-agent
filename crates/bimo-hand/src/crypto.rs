//! Per-line encryption for the hand queue, mirroring bimo-eye `crypto.rs`.
//!
//! FAIL-CLOSED: on Windows every queue line is DPAPI-protected
//! (CryptProtectData, current-user scope). Without DPAPI — and without the
//! explicit `BIMO_HAND_PLAINTEXT_OK=1` opt-in — the queue refuses to open.
//! There is never a silent plaintext fallback.
//!
//! DPAPI protects against another user, or a stolen disk. It does NOT
//! protect against malware running with the same privileges as the hand.

use crate::{hex_decode, hex_encode};

/// The encryption mode in use for the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    /// Windows DPAPI (current user).
    Dpapi,
    /// Plaintext, only with the explicit opt-in (tests / non-Windows).
    PlaintextOptIn,
}

/// Explicit plaintext opt-in, for tests on non-Windows machines.
pub fn plaintext_opt_in() -> bool {
    std::env::var("BIMO_HAND_PLAINTEXT_OK").map(|v| v == "1").unwrap_or(false)
}

/// Decide the mode, or refuse (fail-closed).
pub fn detect_mode() -> Result<CryptoMode, String> {
    if cfg!(windows) {
        Ok(CryptoMode::Dpapi)
    } else if plaintext_opt_in() {
        Ok(CryptoMode::PlaintextOptIn)
    } else {
        Err(
            "hand queue refuses to open: no DPAPI on this platform and \
             BIMO_HAND_PLAINTEXT_OK is not set to 1 (fail-closed)".to_string(),
        )
    }
}

/// Protect one queue line. Returns a one-line JSON wrapper:
/// `{"enc":"dpapi","data":"<hex>"}` or `{"enc":"plain","data":"<json>"}`.
pub fn protect_line(plain: &str) -> Result<String, String> {
    match detect_mode()? {
        CryptoMode::Dpapi => {
            let hex = dpapi_protect(plain.as_bytes())?;
            Ok(format!("{{\"enc\":\"dpapi\",\"data\":\"{}\"}}", hex))
        }
        CryptoMode::PlaintextOptIn => {
            let escaped = serde_json::to_string(plain).map_err(|e| e.to_string())?;
            Ok(format!("{{\"enc\":\"plain\",\"data\":{}}}", escaped))
        }
    }
}

/// Unprotect one queue line produced by [`protect_line`].
pub fn unprotect_line(line: &str) -> Result<String, String> {
    let wrapper: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("bad queue line: {}", e))?;
    let enc = wrapper.get("enc").and_then(|v| v.as_str()).unwrap_or("");
    match enc {
        "dpapi" => {
            if !cfg!(windows) {
                return Err("dpapi queue line cannot be opened on this platform".into());
            }
            let hex = wrapper
                .get("data")
                .and_then(|v| v.as_str())
                .ok_or("dpapi queue line has no data")?;
            let bytes = hex_decode(hex).ok_or("dpapi queue line is not hex")?;
            let plain = dpapi_unprotect(&bytes)?;
            String::from_utf8(plain).map_err(|e| format!("dpapi line is not UTF-8: {}", e))
        }
        "plain" => {
            if !plaintext_opt_in() {
                return Err(
                    "plaintext queue line refused: BIMO_HAND_PLAINTEXT_OK is not 1 (fail-closed)"
                        .to_string(),
                );
            }
            wrapper
                .get("data")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| "plaintext queue line has no data".to_string())
        }
        other => Err(format!("unknown queue line encoding: {}", other)),
    }
}

#[cfg(windows)]
fn dpapi_protect(plain: &[u8]) -> Result<String, String> {
    use windows::Win32::Foundation::HLOCAL;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{
        CryptProtectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
    };
    use windows::core::PCWSTR;
    let mut data = plain.to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptProtectData(
            &input,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok.is_err() {
        return Err("CryptProtectData failed".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
    }
    Ok(hex_encode(&bytes))
}

#[cfg(windows)]
fn dpapi_unprotect(blob: &[u8]) -> Result<Vec<u8>, String> {
    use windows::Win32::Foundation::HLOCAL;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    let mut data = blob.to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptUnprotectData(&input, None, None, None, None, 0, &mut output)
    };
    if ok.is_err() {
        return Err("CryptUnprotectData failed".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn dpapi_protect(_plain: &[u8]) -> Result<String, String> {
    Err("DPAPI is Windows-only".into())
}

#[cfg(not(windows))]
fn dpapi_unprotect(_blob: &[u8]) -> Result<Vec<u8>, String> {
    Err("DPAPI is Windows-only".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_without_opt_in() {
        if cfg!(windows) {
            return;
        }
        std::env::remove_var("BIMO_HAND_PLAINTEXT_OK");
        assert!(detect_mode().is_err());
        assert!(protect_line("x").is_err());
    }

    #[test]
    fn plaintext_round_trip_with_opt_in() {
        if cfg!(windows) {
            return;
        }
        std::env::set_var("BIMO_HAND_PLAINTEXT_OK", "1");
        let line = protect_line("{\"a\":1}").unwrap();
        assert_eq!(unprotect_line(&line).unwrap(), "{\"a\":1}");
    }
}
