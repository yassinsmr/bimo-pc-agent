//! Local encryption of the event log (council condition 8).
//!
//! Windows: every log line is protected with DPAPI (`CryptProtectData`,
//! current-user scope) — no password, no key stored in the code. The
//! disk line is `{"enc":"dpapi","data":"<hex ciphertext>"}`.
//!
//! Fallback (spec section 6): if DPAPI is unavailable — e.g. no real
//! user profile on the runner — the core records a warning in the log
//! itself and continues in plaintext. Encryption then stays an
//! "arrival-day" item, not a silent gap.

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

/// The mode this machine will use. On Windows we probe DPAPI once with a
/// tiny test blob; anywhere else (or on failure) we fall back to plain.
pub fn detect_mode() -> CryptoMode {
    #[cfg(windows)]
    {
        match dpapi_protect(b"bimo-eye-probe") {
            Some(_) => CryptoMode::Dpapi,
            None => CryptoMode::Plain,
        }
    }
    #[cfg(not(windows))]
    {
        CryptoMode::Plain
    }
}

/// Protect one log line for disk. Returns the exact line to write.
pub fn protect_line(line: &str, mode: CryptoMode) -> String {
    match mode {
        CryptoMode::Plain => line.to_string(),
        CryptoMode::Dpapi => {
            #[cfg(windows)]
            {
                match dpapi_protect(line.as_bytes()) {
                    Some(ct) => {
                        let v = serde_json::json!({
                            "enc": "dpapi",
                            "data": hex_encode(&ct),
                        });
                        serde_json::to_string(&v).unwrap_or_else(|_| line.to_string())
                    }
                    // DPAPI failed mid-run: write plaintext rather than
                    // losing the event, and let the reader see it is plain.
                    None => line.to_string(),
                }
            }
            #[cfg(not(windows))]
            {
                line.to_string()
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
