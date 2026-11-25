//! DPAPI protection for shot files (cycle-31 close-out, council
//! condition 8): every shot JPEG is protected with DPAPI
//! (current-user scope) right after encoding, and stored as
//! `shot-000001.jpg.dpapi`. A plain JPEG must never remain on disk:
//! if protection fails, the caller deletes the plain file and reports
//! the shot as failed (fail-closed, same doctrine as the eye log).
//!
//! Twin of `bimo-eye/src/crypto.rs::dpapi_protect` — kept separate
//! because `bimo-shot` must not depend on `bimo-eye`.

use std::path::Path;

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

/// Protect the file at `path` in place (Windows only): read the
/// bytes, DPAPI-protect them, write the ciphertext back.
pub fn protect_file(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let plain =
            std::fs::read(path).map_err(|e| format!("cannot read shot for encryption: {e}"))?;
        let ct = dpapi_protect(&plain).ok_or_else(|| "CryptProtectData failed".to_string())?;
        std::fs::write(path, ct).map_err(|e| format!("cannot write protected shot: {e}"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("dpapi unavailable off Windows".to_string())
    }
}

/// Unprotect bytes (Windows only) — the self-test reads shot files
/// back through this to check the JPEG inside.
pub fn unprotect_bytes(data: &[u8]) -> Result<Vec<u8>, String> {
    #[cfg(windows)]
    {
        dpapi_unprotect(data)
    }
    #[cfg(not(windows))]
    {
        let _ = data;
        Err("dpapi unavailable off Windows".to_string())
    }
}
