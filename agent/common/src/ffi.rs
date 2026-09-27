use crate::consent::{enforce_consent, ConsentToken, CURRENT_POLICY_VERSION};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use std::slice;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(CString::new(msg).unwrap_or_else(|_| CString::new("Unknown error").unwrap()));
    });
}

#[no_mangle]
pub extern "C" fn jocky_consent_token_verify(
    token_bytes: *const u8,
    token_len: usize,
    pubkey_bytes: *const u8,
    pubkey_len: usize,
) -> i32 {
    if token_bytes.is_null() || pubkey_bytes.is_null() {
        set_last_error("Null pointer provided".to_string());
        return 1;
    }
    let token_raw = unsafe { slice::from_raw_parts(token_bytes, token_len) };
    let pubkey = unsafe { slice::from_raw_parts(pubkey_bytes, pubkey_len) };

    let token: ConsentToken = match ciborium::from_reader(token_raw) {
        Ok(t) => t,
        Err(_) => match serde_json::from_slice(token_raw) {
            Ok(t) => t,
            Err(e) => {
                set_last_error(format!("Failed to parse consent token (tried CBOR and JSON): {}", e));
                return 2;
            }
        },
    };

    match enforce_consent(&token, pubkey, CURRENT_POLICY_VERSION) {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(format!("Consent token verification failed: {}", e));
            3
        }
    }
}

#[no_mangle]
pub extern "C" fn jocky_consent_token_free() {
    // No-op placeholder
}

#[no_mangle]
pub extern "C" fn jocky_jkm_verify(
    jkm_bytes: *const u8,
    jkm_len: usize,
    pubkey_bytes: *const u8,
    pubkey_len: usize,
) -> i32 {
    if jkm_bytes.is_null() || pubkey_bytes.is_null() {
        set_last_error("Null pointer provided".to_string());
        return 1;
    }
    let jkm_data = unsafe { slice::from_raw_parts(jkm_bytes, jkm_len) };
    let pubkey = unsafe { slice::from_raw_parts(pubkey_bytes, pubkey_len) };

    if jkm_data.len() < 64 {
        set_last_error("JKM data too short for header".to_string());
        return 2;
    }

    let mut magic = [0u8; 4];
    magic.copy_from_slice(&jkm_data[0..4]);
    if &magic != b"JKM\x01" {
        set_last_error("Invalid JKM magic".to_string());
        return 3;
    }

    let code_offset = u32::from_le_bytes(jkm_data[16..20].try_into().unwrap()) as usize;
    let code_len = u32::from_le_bytes(jkm_data[20..24].try_into().unwrap()) as usize;
    let manifest_offset = u32::from_le_bytes(jkm_data[24..28].try_into().unwrap()) as usize;
    let manifest_len = u32::from_le_bytes(jkm_data[28..32].try_into().unwrap()) as usize;
    let sig_offset = u32::from_le_bytes(jkm_data[32..36].try_into().unwrap()) as usize;
    let sig_len = u32::from_le_bytes(jkm_data[36..40].try_into().unwrap()) as usize;

    if sig_len != 64 {
        set_last_error(format!("Expected sig_len 64, got {}", sig_len));
        return 4;
    }

    if sig_offset + 64 > jkm_data.len() || manifest_offset + manifest_len > jkm_data.len() || code_offset + code_len > jkm_data.len() {
        set_last_error("JKM boundaries out of range".to_string());
        return 5;
    }

    let mut header_bytes = [0u8; 64];
    header_bytes.copy_from_slice(&jkm_data[0..64]);
    
    let mut payload = Vec::new();
    payload.extend_from_slice(&header_bytes);
    payload.extend_from_slice(&jkm_data[code_offset..code_offset + code_len]);
    payload.extend_from_slice(&jkm_data[manifest_offset..manifest_offset + manifest_len]);

    let sig_bytes = &jkm_data[sig_offset..sig_offset + 64];

    if pubkey.len() != 32 {
        set_last_error(format!("Expected 32 byte pubkey, got {}", pubkey.len()));
        return 6;
    }

    let verifying_key = match VerifyingKey::from_bytes(pubkey.try_into().unwrap()) {
        Ok(k) => k,
        Err(_) => {
            set_last_error("Invalid public key".to_string());
            return 7;
        }
    };
    
    let signature = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid signature format".to_string());
            return 8;
        }
    };

    if verifying_key.verify(&payload, &signature).is_err() {
        set_last_error("Signature verification failed".to_string());
        return 9;
    }

    // Optionally we could parse the manifest here, but signature verification is sufficient
    0
}

#[no_mangle]
pub extern "C" fn jocky_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn jocky_last_error() -> *mut c_char {
    LAST_ERROR.with(|e| {
        let mut err = e.borrow_mut();
        if let Some(c_str) = err.take() {
            c_str.into_raw()
        } else {
            std::ptr::null_mut()
        }
    })
}
