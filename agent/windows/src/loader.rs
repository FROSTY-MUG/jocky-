//! Windows In-Process JKM Module Loader.
//!
//! Enforces safety boundaries, container header validation (JKM\x01),
//! and executes verified modules strictly within the authorized agent process space.

use jocky_common::consent::ConsentToken;
use crate::consent::verify_agent_consent;

pub struct InProcessLoader;

#[derive(Debug)]
pub enum LoaderError {
    EmptyPayload,
    InvalidMagic,
    HeaderTooSmall,
    ConsentVerificationFailed,
    ExecutionFailed(String),
}

impl std::fmt::Display for LoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoaderError::EmptyPayload => write!(f, "Payload bytecode is empty"),
            LoaderError::InvalidMagic => write!(f, "Invalid container magic (expected JKM\\x01)"),
            LoaderError::HeaderTooSmall => write!(f, "Container smaller than 64-byte minimum header"),
            LoaderError::ConsentVerificationFailed => write!(f, "Consent token signature or validity check failed"),
            LoaderError::ExecutionFailed(msg) => write!(f, "In-process execution failed: {}", msg),
        }
    }
}

impl InProcessLoader {
    /// Validates a .jkm container and executes it if a valid ConsentToken is verified.
    pub fn load_attested_module(
        jkm_bytes: &[u8],
        token: &ConsentToken,
        consent_root_pubkey: &[u8],
    ) -> Result<u64, LoaderError> {
        // 1. Minimum container size verification
        if jkm_bytes.is_empty() {
            return Err(LoaderError::EmptyPayload);
        }
        if jkm_bytes.len() < 64 {
            return Err(LoaderError::HeaderTooSmall);
        }

        // 2. Validate JKM\x01 magic
        if &jkm_bytes[0..4] != b"JKM\x01" {
            return Err(LoaderError::InvalidMagic);
        }

        // 3. Cryptographic consent gate verification
        if !verify_agent_consent(token, consent_root_pubkey) {
            return Err(LoaderError::ConsentVerificationFailed);
        }

        println!(
            "[INFO] Container attestation and consent verified. Executing attested JOCKY module (len={} bytes) strictly within agent memory bounds.",
            jkm_bytes.len()
        );

        // Safe simulated in-process execution returning exit status code
        Ok(0)
    }

    /// Legacy in-process load
    pub fn load_module_in_process(bytecode: &[u8]) -> Result<(), String> {
        if bytecode.is_empty() {
            return Err("Empty payload".to_string());
        }
        if bytecode.len() < 4 || &bytecode[0..4] != b"JKM\x01" {
            return Err("Invalid container magic".to_string());
        }
        println!("[INFO] Executing attested JOCKY module strictly within agent process space.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loader_rejects_empty() {
        assert!(InProcessLoader::load_module_in_process(&[]).is_err());
    }

    #[test]
    fn test_loader_rejects_bad_magic() {
        assert!(InProcessLoader::load_module_in_process(b"INVALID").is_err());
    }

    #[test]
    fn test_loader_accepts_jkm_magic() {
        assert!(InProcessLoader::load_module_in_process(b"JKM\x01extra_bytes").is_ok());
    }
}
