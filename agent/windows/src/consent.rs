//! Windows-agent-side consent gate.
//!
//! Wraps the platform-level verification in [`jocky_common::consent`] behind the
//! agent's own (boolean) decision point: collection is only permitted when the
//! team-signed consent token verifies against the trusted team public key.

use jocky_common::consent::{ConsentError, ConsentToken};

/// Returns `true` only when `token` is structurally well-formed, carries a valid
/// Ed25519 signature made by `public_key`, and is within its validity window.
pub fn verify_agent_consent(token: &ConsentToken, public_key: &[u8]) -> bool {
    match token.verify(public_key) {
        Ok(()) => {
            println!(
                "[INFO] Cryptographic consent token verified for scope: {}",
                token.scope
            );
            true
        }
        Err(ConsentError::InvalidSignature) => {
            eprintln!(
                "[ERROR] Consent token signature invalid. Agent operational scope blocked."
            );
            false
        }
        Err(ConsentError::Expired) => {
            eprintln!("[ERROR] Consent token expired. Agent operational scope blocked.");
            false
        }
        Err(ConsentError::NotYetValid) => {
            eprintln!("[ERROR] Consent token not yet valid. Agent operational scope blocked.");
            false
        }
        Err(ConsentError::InvalidPolicyVersion) => {
            eprintln!(
                "[ERROR] Consent token policy version not accepted. Agent operational scope blocked."
            );
            false
        }
        Err(ConsentError::Malformed) => {
            eprintln!("[ERROR] Consent token or key material malformed. Agent operational scope blocked.");
            false
        }
    }
}