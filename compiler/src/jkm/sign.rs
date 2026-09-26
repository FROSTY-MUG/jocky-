//! JOCKY Ed25519 Digital Signing and Verification
//!
//! Purpose: Provides Ed25519 cryptographic key generation, file-based serialization
//!          (hex/PEM format), and message signing / verification for .jkm binary modules.
//! Inputs: Ed25519 keypair paths or raw bytes, payload buffer (header + code + manifest).
//! Outputs: 64-byte Ed25519 signature, verification success or cryptographic error.
//! Exit Codes: N/A (Library module; returns Result<T, anyhow::Error>).
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

/// Length of raw Ed25519 public key in bytes
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Length of raw Ed25519 secret seed in bytes
pub const ED25519_SECRET_LEN: usize = 32;
/// Length of raw Ed25519 signature in bytes
pub const ED25519_SIG_LEN: usize = 64;

/// Generate a cryptographically secure Ed25519 signing keypair
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    use rand::RngCore;
    let mut csprng = OsRng;
    let mut secret_bytes = [0u8; ED25519_SECRET_LEN];
    csprng.fill_bytes(&mut secret_bytes);
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Save an Ed25519 signing key to a file (hex-encoded with header)
pub fn save_private_key(key: &SigningKey, path: impl AsRef<Path>) -> Result<()> {
    let hex_bytes = hex::encode(key.to_bytes());
    let content = format!("-----BEGIN JOCKY ED25519 PRIVATE KEY-----\n{}\n-----END JOCKY ED25519 PRIVATE KEY-----\n", hex_bytes);
    fs::write(path.as_ref(), content)
        .with_context(|| format!("Failed to write private key to {:?}", path.as_ref()))?;
    Ok(())
}

/// Save an Ed25519 verifying key to a file (hex-encoded with header)
pub fn save_public_key(key: &VerifyingKey, path: impl AsRef<Path>) -> Result<()> {
    let hex_bytes = hex::encode(key.to_bytes());
    let content = format!("-----BEGIN JOCKY ED25519 PUBLIC KEY-----\n{}\n-----END JOCKY ED25519 PUBLIC KEY-----\n", hex_bytes);
    fs::write(path.as_ref(), content)
        .with_context(|| format!("Failed to write public key to {:?}", path.as_ref()))?;
    Ok(())
}

/// Load an Ed25519 signing key from a file (supports header-wrapped hex or raw 32-byte hex)
pub fn load_private_key(path: impl AsRef<Path>) -> Result<SigningKey> {
    let content = fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read private key from {:?}", path.as_ref()))?;
    let lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let hex_str = lines.join("");
    let bytes = hex::decode(&hex_str)
        .map_err(|e| anyhow!("Invalid hex format in private key {:?}: {}", path.as_ref(), e))?;
    if bytes.len() != ED25519_SECRET_LEN {
        return Err(anyhow!(
            "Invalid private key length: expected {} bytes, got {}",
            ED25519_SECRET_LEN,
            bytes.len()
        ));
    }
    let mut key_bytes = [0u8; ED25519_SECRET_LEN];
    key_bytes.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Load an Ed25519 verifying key from a file (supports header-wrapped hex or raw 32-byte hex)
pub fn load_public_key(path: impl AsRef<Path>) -> Result<VerifyingKey> {
    let content = fs::read_to_string(path.as_ref())
        .with_context(|| format!("Failed to read public key from {:?}", path.as_ref()))?;
    let lines: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with("-----"))
        .collect();
    let hex_str = lines.join("");
    let bytes = hex::decode(&hex_str)
        .map_err(|e| anyhow!("Invalid hex format in public key {:?}: {}", path.as_ref(), e))?;
    if bytes.len() != ED25519_PUBKEY_LEN {
        return Err(anyhow!(
            "Invalid public key length: expected {} bytes, got {}",
            ED25519_PUBKEY_LEN,
            bytes.len()
        ));
    }
    let mut key_bytes = [0u8; ED25519_PUBKEY_LEN];
    key_bytes.copy_from_slice(&bytes);
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| anyhow!("Invalid Ed25519 verifying key: {}", e))
}

/// Sign a payload using the given Ed25519 signing key
pub fn sign_container(signing_key: &SigningKey, payload: &[u8]) -> [u8; ED25519_SIG_LEN] {
    let sig: Signature = signing_key.sign(payload);
    sig.to_bytes()
}

/// Verify that a signature matches the payload under the given verifying key
pub fn verify_container(verifying_key: &VerifyingKey, payload: &[u8], signature_bytes: &[u8]) -> Result<()> {
    if signature_bytes.len() != ED25519_SIG_LEN {
        return Err(anyhow!(
            "Invalid signature length: expected {} bytes, got {}",
            ED25519_SIG_LEN,
            signature_bytes.len()
        ));
    }
    let sig = Signature::from_slice(signature_bytes)
        .map_err(|e| anyhow!("Malformed Ed25519 signature: {}", e))?;
    verifying_key
        .verify(payload, &sig)
        .map_err(|e| anyhow!("Ed25519 signature verification failed: {}", e))
}
