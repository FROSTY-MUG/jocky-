//! Signed build manifest: authenticates the team that attested an agent binary.
//!
//! Every agent ships with a `SignedManifest` embedded alongside its binary. The
//! manifest binds the binary's hash and target triple to a team signing key so
//! that, at registration time, the manager (and the agent itself) can confirm
//! the binary is an authentic, unmodified JOCKY build and not an attacker's
//! replacement. Verification is performed with Ed25519, mirroring
//! [`crate::consent`].

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::constants;

/// A team-signed attestation of an agent binary's provenance.
///
/// The `signature` field covers [`SignedManifest::to_json_for_signing`] (i.e.
/// every field *except* `signature` itself) and is verified against the team's
/// long-term Ed25519 public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    /// Identifier of the team key that signed this manifest (key handle).
    pub team_key_id: String,
    /// Unique build identifier (e.g. a git SHA or UUID).
    pub build_id: String,
    /// Policy version the binary was built and signed under.
    pub policy_version: String,
    /// Per-agent diversification seed used by the compiler to permute bytecode.
    pub diversification_seed: u64,
    /// Hex-encoded hash (SHA-256) of the signed agent binary.
    pub binary_hash: String,
    /// Size of the signed agent binary, in bytes.
    pub binary_size: u64,
    /// `target-triple` the binary was compiled for (e.g. `x86_64-pc-windows-msvc`).
    pub target_triple: String,
    /// UTC timestamp at which the manifest was produced.
    pub created_at: DateTime<Utc>,
    /// Ed25519 detached signature over the canonical manifest payload.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl SignedManifest {
    /// Construct an unsigned manifest. Call [`SignedManifest::sign`] to populate
    /// `signature` before presenting it to the manager.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        team_key_id: impl Into<String>,
        build_id: impl Into<String>,
        policy_version: impl Into<String>,
        diversification_seed: u64,
        binary_hash: impl Into<String>,
        binary_size: u64,
        target_triple: impl Into<String>,
    ) -> Self {
        Self {
            team_key_id: team_key_id.into(),
            build_id: build_id.into(),
            policy_version: policy_version.into(),
            diversification_seed,
            binary_hash: binary_hash.into(),
            binary_size,
            target_triple: target_triple.into(),
            created_at: Utc::now(),
            signature: Vec::new(),
        }
    }

    /// Canonical, signature-compatible JSON representation of the manifest.
    ///
    /// The `signature` field is excluded so that signing and verification
    /// operate over a stable, byte-identical payload.
    pub fn to_json_for_signing(&self) -> String {
        #[derive(Serialize)]
        struct ManifestPayload<'a> {
            team_key_id: &'a str,
            build_id: &'a str,
            policy_version: &'a str,
            diversification_seed: u64,
            binary_hash: &'a str,
            binary_size: u64,
            target_triple: &'a str,
            created_at: DateTime<Utc>,
        }

        let payload = ManifestPayload {
            team_key_id: &self.team_key_id,
            build_id: &self.build_id,
            policy_version: &self.policy_version,
            diversification_seed: self.diversification_seed,
            binary_hash: &self.binary_hash,
            binary_size: self.binary_size,
            target_triple: &self.target_triple,
            created_at: self.created_at,
        };
        serde_json::to_string(&payload)
            .expect("manifest signing payload is always serializable")
    }

    /// Sign the canonical manifest payload in place using the team signing key.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let payload = self.to_json_for_signing();
        let signature: Signature = signing_key.sign(payload.as_bytes());
        self.signature = signature.to_bytes().to_vec();
    }

    /// Verify the manifest's Ed25519 signature against a team public key.
    ///
    /// Returns `Ok(())` when the signature is valid; otherwise an `anyhow`
    /// error describing the failure (malformed key/signature, signature
    /// mismatch, etc.).
    pub fn verify(&self, public_key_bytes: &[u8]) -> Result<()> {
        if public_key_bytes.len() != constants::ED25519_KEY_LEN {
            return Err(anyhow!(
                "team public key must be {} bytes, got {}",
                constants::ED25519_KEY_LEN,
                public_key_bytes.len()
            ));
        }
        if self.signature.len() != constants::ED25519_SIGNATURE_LEN {
            return Err(anyhow!(
                "manifest signature must be {} bytes, got {}",
                constants::ED25519_SIGNATURE_LEN,
                self.signature.len()
            ));
        }

        let public_key: [u8; constants::ED25519_KEY_LEN] = public_key_bytes
            .try_into()
            .map_err(|_| anyhow!("failed to coerce team public key to fixed array"))?;
        let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|e| {
            anyhow!("team public key is not a valid Ed25519 point: {}", e)
        })?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("manifest signature is malformed"))?;

        let payload = self.to_json_for_signing();
        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| anyhow!("manifest signature does not verify against team key"))?;
        Ok(())
    }
}

impl Zeroize for SignedManifest {
    /// Scrub the embedded signature and binary hash from memory on drop paths.
    fn zeroize(&mut self) {
        self.signature.zeroize();
        self.binary_hash.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; constants::ED25519_KEY_LEN];
        bytes[0] = 0x9d;
        bytes[1] = 0x61;
        bytes[2] = 0xb1;
        bytes[3] = 0x9d;
        bytes[4] = 0xef;
        bytes[5] = 0xfd;
        bytes[6] = 0x5a;
        bytes[7] = 0x60;
        bytes[8] = 0xba;
        bytes[9] = 0x84;
        bytes[10] = 0x4a;
        bytes[11] = 0xf4;
        bytes[12] = 0x92;
        bytes[13] = 0xec;
        bytes[14] = 0x2c;
        bytes[15] = 0xc4;
        bytes[16] = 0x44;
        bytes[17] = 0x49;
        bytes[18] = 0xc5;
        bytes[19] = 0x69;
        bytes[20] = 0x7b;
        bytes[21] = 0x32;
        bytes[22] = 0x69;
        bytes[23] = 0x19;
        bytes[24] = 0x70;
        bytes[25] = 0x3b;
        bytes[26] = 0xac;
        bytes[27] = 0x03;
        bytes[28] = 0x1c;
        bytes[29] = 0xae;
        bytes[30] = 0x7f;
        bytes[31] = 0x60;
        SigningKey::from_bytes(&bytes)
    }

    fn fresh_manifest() -> SignedManifest {
        let mut m = SignedManifest::new(
            "team-key-1",
            "build-2026-09-27T00-00-00",
            constants::POLICY_VERSION,
            0xdeadbeef,
            "00112233445566778899aabbccddeeff",
            4096,
            "x86_64-pc-windows-msvc",
        );
        m.sign(&signing_key());
        m
    }

    #[test]
    fn signed_manifest_verifies() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let manifest = fresh_manifest();
        assert!(manifest.verify(&vk).is_ok());
    }

    #[test]
    fn tampered_hash_is_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let mut manifest = fresh_manifest();
        manifest.binary_hash = "ff".repeat(16);
        assert!(manifest.verify(&vk).is_err());
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let mut manifest = fresh_manifest();
        manifest.signature[0] ^= 0xff;
        assert!(manifest.verify(&vk).is_err());
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        let manifest = fresh_manifest();
        assert!(manifest.verify(&[0u8; 10]).is_err());
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let manifest = fresh_manifest();
        let json = serde_json::to_string(&manifest).expect("manifest serializes");
        let decoded: SignedManifest =
            serde_json::from_str(&json).expect("manifest deserializes");
        assert!(decoded.verify(&vk).is_ok());
    }
}