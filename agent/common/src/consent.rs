//! Consent tokens: cryptographically signed, time-bound proof that an agent has
//! been granted a specific forensic scope for a bounded number of operations.
//!
//! Consent is the central safety primitive of the JOCKY platform. Every
//! collection module checks a `ConsentToken` (and its sibling
//! [`crate::manifest::SignedManifest`]) before doing work, so a stolen or
//! expired agent can never operate out-of-scope or after its authorization has
//! been revoked.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::constants;

/// The policy version embedded in tokens authored by this crate. Must equal the
/// `POLICY_VERSION` constant to be accepted by [`enforce_consent`].
pub const CURRENT_POLICY_VERSION: &str = constants::POLICY_VERSION;

/// A cryptographically signed, scope-bound, time-limited consent token.
///
/// The token authorizes an `agent_id` to perform a bounded number of
/// `max_ops` operations within `scope`. It is signed by a team signing key and
/// is only valid between `not_before` and `not_after`. The `signature` field is
/// intentionally excluded from [`ConsentToken::to_json_for_signing`] so that
/// signing is performed over a canonical, stable representation of the token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentToken {
    /// Identifier of the agent this token was issued to.
    pub agent_id: String,
    /// Forensic scope granted (e.g. `"process-enumeration"`, `"memory-acquisition"`).
    pub scope: String,
    /// Earliest time (UTC) at which the token is valid.
    pub not_before: DateTime<Utc>,
    /// Latest time (UTC) at which the token is valid.
    pub not_after: DateTime<Utc>,
    /// Policy version the token was issued under.
    pub policy_version: String,
    /// Maximum number of operations the agent may perform under this token.
    pub max_ops: u64,
    /// Unique nonce chosen by the issuer to prevent token replay.
    pub nonce: String,
    /// Ed25519 detached signature over [`ConsentToken::to_json_for_signing`].
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl ConsentToken {
    /// Create an unsigned consent token valid for `ttl_secs` seconds.
    ///
    /// The TTL is clamped to `[MIN_CONSENT_TTL_SECS, MAX_CONSENT_TTL_SECS]` so
    /// that no token can outlive the platform maximum or receive a non-positive
    /// lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agent_id: impl Into<String>,
        scope: impl Into<String>,
        ttl_secs: i64,
        policy_version: impl Into<String>,
        max_ops: u64,
        nonce: impl Into<String>,
    ) -> Self {
        let ttl = ttl_secs.clamp(constants::MIN_CONSENT_TTL_SECS, constants::MAX_CONSENT_TTL_SECS);
        let now = Utc::now();
        Self {
            agent_id: agent_id.into(),
            scope: scope.into(),
            not_before: now,
            not_after: now + Duration::seconds(ttl),
            policy_version: policy_version.into(),
            max_ops,
            nonce: nonce.into(),
            signature: Vec::new(),
        }
    }

    /// Canonical, signature-compatible JSON representation of the token.
    ///
    /// The `signature` field is deliberately omitted: both the issuer (signing)
    /// and the holder (verifying) derive the exact same bytes, so the signature
    /// is always computed and checked over this payload. Field order is stable
    /// (declaration order) and `serde_json::to_string` produces compact output,
    /// making this representation byte-stable.
    pub fn to_json_for_signing(&self) -> String {
        #[derive(Serialize)]
        struct ConsentPayload<'a> {
            agent_id: &'a str,
            scope: &'a str,
            not_before: DateTime<Utc>,
            not_after: DateTime<Utc>,
            policy_version: &'a str,
            max_ops: u64,
            nonce: &'a str,
        }

        let payload = ConsentPayload {
            agent_id: &self.agent_id,
            scope: &self.scope,
            not_before: self.not_before,
            not_after: self.not_after,
            policy_version: &self.policy_version,
            max_ops: self.max_ops,
            nonce: &self.nonce,
        };
        serde_json::to_string(&payload)
            .expect("consent signing payload is always serializable")
    }

    /// Sign the canonical payload in place using the given team signing key.
    ///
    /// After this call `signature` is populated and the token is ready for
    /// distribution to agents.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let payload = self.to_json_for_signing();
        let signature: Signature = signing_key.sign(payload.as_bytes());
        self.signature = signature.to_bytes().to_vec();
    }

    /// Returns `true` when the token has passed its `not_after` validity window.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Verify the Ed25519 signature and the temporal validity windows.
    ///
    /// The signature is verified first (so the time fields are only trusted once
    /// authenticity is established), then `not_before` and `not_after` are
    /// checked against the current wall clock.
    pub fn verify(&self, public_key_bytes: &[u8]) -> Result<(), ConsentError> {
        if public_key_bytes.len() != constants::ED25519_KEY_LEN {
            return Err(ConsentError::Malformed);
        }
        if self.signature.len() != constants::ED25519_SIGNATURE_LEN {
            return Err(ConsentError::Malformed);
        }

        let public_key: [u8; constants::ED25519_KEY_LEN] = public_key_bytes
            .try_into()
            .map_err(|_| ConsentError::Malformed)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| ConsentError::Malformed)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| ConsentError::Malformed)?;

        let payload = self.to_json_for_signing();
        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| ConsentError::InvalidSignature)?;

        let now = Utc::now();
        if now < self.not_before {
            return Err(ConsentError::NotYetValid);
        }
        if now > self.not_after {
            return Err(ConsentError::Expired);
        }
        Ok(())
    }
}

impl Zeroize for ConsentToken {
    /// Scrub sensitive, issuer-chosen material from memory on drop paths.
    fn zeroize(&mut self) {
        self.nonce.zeroize();
        self.signature.zeroize();
    }
}

/// Verify a consent token end-to-end, including policy-version authorization.
///
/// The signature and temporal checks ([`ConsentToken::verify`]) are performed
/// first, then the token's `policy_version` is compared against the
/// `required_policy`. This ordering ensures an attacker cannot forge a token
/// with an acceptable policy version without also holding a valid team signing
/// key.
pub fn enforce_consent(
    token: &ConsentToken,
    public_key: &[u8],
    required_policy: &str,
) -> Result<(), ConsentError> {
    token.verify(public_key)?;
    if token.policy_version != required_policy {
        return Err(ConsentError::InvalidPolicyVersion);
    }
    Ok(())
}

/// Errors returned by consent token verification and enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentError {
    /// The Ed25519 signature on the token did not verify.
    InvalidSignature,
    /// The token's `not_after` window has elapsed.
    Expired,
    /// The token's `not_before` window has not yet started.
    NotYetValid,
    /// The token's `policy_version` does not match the required policy.
    InvalidPolicyVersion,
    /// The token, its signature, or the supplied key material was malformed
    /// (wrong length, invalid point encoding, etc.).
    Malformed,
}

impl std::fmt::Display for ConsentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::InvalidSignature => "invalid Ed25519 signature on consent token",
            Self::Expired => "consent token has expired",
            Self::NotYetValid => "consent token is not yet valid",
            Self::InvalidPolicyVersion => "consent token policy version is not accepted",
            Self::Malformed => "consent token or supplied key material is malformed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ConsentError {}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic 32-byte Ed25519 secret seed (from the ed25519-dalek test
    // vectors). Using a fixed seed keeps the tests hermetic and offline.
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

    fn fresh_token() -> ConsentToken {
        let mut token = ConsentToken::new(
            "agent-001",
            "process-enumeration",
            constants::MAX_CONSENT_TTL_SECS,
            constants::POLICY_VERSION,
            1_000,
            "nonce-deadbeef",
        );
        token.sign(&signing_key());
        token
    }

    #[test]
    fn valid_token_verifies() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let token = fresh_token();
        assert!(token.verify(&vk).is_ok());
    }

    #[test]
    fn is_not_expired_at_creation() {
        let token = fresh_token();
        assert!(!token.is_expired());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let mut tampered = fresh_token();
        tampered.scope = "privilege-escalation".to_string();
        assert_eq!(
            tampered.verify(&vk),
            Err(ConsentError::InvalidSignature)
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let mut token = fresh_token();
        token.signature[0] ^= 0xff;
        assert_eq!(
            token.verify(&vk),
            Err(ConsentError::InvalidSignature)
        );
    }

    #[test]
    fn malformed_short_public_key_rejected() {
        let token = fresh_token();
        assert_eq!(token.verify(&[0u8; 16]), Err(ConsentError::Malformed));
    }

    #[test]
    fn malformed_truncated_signature_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let mut token = fresh_token();
        token.signature.pop();
        assert_eq!(token.verify(&vk), Err(ConsentError::Malformed));
    }

    #[test]
    fn expired_token_is_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let now = Utc::now();
        let mut token = ConsentToken {
            agent_id: "agent-001".to_string(),
            scope: "process-enumeration".to_string(),
            not_before: now - Duration::hours(2),
            not_after: now - Duration::hours(1),
            policy_version: constants::POLICY_VERSION.to_string(),
            max_ops: 10,
            nonce: "expired-nonce".to_string(),
            signature: Vec::new(),
        };
        token.sign(&sk);
        assert_eq!(token.verify(&vk), Err(ConsentError::Expired));
        assert!(token.is_expired());
    }

    #[test]
    fn future_token_is_rejected() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let now = Utc::now();
        let mut token = ConsentToken {
            agent_id: "agent-001".to_string(),
            scope: "process-enumeration".to_string(),
            not_before: now + Duration::hours(1),
            not_after: now + Duration::hours(2),
            policy_version: constants::POLICY_VERSION.to_string(),
            max_ops: 10,
            nonce: "future-nonce".to_string(),
            signature: Vec::new(),
        };
        token.sign(&sk);
        assert_eq!(token.verify(&vk), Err(ConsentError::NotYetValid));
    }

    #[test]
    fn enforce_consent_accepts_matching_policy() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let token = fresh_token();
        assert!(enforce_consent(&token, &vk, constants::POLICY_VERSION).is_ok());
    }

    #[test]
    fn enforce_consent_rejects_policy_mismatch() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let token = fresh_token();
        assert_eq!(
            enforce_consent(&token, &vk, "999"),
            Err(ConsentError::InvalidPolicyVersion)
        );
    }

    #[test]
    fn signing_then_verifying_round_trips_through_json() {
        let sk = signing_key();
        let vk = sk.verifying_key().to_bytes();
        let token = fresh_token();
        let json = serde_json::to_string(&token).expect("token serializes with signature");
        let decoded: ConsentToken =
            serde_json::from_str(&json).expect("token deserializes from signature");
        assert!(decoded.verify(&vk).is_ok());
    }
}