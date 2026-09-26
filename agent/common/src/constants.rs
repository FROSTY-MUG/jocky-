//! Platform-wide constants shared across the JOCKY agent, compiler, and
//! manager crates.

/// Consent / manifest policy version.
///
/// This string is embedded in consent tokens and signed manifests. Bumping it
/// invalidates all outstanding tokens and requires agents to re-attest under
/// the new policy, so only do so on a backwards-incompatible schema change.
pub const POLICY_VERSION: &str = "1";

/// Maximum lifetime, in seconds, of an issued consent token (15 minutes).
///
/// Stations on a live endpoint may renew consent up to this limit before
/// requiring a fresh signed token from the manager.
pub const MAX_CONSENT_TTL_SECS: i64 = 900;

/// Minimum acceptable lifetime, in seconds, of a consent token. Values below
/// this are clamped up so tokens with absurd negative or tiny TTLs cannot be
/// minted.
pub const MIN_CONSENT_TTL_SECS: i64 = 1;

/// Default ceiling on the number of operations a single consent token permits
/// before the agent must renew consent with the manager.
pub const DEFAULT_MAX_OPS: u64 = 10_000;

/// Length, in bytes, of an Ed25519 public key.
pub const ED25519_KEY_LEN: usize = 32;

/// Length, in bytes, of an Ed25519 signature (R-component || s-component).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Human-readable identifier for the signature algorithm used to sign
/// consent tokens and manifests.
pub const SIGNING_ALGORITHM: &str = "Ed25519";

/// Wire protocol version exchanged during agent <-> manager registration and
/// heartbeats.
pub const PROTOCOL_VERSION: &str = "jocky/proto-1";