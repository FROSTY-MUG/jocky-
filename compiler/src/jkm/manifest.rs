//! JOCKY Module Manifest (.jkm CBOR metadata)
//!
//! Purpose: Define the structured manifest embedded inside .jkm binary containers,
//!          containing provenance, build seed, target triple, timestamps, cryptographic
//!          hashes, and symbol mappings encoded using standard CBOR (RFC 8949).
//! Inputs: Module identity, compilation target, deterministic build seed, hashes.
//! Outputs: Canonical CBOR byte serialization and deserialization.
//! Exit Codes: N/A (Library module; returns Result<T, anyhow::Error>).
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Manifest version for .jkm specification
pub const JKM_MANIFEST_VERSION: u32 = 1;

/// CBOR-encoded manifest embedded within a .jkm container
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JkmManifest {
    /// Manifest schema version
    pub version: u32,
    /// Module identifier (e.g. "min", "memory", "agent_win")
    pub module_name: String,
    /// Compilation target triple (e.g. "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc")
    pub target_triple: String,
    /// Deterministic PRNG seed used for diversification passes
    pub build_seed: u64,
    /// UTC timestamp of compilation in seconds since Unix epoch
    pub timestamp: u64,
    /// Compiler version string
    pub compiler_version: String,
    /// BLAKE3 digest of the raw compiled machine code section (hex)
    pub code_hash_blake3: String,
    /// SHA-256 digest of the raw compiled machine code section (hex)
    pub code_hash_sha256: String,
    /// String encryption key derivation identifier / tag
    pub string_key_id: String,
    /// Symbol mapping from original identifier to seed-mangled identifier
    pub symbol_map: BTreeMap<String, String>,
}

impl JkmManifest {
    /// Create a new manifest instance with default version and metadata
    pub fn new(
        module_name: impl Into<String>,
        target_triple: impl Into<String>,
        build_seed: u64,
        code_bytes: &[u8],
        symbol_map: BTreeMap<String, String>,
    ) -> Self {
        let code_hash_blake3 = blake3::hash(code_bytes).to_hex().to_string();
        
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(code_bytes);
        let code_hash_sha256 = hex::encode(hasher.finalize());

        let mut key_hasher = blake3::Hasher::new();
        key_hasher.update(&build_seed.to_le_bytes());
        key_hasher.update(b"jocky-string-key-v1");
        let string_key_id = hex::encode(&key_hasher.finalize().as_bytes()[0..8]);

        Self {
            version: JKM_MANIFEST_VERSION,
            module_name: module_name.into(),
            target_triple: target_triple.into(),
            build_seed,
            timestamp: chrono::Utc::now().timestamp() as u64,
            compiler_version: env!("CARGO_PKG_VERSION").to_string(),
            code_hash_blake3,
            code_hash_sha256,
            string_key_id,
            symbol_map,
        }
    }

    /// Serialize manifest into canonical CBOR format
    pub fn to_cbor(&self) -> Result<Vec<u8>, anyhow::Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| anyhow::anyhow!("CBOR serialization error: {}", e))?;
        Ok(buf)
    }

    /// Deserialize manifest from CBOR bytes
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, anyhow::Error> {
        ciborium::from_reader(bytes)
            .map_err(|e| anyhow::anyhow!("CBOR deserialization error: {}", e))
    }

    /// Serialize to pretty JSON (convenience for SBOM and inspection)
    pub fn to_json(&self) -> Result<String, anyhow::Error> {
        serde_json::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("JSON serialization error: {}", e))
    }
}
