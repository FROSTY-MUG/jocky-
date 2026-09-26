//! JOCKY Binary Module (.jkm) Container Implementation
//!
//! Purpose: Encapsulates compiled machine code, CBOR metadata manifest, and Ed25519
//!          attestation signature into a single, verifiable, polymorphic container format.
//! Inputs: Compiled binary object bytes, CBOR manifest, optional Ed25519 signing key.
//! Outputs: Serialized .jkm binary payload, parsed container structures, signature verifier.
//! Exit Codes: N/A (Library module; returns Result<T, anyhow::Error>).
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.
//!
//! Format Specification (Little-Endian):
//! +-------------------------------------------------------------+
//! | Header (64 bytes):                                          |
//! |   0..4   : Magic b"JKM\x01"                                  |
//! |   4..6   : Container Version (u16 = 1)                       |
//! |   6..8   : Target Architecture ID (u16)                      |
//! |   8..16  : Deterministic Build Seed (u64)                   |
//! |  16..20  : Code Section Offset (u32)                        |
//! |  20..24  : Code Section Length (u32)                        |
//! |  24..28  : Manifest Offset (u32)                            |
//! |  28..32  : Manifest Length (u32)                            |
//! |  32..36  : Signature Offset (u32)                           |
//! |  36..40  : Signature Length (u32, 0 or 64)                  |
//! |  40..64  : Reserved Padding (24 bytes, 0x00)                |
//! +-------------------------------------------------------------+
//! | Code Section (Raw ELF/COFF/Mach-O bytes)                     |
//! +-------------------------------------------------------------+
//! | Manifest Section (CBOR-encoded metadata)                     |
//! +-------------------------------------------------------------+
//! | Signature Section (64-byte Ed25519 signature over H+C+M)    |
//! +-------------------------------------------------------------+
//!
//! Trap T3: Signature Scope:
//! The signature MUST cover exactly `header bytes + code bytes + CBOR manifest bytes`,
//! in that order. The 64-byte signature itself is appended at `sig_offset`.

use crate::jkm::manifest::JkmManifest;
use crate::jkm::sign::{self, ED25519_SIG_LEN};
use anyhow::{anyhow, ensure, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const JKM_MAGIC: &[u8; 4] = b"JKM\x01";
pub const JKM_VERSION: u16 = 1;
pub const JKM_HEADER_SIZE: usize = 64;

pub const TARGET_UNKNOWN: u16 = 0;
pub const TARGET_X86_64_LINUX_GNU: u16 = 1;
pub const TARGET_X86_64_WINDOWS_MSVC: u16 = 2;
pub const TARGET_X86_64_APPLE_DARWIN: u16 = 3;
pub const TARGET_AARCH64_LINUX_GNU: u16 = 4;
pub const TARGET_AARCH64_APPLE_DARWIN: u16 = 5;

pub fn target_triple_to_id(triple: &str) -> u16 {
    if triple.contains("linux") && triple.contains("x86_64") {
        TARGET_X86_64_LINUX_GNU
    } else if triple.contains("windows") && (triple.contains("x86_64") || triple.contains("msvc")) {
        TARGET_X86_64_WINDOWS_MSVC
    } else if triple.contains("darwin") && triple.contains("x86_64") {
        TARGET_X86_64_APPLE_DARWIN
    } else if triple.contains("linux") && triple.contains("aarch64") {
        TARGET_AARCH64_LINUX_GNU
    } else if triple.contains("darwin") && triple.contains("aarch64") {
        TARGET_AARCH64_APPLE_DARWIN
    } else {
        TARGET_UNKNOWN
    }
}

pub fn target_id_to_triple(id: u16) -> &'static str {
    match id {
        TARGET_X86_64_LINUX_GNU => "x86_64-unknown-linux-gnu",
        TARGET_X86_64_WINDOWS_MSVC => "x86_64-pc-windows-msvc",
        TARGET_X86_64_APPLE_DARWIN => "x86_64-apple-darwin",
        TARGET_AARCH64_LINUX_GNU => "aarch64-unknown-linux-gnu",
        TARGET_AARCH64_APPLE_DARWIN => "aarch64-apple-darwin",
        _ => "unknown",
    }
}

/// Parsed header of a .jkm container
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JkmHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub target_id: u16,
    pub seed: u64,
    pub code_offset: u32,
    pub code_len: u32,
    pub manifest_offset: u32,
    pub manifest_len: u32,
    pub sig_offset: u32,
    pub sig_len: u32,
}

impl JkmHeader {
    pub fn to_bytes(&self) -> [u8; JKM_HEADER_SIZE] {
        let mut buf = [0u8; JKM_HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.target_id.to_le_bytes());
        buf[8..16].copy_from_slice(&self.seed.to_le_bytes());
        buf[16..20].copy_from_slice(&self.code_offset.to_le_bytes());
        buf[20..24].copy_from_slice(&self.code_len.to_le_bytes());
        buf[24..28].copy_from_slice(&self.manifest_offset.to_le_bytes());
        buf[28..32].copy_from_slice(&self.manifest_len.to_le_bytes());
        buf[32..36].copy_from_slice(&self.sig_offset.to_le_bytes());
        buf[36..40].copy_from_slice(&self.sig_len.to_le_bytes());
        // Remaining bytes 40..64 are 0x00 padding
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= JKM_HEADER_SIZE,
            "Buffer too short for JKM header: expected at least {} bytes, got {}",
            JKM_HEADER_SIZE,
            bytes.len()
        );
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        ensure!(
            &magic == JKM_MAGIC,
            "Invalid JKM magic: expected {:?}, got {:?}",
            JKM_MAGIC,
            magic
        );

        let version = u16::from_le_bytes(bytes[4..6].try_into()?);
        let target_id = u16::from_le_bytes(bytes[6..8].try_into()?);
        let seed = u64::from_le_bytes(bytes[8..16].try_into()?);
        let code_offset = u32::from_le_bytes(bytes[16..20].try_into()?);
        let code_len = u32::from_le_bytes(bytes[20..24].try_into()?);
        let manifest_offset = u32::from_le_bytes(bytes[24..28].try_into()?);
        let manifest_len = u32::from_le_bytes(bytes[28..32].try_into()?);
        let sig_offset = u32::from_le_bytes(bytes[32..36].try_into()?);
        let sig_len = u32::from_le_bytes(bytes[36..40].try_into()?);

        Ok(Self {
            magic,
            version,
            target_id,
            seed,
            code_offset,
            code_len,
            manifest_offset,
            manifest_len,
            sig_offset,
            sig_len,
        })
    }
}

/// JOCKY Binary Module container
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JkmContainer {
    pub header: JkmHeader,
    pub code: Vec<u8>,
    pub manifest_cbor: Vec<u8>,
    pub signature: Option<[u8; ED25519_SIG_LEN]>,
}

impl JkmContainer {
    /// Construct a new unsigned JkmContainer from code and structured manifest
    pub fn new(
        target_triple: &str,
        seed: u64,
        code: Vec<u8>,
        manifest: &JkmManifest,
    ) -> Result<Self> {
        let manifest_cbor = manifest.to_cbor()?;
        let target_id = target_triple_to_id(target_triple);

        let code_offset = JKM_HEADER_SIZE as u32;
        let code_len = code.len() as u32;
        let manifest_offset = code_offset + code_len;
        let manifest_len = manifest_cbor.len() as u32;
        let sig_offset = manifest_offset + manifest_len;
        let sig_len = 0; // Unsigned initially

        let header = JkmHeader {
            magic: *JKM_MAGIC,
            version: JKM_VERSION,
            target_id,
            seed,
            code_offset,
            code_len,
            manifest_offset,
            manifest_len,
            sig_offset,
            sig_len,
        };

        Ok(Self {
            header,
            code,
            manifest_cbor,
            signature: None,
        })
    }

    /// Sign the container using the provided Ed25519 signing key.
    /// In accordance with Trap T3, the signature scope is:
    /// header bytes (with sig_len=64) + code bytes + manifest bytes.
    pub fn sign(&mut self, key: &SigningKey) {
        self.header.sig_len = ED25519_SIG_LEN as u32;
        let mut payload_to_sign = Vec::new();
        payload_to_sign.extend_from_slice(&self.header.to_bytes());
        payload_to_sign.extend_from_slice(&self.code);
        payload_to_sign.extend_from_slice(&self.manifest_cbor);

        let sig = sign::sign_container(key, &payload_to_sign);
        self.signature = Some(sig);
    }

    /// Verify the container's integrity and signature against the provided public key
    pub fn verify(&self, pubkey: &VerifyingKey) -> Result<()> {
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("Container is not signed"))?;

        ensure!(
            self.header.sig_len == ED25519_SIG_LEN as u32,
            "Invalid signature length recorded in header: {}",
            self.header.sig_len
        );

        let mut payload_signed = Vec::new();
        payload_signed.extend_from_slice(&self.header.to_bytes());
        payload_signed.extend_from_slice(&self.code);
        payload_signed.extend_from_slice(&self.manifest_cbor);

        sign::verify_container(pubkey, &payload_signed, sig)
    }

    /// Parse manifest struct from container's embedded CBOR section
    pub fn parse_manifest(&self) -> Result<JkmManifest> {
        JkmManifest::from_cbor(&self.manifest_cbor)
    }

    /// Serialize the full container into a binary vector
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            JKM_HEADER_SIZE
                + self.code.len()
                + self.manifest_cbor.len()
                + if self.signature.is_some() {
                    ED25519_SIG_LEN
                } else {
                    0
                },
        );
        out.extend_from_slice(&self.header.to_bytes());
        out.extend_from_slice(&self.code);
        out.extend_from_slice(&self.manifest_cbor);
        if let Some(sig) = &self.signature {
            out.extend_from_slice(sig);
        }
        out
    }

    /// Parse a .jkm container from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let header = JkmHeader::from_bytes(bytes)?;

        let code_start = header.code_offset as usize;
        let code_end = code_start + header.code_len as usize;
        ensure!(
            bytes.len() >= code_end,
            "Buffer underflow reading code section: file size {}, section ends at {}",
            bytes.len(),
            code_end
        );
        let code = bytes[code_start..code_end].to_vec();

        let manifest_start = header.manifest_offset as usize;
        let manifest_end = manifest_start + header.manifest_len as usize;
        ensure!(
            bytes.len() >= manifest_end,
            "Buffer underflow reading manifest section: file size {}, section ends at {}",
            bytes.len(),
            manifest_end
        );
        let manifest_cbor = bytes[manifest_start..manifest_end].to_vec();

        let signature = if header.sig_len == ED25519_SIG_LEN as u32 {
            let sig_start = header.sig_offset as usize;
            let sig_end = sig_start + ED25519_SIG_LEN;
            ensure!(
                bytes.len() >= sig_end,
                "Buffer underflow reading signature section: file size {}, section ends at {}",
                bytes.len(),
                sig_end
            );
            let mut sig = [0u8; ED25519_SIG_LEN];
            sig.copy_from_slice(&bytes[sig_start..sig_end]);
            Some(sig)
        } else {
            None
        };

        Ok(Self {
            header,
            code,
            manifest_cbor,
            signature,
        })
    }
}
