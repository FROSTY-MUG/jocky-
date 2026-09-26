//! JOCKY Module (.jkm) Container Subsystem
//!
//! Purpose: Top-level module declaring container formatting, CBOR manifest serialization,
//!          and Ed25519 digital signature validation for polymorphic JOCKY modules.
//! Inputs: Compiled binary object bytes, compilation metadata, diversification seeds.
//! Outputs: Packed, attested, and signed .jkm binary containers.
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

pub mod container;
pub mod manifest;
pub mod sign;

pub use container::JkmContainer;
pub use manifest::JkmManifest;
pub use sign::{generate_keypair, sign_container, verify_container};
