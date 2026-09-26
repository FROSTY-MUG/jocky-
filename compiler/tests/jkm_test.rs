//! JOCKY .jkm Container Unit Tests
//!
//! Purpose: Test binary serialization, parsing, header verification, offset validation,
//!          and CBOR manifest integrity for the .jkm container format.
//! Inputs: Synthetic test code buffers and manifest structures.
//! Outputs: Assertions verifying byte layout, roundtrip deserialization, and error handling.
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use jockyc::jkm::container::{
    target_triple_to_id, JkmContainer, JkmHeader, JKM_HEADER_SIZE, JKM_MAGIC,
    TARGET_X86_64_LINUX_GNU, TARGET_X86_64_WINDOWS_MSVC,
};
use jockyc::jkm::manifest::JkmManifest;
use std::collections::BTreeMap;

#[test]
fn test_jkm_header_roundtrip() {
    let header = JkmHeader {
        magic: *JKM_MAGIC,
        version: 1,
        target_id: TARGET_X86_64_LINUX_GNU,
        seed: 0x1337_CAFE_DEAD_BEEF,
        code_offset: 64,
        code_len: 256,
        manifest_offset: 320,
        manifest_len: 128,
        sig_offset: 448,
        sig_len: 64,
    };

    let bytes = header.to_bytes();
    assert_eq!(bytes.len(), JKM_HEADER_SIZE);
    assert_eq!(&bytes[0..4], b"JKM\x01");

    let parsed = JkmHeader::from_bytes(&bytes).expect("Failed to parse JkmHeader");
    assert_eq!(parsed, header);
}

#[test]
fn test_jkm_container_roundtrip() {
    let fake_code = vec![0x90, 0x90, 0x31, 0xc0, 0xc3]; // NOP NOP XOR EAX, EAX; RET
    let mut symbol_map = BTreeMap::new();
    symbol_map.insert("main".to_string(), "main_a1b2c3d4".to_string());

    let manifest = JkmManifest::new(
        "test_mod",
        "x86_64-unknown-linux-gnu",
        42,
        &fake_code,
        symbol_map.clone(),
    );

    let container = JkmContainer::new(
        "x86_64-unknown-linux-gnu",
        42,
        fake_code.clone(),
        &manifest,
    )
    .expect("Failed to create container");

    let serialized = container.to_bytes();
    assert!(serialized.len() > JKM_HEADER_SIZE);
    assert_eq!(&serialized[0..4], b"JKM\x01");

    let parsed = JkmContainer::from_bytes(&serialized).expect("Failed to parse container");
    assert_eq!(parsed.header.target_id, TARGET_X86_64_LINUX_GNU);
    assert_eq!(parsed.header.seed, 42);
    assert_eq!(parsed.code, fake_code);

    let parsed_manifest = parsed.parse_manifest().expect("Failed to parse CBOR manifest");
    assert_eq!(parsed_manifest.module_name, "test_mod");
    assert_eq!(parsed_manifest.target_triple, "x86_64-unknown-linux-gnu");
    assert_eq!(parsed_manifest.build_seed, 42);
    assert_eq!(parsed_manifest.symbol_map.get("main").unwrap(), "main_a1b2c3d4");
}

#[test]
fn test_target_triple_mappings() {
    assert_eq!(
        target_triple_to_id("x86_64-unknown-linux-gnu"),
        TARGET_X86_64_LINUX_GNU
    );
    assert_eq!(
        target_triple_to_id("x86_64-pc-windows-msvc"),
        TARGET_X86_64_WINDOWS_MSVC
    );
}

#[test]
fn test_invalid_magic_rejected() {
    let mut bytes = vec![0u8; 128];
    bytes[0..4].copy_from_slice(b"BAD!");
    let result = JkmHeader::from_bytes(&bytes);
    assert!(result.is_err());
}
