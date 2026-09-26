//! JOCKY Ed25519 Signing & Tamper Verification Unit Tests
//!
//! Purpose: Test key generation, signing, positive verification, and negative tamper detection
//!          (byte flips, mismatched keys, corrupt signatures) on .jkm containers.
//! Inputs: Generated Ed25519 keypairs and signed JkmContainer instances.
//! Outputs: Assertions verifying cryptographic integrity and tamper rejection.
//! Blueprint Section: §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.

use jockyc::jkm::container::JkmContainer;
use jockyc::jkm::manifest::JkmManifest;
use jockyc::jkm::sign::{generate_keypair, load_private_key, load_public_key, save_private_key, save_public_key};
use std::collections::BTreeMap;

#[test]
fn test_ed25519_key_save_load() {
    let temp_dir = std::env::temp_dir();
    let priv_path = temp_dir.join("jocky_test_priv.key");
    let pub_path = temp_dir.join("jocky_test_pub.key");

    let (sk, vk) = generate_keypair();
    save_private_key(&sk, &priv_path).expect("Failed to save private key");
    save_public_key(&vk, &pub_path).expect("Failed to save public key");

    let loaded_sk = load_private_key(&priv_path).expect("Failed to load private key");
    let loaded_vk = load_public_key(&pub_path).expect("Failed to load public key");

    assert_eq!(sk.to_bytes(), loaded_sk.to_bytes());
    assert_eq!(vk.to_bytes(), loaded_vk.to_bytes());

    let _ = std::fs::remove_file(priv_path);
    let _ = std::fs::remove_file(pub_path);
}

#[test]
fn test_sign_and_verify_happy_path() {
    let (sk, vk) = generate_keypair();
    let fake_code = vec![0x48, 0x31, 0xc0, 0xc3]; // XOR RAX, RAX; RET
    let manifest = JkmManifest::new(
        "auth_test",
        "x86_64-unknown-linux-gnu",
        1234,
        &fake_code,
        BTreeMap::new(),
    );

    let mut container = JkmContainer::new(
        "x86_64-unknown-linux-gnu",
        1234,
        fake_code,
        &manifest,
    )
    .expect("Failed to construct container");

    container.sign(&sk);
    assert!(container.signature.is_some());

    // Serialize and deserialize
    let raw = container.to_bytes();
    let deserialized = JkmContainer::from_bytes(&raw).expect("Failed to parse container");

    // Verify with correct public key
    assert!(deserialized.verify(&vk).is_ok());
}

#[test]
fn test_tamper_detection_code_byte_flip() {
    let (sk, vk) = generate_keypair();
    let fake_code = vec![0x90, 0x90, 0x90, 0xc3];
    let manifest = JkmManifest::new(
        "tamper_test",
        "x86_64-unknown-linux-gnu",
        999,
        &fake_code,
        BTreeMap::new(),
    );

    let mut container = JkmContainer::new(
        "x86_64-unknown-linux-gnu",
        999,
        fake_code,
        &manifest,
    )
    .expect("Failed to construct container");

    container.sign(&sk);
    let mut raw = container.to_bytes();

    // Tamper: flip a byte in code section (offset 64 is the first byte of code)
    raw[64] ^= 0xFF;

    let tampered_container = JkmContainer::from_bytes(&raw).expect("Parsing should succeed");
    let verify_res = tampered_container.verify(&vk);
    assert!(verify_res.is_err(), "Verification MUST fail on tampered code section");
}

#[test]
fn test_tamper_detection_wrong_public_key() {
    let (sk1, _vk1) = generate_keypair();
    let (_sk2, vk2) = generate_keypair();

    let fake_code = vec![0xc3];
    let manifest = JkmManifest::new("m", "x86_64-unknown-linux-gnu", 1, &fake_code, BTreeMap::new());

    let mut container = JkmContainer::new("x86_64-unknown-linux-gnu", 1, fake_code, &manifest).unwrap();
    container.sign(&sk1);

    let verify_res = container.verify(&vk2);
    assert!(verify_res.is_err(), "Verification MUST fail with wrong public key");
}
