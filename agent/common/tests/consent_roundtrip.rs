use ed25519_dalek::{SigningKey, VerifyingKey};
use jocky_common::consent::{issue, verify};

#[test]
fn roundtrip_happy_path() {
    // Deterministic seed — 32 bytes, never zero, never all-ones.
    let seed = [0x42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let token = issue(
        &signing_key,
        "test-agent-01",
        "host:LAB-WIN-01",
        3600,
        1000,
        1,
    ).expect("issue should succeed");

    verify(&token, &verifying_key).expect("verify should succeed");
}

#[test]
fn roundtrip_tamper_rejected() {
    let seed = [0x42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let mut token = issue(
        &signing_key,
        "test-agent-01",
        "host:LAB-WIN-01",
        3600,
        1000,
        1,
    ).expect("issue should succeed");

    // Tamper the payload: modify the scope
    token.scope = "host:TAMPERED-01".to_string();

    let result = verify(&token, &verifying_key);
    assert!(result.is_err(), "tampered token must fail verification");
}

#[test]
fn roundtrip_wrong_key_rejected() {
    let seed_a = [0x42u8; 32];
    let seed_b = [0x43u8; 32];
    let signing_key = SigningKey::from_bytes(&seed_a);
    let wrong_verifying_key = SigningKey::from_bytes(&seed_b).verifying_key();

    let token = issue(
        &signing_key,
        "test-agent-01",
        "host:LAB-WIN-01",
        3600,
        1000,
        1,
    ).expect("issue should succeed");

    let result = verify(&token, &wrong_verifying_key);
    assert!(result.is_err(), "wrong pubkey must fail verification");
}
