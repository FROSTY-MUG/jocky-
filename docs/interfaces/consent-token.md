# Interface Specification: Consent Token

**Status:** FROZEN  
**Date:** 2026-09-28  
**Source of Truth:** [`agent/common/src/consent.rs`](../../agent/common/src/consent.rs)  
**Consumer Implementations:**  
- Rust agent runtime & FFI: `agent/common`
- Windows C++ agent runtime: `agent/windows-cpp/src/consent.cpp`
- Linux eBPF user-space agent: `agent/linux`
- Central Manager: `manager/go`

---

## 1. Overview

The JOCKY Consent Token is the cryptographic proof of authority required for an endpoint agent to execute an operational capability (e.g. process inspection, memory acquisition, kernel module evaluation, or `.jkm` module execution). Under JOCKY §0.2 safety constraints, no agent may perform introspection or run modules without a cryptographically valid, in-scope, non-expired Consent Token issued by the Central Manager.

---

## 2. Token Format & Data Types

The canonical representation of a Consent Token is encoded in **RFC 8949 CBOR** (`ciborium` in Rust).

### Field Schema (Ordered)

| Field Name | Type | Description | Constraints / Format |
|---|---|---|---|
| `agent_id` | String (UTF-8) | Unique identifier of the designated endpoint agent | Matches host registration ID |
| `scope` | String (UTF-8) | Scoped authorization target | `"host:<id>"` or `"net:<cidr>"` |
| `not_before` | u64 | Activation timestamp (Unix seconds) | Token is invalid before this epoch time |
| `not_after` | u64 | Expiration timestamp (Unix seconds) | Token is invalid after this epoch time |
| `max_ops` | u64 | Maximum number of operational invocations allowed | Decremented or validated by agent |
| `policy_version` | u32 | Version of security policy governing this grant | Monotonically increasing |
| `signature` | bytes[64] | Ed25519 signature over canonical payload | Raw 64-byte Ed25519 signature |

---

## 3. Cryptographic Verification & Signing

### 3.1 Signed Payload Construction
The signature is generated strictly over the canonical CBOR serialization of the fields **excluding** the `signature` field itself, in exact declared order:

```rust
// Canonical payload structure for signing and verification
(
    agent_id: String,
    scope: String,
    not_before: u64,
    not_after: u64,
    max_ops: u64,
    policy_version: u32,
)
```

The payload bytes are passed directly into the Ed25519 signature algorithm without intermediate hashing (as Ed25519 internally performs SHA-512 over the message).

### 3.2 Signature Algorithm
- **Algorithm:** Ed25519 (PureEdDSA with Curve25519)
- **Library Reference:** `ed25519-dalek 2.x` / RFC 8032

### 3.3 Key Representations
- **Public Key in Environment / Wire:** Base64 of the raw 32-byte Ed25519 verifying key (`JOCKY_MANAGER_PUBKEY`).
- **Private Key Storage:** PKCS#8 v1 (`BEGIN PRIVATE KEY` format emitted by `jockyc keygen` or `jocky-token-issue`).
- **Token Transmission on Wire / Env:** Base64 of the complete CBOR token bytes (`JOCKY_CONSENT_TOKEN`).

---

## 4. Scope Format & Validation Rules

1. **Host Scope:**  
   Format: `host:<id>` (e.g. `host:LAB-WIN-01`, `host:prod-srv-04`).  
   The agent MUST verify that the token's scope either exactly matches its local hostname or matches the wildcard `host:*`.
2. **Network Scope:**  
   Format: `net:<cidr>` (e.g. `net:192.168.1.0/24`, `net:10.0.0.0/8`).  
   The agent MUST verify that its active network adapter IP falls within the authorized CIDR.
3. **Temporal Validity:**  
   The host clock $T_{now}$ must satisfy:
   $$T_{not\_before} \le T_{now} \le T_{not\_after}$$
   Tokens where $T_{now} < T_{not\_before}$ or $T_{now} > T_{not\_after}$ MUST be rejected immediately with audit log entry.
