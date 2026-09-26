# 04 — Binary Diversification, .jkm Container, and Polymorphic CI/CD

**JOCKY v0.1 Specification & Implementation Guide**  
Problem Statement: **SIH26148 (NTRO)**  
Blueprint Section: **§0.4 Binary Diversification & Polymorphism; §2.3 Binary Packaging & Attestation; §4 CI/CD Pipeline**

---

## 1. Overview & Defensive Framing

In degraded or adversary-compromised operating environments, incident response tooling often encounters brittle static blocking rules (e.g., rigid SHA-256 blacklists or simplistic byte-signature matches) designed to prevent forensic investigation. JOCKY addresses this not through offensive evasion, but through **compiler-enforced polymorphism and cryptographic attestation**.

Every build of a JOCKY forensic script generates unique binary artifacts that share identical behavioral semantics while possessing distinct binary layouts, cryptographic digests, instruction sequences, and symbol names. Every binary is encapsulated in a tamper-evident **`.jkm` (JOCKY Module) container** signed with Ed25519, backed by an embedded CBOR manifest and an SPDX 2.3 Software Bill of Materials (SBOM).

```
   JOCKY Source (.jky)
          │
          ▼
   [ Lexer & Parser ] ──▶ [ Denylist Verification ]
          │
          ▼
    [ Typechecker ]
          │
          ▼
  [ HirProgram AST ]
          │
          ├─────────────────────────────────────────────────┐
          │  4 Diversification Passes (Deterministic Seed)  │
          │   1. Seeded Basic-Block Reordering               │
          │   2. Equivalent Instruction Substitution        │
          │   3. Deterministic Symbol Mangling (ChaCha20)   │
          │   4. BLAKE3 Per-Build String XOR Encryption     │
          └─────────────────────────────────────────────────┘
          │
          ▼
   [ LLVM 17 Codegen ] (inkwell)
     ├── x86_64-unknown-linux-gnu (ELF64)
     └── x86_64-pc-windows-msvc   (COFF-x86-64)
          │
          ▼
     [ Raw Code Object Bytes ]
          │
          ▼
   [ .jkm Container Assembler ]
     ├── Header (64-byte binary header, little-endian)
     ├── Code Section (Raw ELF / COFF bytes)
     ├── Manifest (RFC 8949 CBOR: hashes, seed, symbol map)
     └── Signature (64-byte Ed25519 over Header + Code + Manifest)
          │
          ▼
   Signed .jkm Module ──▶ Verified via `jocky-verify`
```

---

## 2. Four Diversification Passes

All diversification passes are deterministic functions of a 64-bit integer seed (`--seed <u64>`), powered by a CSPRNG (`rand_chacha::ChaCha20Rng`). Given the same source code and the same seed, `jockyc` emits identical binaries; across different seeds, it emits binaries with zero byte collisions.

### 2.1 Seeded Basic-Block Reordering
- In control-flow blocks containing non-dependent statement lists or commutative expressions, the order of basic blocks and independent statements is permuted using the seeded ChaCha20 PRNG.
- Preserves control-flow graph (CFG) dominator trees and data dependencies while altering branch target offsets and basic block layout.

### 2.2 Equivalent Instruction Substitution
- Arithmetic and logical operations are substituted with algebraic and bitwise equivalents:
  - `a + b` $\Longleftrightarrow$ `a - (-b)` or `(a ^ b) + ((a & b) << 1)`
  - `a ^ b` $\Longleftrightarrow$ `(a | b) & ~(a & b)`
  - `a * 2` $\Longleftrightarrow$ `a << 1`
  - Register zeroing via `xor r, r` vs `sub r, r` vs immediate zero assignment.
- Applied during the MIR/HIR optimization stage prior to LLVM target lowering.

### 2.3 Function Name Mangling Keyed by Build Seed
- All non-exported and non-entrypoint symbols (excluding `main` and runtime externs) are mangled into deterministic 8-character hex identifiers:
  $$\text{mangled\_name} = \text{format!}(\text{"}\{\}\_\{\:08x\}\text{"}, \text{orig\_name}, \text{rng.gen::<u32>()})$$
- The compiler records the bijective mapping between original and mangled symbols in the embedded CBOR manifest, allowing DFIR analysts to reconstruct trace logs without exposing predictable symbol names in the binary.

### 2.4 String Literal Encryption
- String literals embedded in binary modules are encrypted using a 32-byte symmetric keystream derived from the build seed via BLAKE3:
  $$\text{Key} = \text{BLAKE3}(\text{seed\_le\_bytes} \mathbin{\Vert} \text{b"jocky-string-key-v1"})[0..32]$$
- Encrypted literals are transformed into `__ENC__<hex>` representations in the IR and decrypted at module load time by the authorized agent runtime.

---

## 3. The `.jkm` Container Binary Specification

A `.jkm` binary module is structured as follows (all multibyte header integers are Little-Endian):

### 3.1 Header Layout (Fixed 64 Bytes)
| Offset | Field | Type | Description |
|---|---|---|---|
| `0..4` | Magic | `[u8; 4]` | ASCII `b"JKM\x01"` (0x4A, 0x4B, 0x4D, 0x01) |
| `4..6` | Version | `u16` | Container version (`1`) |
| `6..8` | Target ID | `u16` | Architecture (`1`=Linux x86_64 ELF, `2`=Windows x86_64 COFF) |
| `8..16` | Seed | `u64` | Deterministic build seed |
| `16..20` | Code Offset | `u32` | Byte offset of code section (usually `64`) |
| `20..24` | Code Length | `u32` | Length of raw code section in bytes |
| `24..28` | Manifest Offset | `u32` | Byte offset of CBOR manifest section |
| `28..32` | Manifest Length | `u32` | Length of CBOR manifest in bytes |
| `32..36` | Signature Offset| `u32` | Byte offset of Ed25519 signature |
| `36..40` | Signature Length| `u32` | Length of signature (`64` if signed, `0` if unsigned) |
| `40..64` | Reserved | `[u8; 24]` | Zero-padded padding for future extensions |

### 3.2 Code Section
Contains raw, linkable object bytes:
- For Linux targets: ELF64 relocatable object file with SysV ABI.
- For Windows targets: COFF-x86-64 object file with `IMAGE_FILE_MACHINE_AMD64` (0x8664) and MSVC x64 ABI.

### 3.3 Manifest Section (CBOR RFC 8949)
Serialized CBOR structure with the following schema:
```json
{
  "version": 1,
  "module_name": "network_trace",
  "target_triple": "x86_64-pc-windows-msvc",
  "build_seed": 1001,
  "timestamp": 1774656000,
  "compiler_version": "0.1.0",
  "code_hash_blake3": "4a7f...",
  "code_hash_sha256": "9b12...",
  "string_key_id": "c0ffee12...",
  "symbol_map": {
    "parse_header": "parse_header_8f2a1b9c",
    "inspect_flow": "inspect_flow_3d4e5f60"
  }
}
```

### 3.4 Signature Section (Ed25519)
- **Signature Scope (Trap T3)**: The Ed25519 signature is strictly computed over:
  $$\text{Payload} = \text{Header Bytes (with sig\_len=64)} \mathbin{\Vert} \text{Code Bytes} \mathbin{\Vert} \text{CBOR Manifest Bytes}$$
- Tamper Detection: Any single-bit alteration in the header, code, or manifest will cause signature verification to fail.

---

## 4. Attestation Verification CLI (`jocky-verify`)

The standalone `jocky-verify` binary verifies `.jkm` module integrity:
```bash
jocky-verify dist/signed.jkm --pubkey certs/ed25519.pub
```
- Exit 0: Module is authenticated, signature is valid, and manifest is intact.
- Exit 1: Signature invalid, tampered binary, or mismatched public key.

---

## 5. Multi-Language Build Runner & CI Targets

Orchestration across Windows, Linux, and macOS is driven by the unified `justfile` and `Makefile`:
- `just diversify`: Emits polymorphic variants across seeds.
- `just sign`: Signs modules using Ed25519 keypairs.
- `just verify`: Audits container integrity.
- `just sbom`: Generates SPDX 2.3 JSON documents.
- `just hash`: Emits dual BLAKE3 and SHA-256 digests.