# Architecture

## Overview

JOCKY is structured into six primary components:
1. **Compiler Frontend**: Parser, AST, semantic typechecker, and compile-time capability denylist for the JOCKY DFIR DSL. *(Implemented)*
2. **LLVM Codegen Backend**: LLVM 17 lowering engine emitting SysV x86_64 ELF objects and Windows MSVC COFF objects. *(Implemented)*
3. **Signed `.jkm` Module Container**: Binary container format bundling machine code, CBOR metadata, and Ed25519 digital signatures. *(Implemented)*
4. **Consent-Bound Agent Runtime**: Multi-platform endpoint agents enforcing signed consent tokens and hardware sandboxes. *(Scaffolded)*
5. **Central Manager Plane**: Coordination plane distributing attested policies, registering module hashes, and verifying mTLS. *(Scaffolded)*
6. **DFIR Dashboard**: Incident investigation UI for timeline inspection, telemetry analysis, and token generation. *(Scaffolded)*

---

## Data Flow

### Build Flow (Implemented & Verified)
```text
.jky source
  → lexer (logos)
  → parser (recursive descent + Pratt precedence)
  → AST
  → denylist pass (E0401 on forbidden primitive)
  → typechecker (bidirectional type inference, E0301)
  → HIR
  → diversification passes (seeded BB reorder, substitution, mangling, string enc)
  → LLVM IR (inkwell)
  → object file (.o for ELF64, .obj for COFF)
  → .jkm container (magic + header + code + CBOR manifest + Ed25519 signature)
```

### Runtime Flow (Deferred to Steps 3 & 4)
```text
Manager issues job with consent token
  → agent fetches job over mTLS
  → agent verifies token + module signature + transparency log
  → agent loads .jkm module in-process
  → module runs in sandbox
  → results uploaded to S3/R2 via presigned URL
  → manager ingests into Postgres
  → dashboard renders findings
```

---

## Trust Boundaries

- **Analyst ↔ Edge**: Protected by Cloudflare Access + WireGuard / Tailscale VPN.
- **Edge ↔ Manager**: Authenticated over mTLS with role-based access control.
- **Agent ↔ Manager**: Bidirectional mTLS using unique per-agent X.509 client certificates.
- **Agent ↔ Its Own Modules**: Requires valid Ed25519 signature over `header + code + manifest` plus a valid cryptographically unexpired consent token.
- **Agent ↔ Target System**: Enforced scope fence limiting collection to pre-authorized PIDs, filesystems, and memory ranges.

---

## Safety Model

- **Capability Denylist**: 23 offensive primitives rejected at compile time by `compiler/src/passes/denylist.rs` (Diagnostic code `E0401`).
- **Consent Tokens**: Cryptographically signed by an incident commander, strictly scope-bound (authorized target machine ID, allowed actions, expiration timestamp).
- **Signed Manifests**: Every `.jkm` container embeds an RFC 8949 CBOR manifest signed by the build key, recording SHA-256 and BLAKE3 digests.
- **Transparency Log**: Tamper-evident append-only Merkle log maintaining immutable records of every released module.

---

## Non-Goals

- **Not Offensive Tooling**: Zero weaponization capabilities; cannot be used for exploitation, persistence, credential extraction, or defense evasion against legitimate operators.
- **No Unconsented Execution**: Agents refuse to execute without a cryptographically valid consent token.
- **No Third-Party Targeting**: All test suites and primitives operate on operator-owned environments.

---

## Technical Design References

- [docs/00-blueprint.md](../docs/00-blueprint.md) — Master architectural blueprint and safety invariants.
- [docs/01-threat-model.md](../docs/01-threat-model.md) — STRIDE threat model and adversary assumptions.
- [docs/02-language-and-compiler.md](../docs/02-language-and-compiler.md) — EBNF language grammar and lexer/parser design.
- [docs/03-typechecker-and-codegen.md](../docs/03-typechecker-and-codegen.md) — HIR representation, lowering, and target ABI conventions.
- [docs/04-cicd-polymorphism.md](../docs/04-cicd-polymorphism.md) — Diversification passes and `.jkm` container format.
- [docs/05-multi-language-toolchain.md](../docs/05-multi-language-toolchain.md) — Multi-language CI build matrix and runner scripts.
