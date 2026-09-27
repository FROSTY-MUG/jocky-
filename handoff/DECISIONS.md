# Architecture Decision Records (ADRs)

This document records the architectural and design decisions established during the development of JOCKY v0.1.

---

## ADR 001: Compile-Time Capability Denylist Enforcement
- **Date**: 2026-09-25
- **Status**: Accepted & Implemented
- **Context**: Problem statement SIH26148 (NTRO) requires forensic analysis without triggering false positives or being blocked by signature engines. The platform must be strictly defensive and provably non-weaponizable.
- **Decision**: Reject all offensive primitives (process injection, credential dumping, persistence, defense disabling) at parse/AST check time with compiler diagnostic code `E0401`.
- **Consequences**: Offensive operations cannot be compiled, represented in HIR, or emitted into machine code. 14 explicit tests in `frontend_test` enforce this boundary.

---

## ADR 002: Conda-Forge LLVM 17 for Windows Build Environment
- **Date**: 2026-09-26
- **Status**: Accepted & Implemented
- **Context**: The official Windows LLVM 17 installer (`LLVM-17.0.6-win64.exe`) and vcpkg binary distributions fail on Windows MSVC environments due to missing static headers, lack of `llvm-config.exe`, or incompatible DLL imports.
- **Decision**: Standardize Windows development on conda-forge's `llvmdev` 17.0.6 package installed into an isolated conda environment (`llvm17`), with `z.lib` and `zstd.dll.lib` copied into the library path.
- **Consequences**: Stable, reproducible inkwell compilation on Windows using MSVC `link.exe` without administrative privileges.

---

## ADR 003: Deterministic Polymorphism Engine (4 Passes)
- **Date**: 2026-09-26
- **Status**: Accepted & Implemented
- **Context**: In compromised environments, defenders face brittle hash blocklists. To prevent legitimate DFIR agents from being blocked, binaries must be polymorphic while remaining mathematically deterministic and reproducible.
- **Decision**: Implement four diversification passes on the HIR:
  1. Seeded basic-block reordering.
  2. Algebraic instruction substitution.
  3. Function symbol name mangling (`<name>_<hex8>`) via `ChaCha20Rng`.
  4. String literal XOR encryption with a 32-byte key derived via `BLAKE3(seed || "jocky-string-key-v1")`.
- **Consequences**: Binaries compiled from identical source with distinct seeds have zero hash collisions, while retaining identical runtime behavior.

---

## ADR 004: `.jkm` Binary Container Format and Ed25519 Attestation
- **Date**: 2026-09-26
- **Status**: Accepted & Implemented
- **Context**: Polymorphic binaries require rigorous attestation so endpoint operators can verify that a newly generated binary was built by an authorized compiler.
- **Decision**: Design the `.jkm` (JOCKY Module) container format:
  - 64-byte binary header with magic `JKM\x01` and section offsets.
  - Raw code section (ELF64 or COFF-x86-64).
  - RFC 8949 CBOR metadata manifest (`ciborium`) tracking seed, timestamps, and symbol maps.
  - 64-byte Ed25519 digital signature covering `Header + Code + Manifest` (Trap T3).
- **Consequences**: Any bit flip in the header, code, or manifest causes `jocky-verify` to reject the module with an exit code of 1.

---

## ADR 005: Dual-Target Support (Linux ELF64 + Windows MSVC COFF)
- **Date**: 2026-09-26
- **Status**: Accepted & Implemented
- **Context**: Forensics must operate on both Linux servers and Windows enterprise workstations.
- **Decision**: Configure inkwell's `TargetMachine` with `RelocMode::PIC` for `x86_64-unknown-linux-gnu` and `RelocMode::Default` for `x86_64-pc-windows-msvc`, targeting `IMAGE_FILE_MACHINE_AMD64`.
- **Consequences**: The compiler natively emits `.o` (ELF64) and `.obj` (COFF) objects from the same JOCKY source files.

---

## ADR 006: Multi-Language CI/CD Orchestration
- **Date**: 2026-09-27
- **Status**: Accepted & Implemented
- **Context**: Different tooling requirements across platforms demand language-specific tools (Go for single-binary distribution, Python for SPDX SBOMs, PowerShell for Windows, Bash for POSIX).
- **Decision**: Maintain native scripts for each ecosystem (`ci/go`, `ci/py`, `ci/ps`, `ci/*.sh`), managed from top-level `justfile` and fallback `Makefile`.
- **Consequences**: Every CI script is runnable in its native environment and syntactically verifiable across platforms.
