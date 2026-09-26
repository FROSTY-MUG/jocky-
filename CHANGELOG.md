# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-27

### Added

- **Language Specification & Compiler Frontend**:
  - JOCKY v0.1 grammar specification and design document ([docs/02-language-and-compiler.md](docs/02-language-and-compiler.md)).
  - High-performance lexer powered by `logos`.
  - Recursive-descent parser with comprehensive AST data structures and Pratt expression precedence parsing.
  - Full semantic typechecker supporting primitive types, user-defined structs, arrays, and return inference.
- **LLVM 17 Native Code Generation**:
  - LLVM 17 codegen backend using `inkwell` bindings.
  - Linux ELF64 (`x86_64-unknown-linux-gnu`) relocatable object generation.
  - Windows COFF-x86-64 (`x86_64-pc-windows-msvc`) object generation with `IMAGE_FILE_MACHINE_AMD64` support.
  - LLVM IR textual emission flag (`--emit-ir`).
- **Binary Diversification & Polymorphism Engine**:
  - Seed-deterministic basic-block reordering preserving CFG dominance relationships.
  - Algebraic and bitwise instruction substitution.
  - Deterministic function symbol mangling keyed via `ChaCha20Rng`.
  - BLAKE3-derived per-build string literal XOR encryption.
- **`.jkm` Container Format & Attestation**:
  - 64-byte structured container binary header with magic `JKM\x01` and section offsets.
  - Embedded RFC 8949 CBOR manifest tracking build seed, timestamps, and symbol maps.
  - Ed25519 digital signing over `header + code + manifest` (Trap T3).
  - Standalone verification binary (`jocky-verify`) for provenance auditing and tamper detection.
- **Multi-Language CI/CD Toolchain**:
  - Go single-binary artifact management tool (`ci/go`) with BLAKE3 and SHA-256 calculation.
  - Python SPDX 2.3 JSON SBOM generator (`ci/py/sbom.py`) and registry client (`ci/py/registry.py`).
  - Cross-platform Bash scripts (`ci/*.sh`, `ci/lib/common.sh`) and PowerShell scripts (`ci/ps/*.ps1`).
  - Windows command-line batch wrapper (`ci/diversify.bat`).
  - Polyglot agent scaffolding: Windows C++20 (`agent/windows-cpp`), Linux C eBPF (`agent/linux-ebpf`), and macOS Swift 5.9 (`agent/macos-swift`).
  - Lightweight Go manager service scaffold (`manager/go`).
  - Top-level `justfile` and fallback `Makefile` build dispatchers.
- **Comprehensive Test Suite**:
  - 110 automated tests covering unit, integration, stdlib, codegen, diversification, and cryptographic tamper detection.

### Security

- Compile-time capability denylist actively barring 23 offensive primitives (process injection, credential dumping, persistence, and defense disabling).
- Ed25519 digital signature validation detecting byte flips and tampered container sections.
