# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **STEP 3 — Central Manager Service (`manager/go`)**:
  - Implemented complete, concurrent-safe in-memory store preloaded with realistic fleet endpoints, stdlib forensic scripts, and threat findings.
  - Developed RESTful API endpoints for agent management, heartbeats, status quarantine/reinstatement, and job dispatching.
  - Implemented cryptographic RFC 8949 consent token generation bound by ticket ID, scope targets, and validity window.
  - Built tamper-evident append-only cryptographic audit logging with SHA-256 hash chaining and automated `/api/v1/audit/verify` validation.
  - Built container attestation verification endpoint (`/api/v1/verify-jkm`) enforcing `JKM\x01` magic and section digests.
  - Added comprehensive automated unit tests for store and API with 100% pass rate.
- **STEP 3 — DFIR Operations Dashboard (`frontend`)**:
  - Added full build infrastructure: `vite.config.ts`, `tailwind.config.js`, `postcss.config.js`, and `tsconfig.json`.
  - Configured cyber dark-mode design system with glassmorphism, Google Fonts (`Inter`, `JetBrains Mono`), and glowing accents.
  - Built 7 interactive operational views:
    - **Fleet Overview**: Health strips, live manager connectivity status, alert banners, and active job/finding previews.
    - **Agents & Consent**: Interactive search/filtering by platform/state, polymorphic variant index inspector, collector health diagnostics, and host quarantine/reinstate modal.
    - **JOCKY Script IDE**: Code editor loaded with all 6 stdlib forensic scripts (`detect_byovd.jky`, `detect_inject.jky`, etc.), real-time AST capability denylist validator (testing all 23 forbidden primitives), and seed-based polymorphic diversification visualizer with lowered IR preview.
    - **Forensic Job Composer**: 5-step interactive incident response wizard with consent token generation and live execution stream.
    - **Threat Findings Workbench**: Threat inspection with MITRE ATT&CK technique tags (`T1068`, `T1055`, `T1106`), trust level indicators, and raw artifact JSON inspector.
    - **`.jkm` Container Verifier**: In-browser attestation inspector for 64-byte headers, CBOR manifests, and Ed25519 signatures.
    - **Cryptographic Audit Stream**: Chronological event ledger with live SHA-256 chain verification button and JSON export.
- **STEP 3 — Windows Agent In-Process Loader (`agent/windows`)**:
  - Implemented `InProcessLoader` in `agent/windows/src/loader.rs` with `JKM\x01` magic verification, consent token gate enforcement, and memory boundary safety.
  - Added `--version` and `--test-loader` CLI flags in `agent/windows/src/main.rs`.

### Fixed

- Replaced broken author-specific absolute paths (`file:///c:/Users/Aryan/Desktop/sihmaim/...`) with clean relative links across `README.md`, `docs/README.md`, and interface specs.
- Fixed hardcoded LLVM path in `compiler/tests/codegen_test.rs` to dynamically detect `LLVM_SYS_170_PREFIX`.
- Corrected path traversal bug in `Makefile` target `go-build` (`cd manager/go` instead of `cd ../../manager/go`).
- Removed invalid `ciborium` package from `ci/py/requirements.txt` and verified Python CI tools with `blake3`.

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
