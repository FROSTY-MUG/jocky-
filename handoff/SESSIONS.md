# Engineering Work Log

This document records the chronological development history and milestones achieved across engineering sessions.

---

## Session 1: STEP 1.5 — Compiler Frontend & Denylist
- **Date**: 2026-09-25
- **Commit**: `94c032e`
- **Accomplishments**:
  - Implemented high-performance lexer using `logos` in `compiler/src/lexer/`.
  - Built recursive-descent parser with Pratt expression precedence in `compiler/src/parser/`.
  - Designed AST structures in `compiler/src/ast/`.
  - Implemented AST-level compile-time capability denylist in `compiler/src/passes/denylist.rs` barring 23 offensive primitives with diagnostic code `E0401`.
  - Authored standard library forensic scripts in `stdlib/jocky/` (`byovd.jky`, `inject.jky`, `memory.jky`, `network.jky`, `process.jky`, `syscall.jky`).
  - Passed 61 initial tests (`frontend_test` + `stdlib_test`).

---

## Session 2: STEP 2A — LLVM 17 Environment Repair & ELF64 Codegen
- **Date**: 2026-09-26
- **Commit**: `ae0f5d2`
- **Accomplishments**:
  - Repaired broken Windows LLVM state by standardizing on conda-forge's `llvmdev` 17.0.6 in `C:\Users\Aryan\miniconda3\envs\llvm17`.
  - Resolved MSVC linker errors by copying `z.lib` and configuring `zstd.dll.lib`.
  - Implemented semantic typechecker in `compiler/src/passes/typecheck.rs` (18 tests).
  - Built LLVM 17 code generation backend in `compiler/src/codegen/llvm.rs` using `inkwell` with `RelocMode::PIC` targeting `x86_64-unknown-linux-gnu` ELF64 objects.
  - Passed all 9 verification gates (88 total tests passing).

---

## Session 3: STEP 2B — Diversification, .jkm Container, Signing, COFF Target, Multi-Language CI
- **Date**: 2026-09-27
- **Commit**: (Included in `54b2b73`)
- **Accomplishments**:
  - Implemented 4 diversification passes in `compiler/src/passes/diversify.rs`:
    1. Seeded basic-block reordering.
    2. Algebraic instruction substitution.
    3. ChaCha20-keyed function name mangling.
    4. BLAKE3 per-build string XOR encryption (`jocky-string-key-v1`).
  - Designed `.jkm` binary container format in `compiler/src/jkm/` (64-byte header, code, RFC 8949 CBOR manifest, Ed25519 signature over H+C+M).
  - Implemented Ed25519 cryptographic signing and verification in `compiler/src/jkm/sign.rs`.
  - Built standalone verification tool `jocky-verify` (`compiler/src/bin/jocky-verify.rs`).
  - Added Windows COFF (`x86_64-pc-windows-msvc`) target support with `IMAGE_FILE_MACHINE_AMD64`.
  - Built multi-language CI toolchain:
    - Go single-binary artifact manager in `ci/go/` (`jocky-artifact`).
    - Python SPDX 2.3 SBOM generator and registry client in `ci/py/`.
    - Cross-platform Bash scripts (`ci/*.sh`, `ci/lib/common.sh`) and PowerShell scripts (`ci/ps/*.ps1`).
    - Windows batch wrapper `ci/diversify.bat`.
    - Scaffolds: C++20 Windows agent, Linux eBPF syscall tracer, macOS Swift 5.9 agent, and Go manager HTTP service.
    - Unified `justfile` and fallback `Makefile`.
  - Executed and passed all 15 verification gates (110 total tests passing).

---

## Session 4: Repository Polish & GitHub Publishing
- **Date**: 2026-09-27
- **Commit**: `54b2b73`
- **Accomplishments**:
  - Created root front-matter files: `README.md`, `SECURITY.md`, `LICENSE` (Apache-2.0), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CHANGELOG.md`, `AUTHORS.md`, `CITATION.cff`, `.editorconfig`, `.gitattributes`.
  - Added GitHub issue templates (`bug_report.md`, `feature_request.md`, `security_concern.md`, `config.yml`), pull request template, and `dependabot.yml`.
  - Added documentation index `docs/README.md`, terminology guide `docs/GLOSSARY.md`, and architecture pointer `docs/ARCHITECTURE.md`.
  - Executed audits V1–V6 (100% pass, markdown lint clean, secrets scan clean, 110 tests pass).
  - Pushed all commits cleanly to `https://github.com/FROSTY-MUG/jocky-` on branch `main`.
  - Created authoritative `handoff/` directory with comprehensive state snapshots and runbooks.

---

## Session 5: STEP 3A — Windows C++ Agent & Shared Consent Protocol
- **Date**: 2026-09-28
- **Commit**: (Pending STEP 3A commit)
- **Accomplishments**:
  - **Shared Protocol (`agent/common`)**:
    - Implemented C FFI layer (`agent/common/src/ffi.rs`) and C header (`agent/common/include/jocky.h`) exposing `jocky_consent_token_verify` and `jocky_jkm_verify` with safe foreign strings.
    - Added RFC 8949 CBOR serialization (`to_cbor()`, `from_cbor()`) to `ConsentToken` alongside dual JSON/CBOR verification support.
    - Implemented `issue()` function in `consent.rs` and standalone CLI binary `jocky-token-issue` in `agent/common/src/bin/jocky-token-issue.rs`.
    - Added integration test `agent/common/tests/consent_roundtrip.rs` with 3 deterministic tests passing with deterministic seed `[0x42u8; 32]`.
  - **Windows C++20 Agent (`agent/windows-cpp`)**:
    - Built C++20 agent runtime (`jocky-agent-win`) compiled with MSVC `/W4 /WX`.
    - Integrated with `jocky_common.dll` via dynamic link and `jocky.h`.
    - Implemented `ConsentValidator` supporting raw PEM text, hex text, base64 raw keys, and base64 PEM files.
    - Implemented `ModuleLoader` extracting COFF `.text` section from signed `.jkm` modules and executing in-process using `VirtualAlloc` (PAGE_READWRITE), `VirtualProtect` (PAGE_EXECUTE_READ), and `VirtualFree`.
    - Implemented read-only collectors in `collectors/`:
      - `process.cpp`: NtQuerySystemInformation process enumeration with `PROCESS_QUERY_LIMITED_INFORMATION`.
      - `network.cpp`: `GetExtendedTcpTable` / `GetExtendedUdpTable` connection enumeration.
      - `driver.cpp`: `EnumDeviceDrivers` + BCrypt SHA-256 driver hashing.
    - Implemented detection modules in `detect/`:
      - `byovd.cpp`: Scans running drivers against LOLDrivers blocklist subset (`loldrivers_subset.json` converted to UTF-8).
      - `inject.cpp`: ETW consumer (`OpenTraceA` / `ProcessTrace`) tracking thread creation across processes with clean thread lifecycle.
    - Implemented structured JSON reporting and ProgramData audit logging (`C:\ProgramData\JOCKY\audit.log`).
    - Implemented 5 C++ test targets with CTest passing 100% (`run_all_tests`).
  - Executed Gates 1–12 cleanly (all passed with raw outputs recorded). Total tests passing: 138 (110 compiler + 23 common + 5 C++ test suites).

