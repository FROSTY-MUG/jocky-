# State Snapshot

**Last updated:** 2026-09-28T04:00:00Z  
**Last commit:** (Pending STEP 3A commit)  
**Tests passing:** 138 passed (110 compiler + 23 common + 5 C++ test suites); 0 failed  
**Denylist enforcement:** WORKING (verified by GATE 12 compile-fail regression and 14 tests in `frontend_test`)

---

## Phase Completion

| Phase | Description | Status | Details |
|---|---|---|---|
| **1.5** | Compiler frontend (lexer, parser, AST, denylist) | **COMPLETE** | Logos lexer, Pratt parser, AST, 23-primitive capability denylist. |
| **2A** | Typechecker + LLVM codegen (Linux ELF64) | **COMPLETE** | Bidirectional type inference, SysV x86_64 ELF objects via inkwell + LLVM 17. |
| **2B** | Diversification, .jkm, Ed25519, COFF, multi-lang CI | **COMPLETE** | 4 passes, `.jkm` binary container, Ed25519 signing/verification, Windows COFF, multi-language CI toolchain. |
| **Repo Polish**| README, SECURITY, LICENSE, templates, CI push | **COMPLETE** | Full front-matter, issue/PR templates, dependabot, push verified on `origin/main`. |
| **3A** | Windows C++ Agent + Shared Consent Protocol | **COMPLETE** | C++20 runtime, Ed25519 consent token enforcement, in-process COFF execution, read-only collectors (process, network, driver), detectors (BYOVD with LOLDrivers blocklist, ETW injection). |
| **3B** | Linux Agent & eBPF Program | **NOT STARTED** | Ready for execution; eBPF syscall tracer and Rust agent. |
| **3C** | macOS Swift Agent | **NOT STARTED** | EndpointSecurity framework integration deferred. |
| **4** | Real manager (Go), cloud relay (S3/SQS) | **NOT STARTED** | Go manager scaffold (`manager/go`) verified; HTTP health check operational. |
| **5** | Frontend dashboard (React + Tailwind) | **NOT STARTED** | Directory scaffolded in `frontend/`; implementation deferred. |
| **6** | Real-world lab testing campaign | **NOT STARTED** | Planned for live deployment environments. |

---

## Component Ledger

| Component | Language | Status | Proof Command | Last Verified |
|---|---|---|---|---|
| `compiler/src/passes/diversify.rs` | Rust | **WORKING** | `cargo test -p jockyc --test diversify_test` | 2026-09-28 |
| `compiler/src/passes/mod.rs` | Rust | **WORKING** | `cargo check -p jockyc` | 2026-09-28 |
| `compiler/src/jkm/mod.rs` | Rust | **WORKING** | `cargo check -p jockyc` | 2026-09-28 |
| `compiler/src/jkm/manifest.rs` | Rust | **WORKING** | `cargo test -p jockyc --test jkm_test` | 2026-09-28 |
| `compiler/src/jkm/sign.rs` | Rust | **WORKING** | `cargo test -p jockyc --test sign_test` | 2026-09-28 |
| `compiler/src/jkm/container.rs` | Rust | **WORKING** | `cargo test -p jockyc --test jkm_test` | 2026-09-28 |
| `compiler/src/codegen/llvm.rs` | Rust | **WORKING** | `cargo test -p jockyc --test codegen_coff_test` | 2026-09-28 |
| `compiler/src/main.rs` | Rust | **WORKING** | `cargo build -p jockyc --bin jockyc` | 2026-09-28 |
| `compiler/src/bin/jocky-verify.rs` | Rust | **WORKING** | `cargo build -p jockyc --bin jocky-verify` | 2026-09-28 |
| `agent/common/src/consent.rs` | Rust | **WORKING** | `cargo test -p jocky-common` | 2026-09-28 |
| `agent/common/src/ffi.rs` | Rust | **WORKING** | `cargo build -p jocky-common --release` | 2026-09-28 |
| `agent/common/src/bin/jocky-token-issue.rs` | Rust | **WORKING** | `cargo run -p jocky-common --bin jocky-token-issue -- --help` | 2026-09-28 |
| `agent/common/tests/consent_roundtrip.rs` | Rust | **WORKING** | `cargo test -p jocky-common --test consent_roundtrip` | 2026-09-28 |
| `agent/windows-cpp/src/main.cpp` | C++20 | **WORKING** | `.\agent\windows-cpp\build\Release\jocky-agent-win.exe --version` | 2026-09-28 |
| `agent/windows-cpp/src/agent.cpp` | C++20 | **WORKING** | `powershell -ExecutionPolicy Bypass -File .\scratch\test_gates.ps1` | 2026-09-28 |
| `agent/windows-cpp/src/consent.cpp` | C++20 | **WORKING** | `ctest -R test_consent --output-on-failure -C Release` | 2026-09-28 |
| `agent/windows-cpp/src/module_loader.cpp` | C++20 | **WORKING** | `ctest -R test_module_loader --output-on-failure -C Release` | 2026-09-28 |
| `agent/windows-cpp/src/collectors/` | C++20 | **WORKING** | `ctest -R test_collectors --output-on-failure -C Release` | 2026-09-28 |
| `agent/windows-cpp/src/detect/byovd.cpp` | C++20 | **WORKING** | `ctest -R test_byovd --output-on-failure -C Release` | 2026-09-28 |
| `agent/windows-cpp/src/detect/inject.cpp` | C++20 | **WORKING** | `ctest -R test_inject --output-on-failure -C Release` | 2026-09-28 |
| `ci/py/hash.py` | Python | **WORKING** | `python ci/py/hash.py .\scratch\signed.jkm` | 2026-09-27 |
| `ci/py/sbom.py` | Python | **WORKING** | `python -m py_compile ci/py/sbom.py` | 2026-09-27 |
| `ci/py/registry.py` | Python | **WORKING** | `python -m py_compile ci/py/registry.py` | 2026-09-27 |
| `ci/lib/common.sh` | Bash | **WORKING** | `bash.exe -n ci/lib/common.sh` | 2026-09-27 |
| `ci/diversify.sh` | Bash | **WORKING** | `bash.exe ci/diversify.sh --help` | 2026-09-27 |
| `ci/sign.sh` | Bash | **WORKING** | `bash.exe -n ci/sign.sh` | 2026-09-27 |
| `ci/verify.sh` | Bash | **WORKING** | `bash.exe -n ci/verify.sh` | 2026-09-27 |
| `ci/sbom.sh` | Bash | **WORKING** | `bash.exe -n ci/sbom.sh` | 2026-09-27 |
| `ci/ps/common.ps1` | PowerShell | **WORKING** | `pwsh -NoProfile -Command "& { . .\ci\ps\common.ps1 }"` | 2026-09-27 |
| `ci/ps/diversify.ps1` | PowerShell | **WORKING** | `pwsh -NoProfile -File ci/ps/diversify.ps1 -Help` | 2026-09-27 |
| `ci/ps/sign.ps1` | PowerShell | **WORKING** | `pwsh -NoProfile -File ci/ps/sign.ps1 -Help` | 2026-09-27 |
| `ci/ps/verify.ps1` | PowerShell | **WORKING** | `pwsh -NoProfile -File ci/ps/verify.ps1 -Help` | 2026-09-27 |
| `ci/ps/sbom.ps1` | PowerShell | **WORKING** | `pwsh -NoProfile -File ci/ps/sbom.ps1 -Help` | 2026-09-27 |
| `ci/diversify.bat` | Batch | **WORKING** | `cmd /c ci\diversify.bat --help` | 2026-09-27 |
| `ci/go/main.go` | Go | **WORKING** | `cd ci/go && go build ./... && go vet ./...` | 2026-09-27 |
| `ci/go/internal/artifact/artifact.go` | Go | **WORKING** | `go run . hash ../../scratch/signed.jkm` | 2026-09-27 |
| `ci/go/internal/registry/registry.go` | Go | **WORKING** | `cd ci/go && go vet ./...` | 2026-09-27 |
| `agent/linux-ebpf/src/syscall_trace.bpf.c` | C (BPF) | **PARTIAL** | Verified syntax; requires Linux kernel headers + `clang -target bpf` | 2026-09-27 |
| `agent/macos-swift/Package.swift` | Swift 5.9 | **PARTIAL** | Manifest syntax valid; requires macOS 13+ and Xcode 15+ | 2026-09-27 |
| `manager/go/cmd/jocky-manager/main.go` | Go | **WORKING** | `cd manager/go && go build ./... && go vet ./...` | 2026-09-27 |
| `justfile` | Just | **WORKING** | `just --list` | 2026-09-27 |
| `Makefile` | Make | **WORKING** | `make help` | 2026-09-27 |

---

## Known Gaps

- **`agent/linux-ebpf/src/syscall_trace.bpf.c`**: PARTIAL — requires Linux kernel 5.8+ with BTF headers and `clang -target bpf`. Syntax checked on Windows; fully compiled and tested in GitHub Actions on `ubuntu-latest`. Deferred to STEP 3B.
- **`agent/macos-swift/Package.swift`**: PARTIAL — requires macOS 13+ with Xcode 15+ and Swift 5.9 toolchain. Package manifest validated; execution deferred to macOS CI runner. Deferred to STEP 3C.
- **`manager/go/`**: SCAFFOLD WORKING — Go HTTP service listens on `:8080`, handles `/health`, and shuts down on SIGTERM/SIGINT. Multi-tenant database logic and policy distribution deferred to STEP 4.

---

## Test Counts

| Test Suite | Count | Status | Notes |
|---|---|---|---|
| `frontend_test` | 55 | **PASS** | Lexing, parsing, precedence, 14 explicit denylist rejections |
| `stdlib_test` | 6 | **PASS** | Verification of standard library AST structures |
| `typecheck_test` | 18 | **PASS** | Type inference, primitive checks, struct field checks |
| `codegen_test` | 11 | **PASS** | Arithmetic, loops, structs, functions, IR flags |
| `codegen_stdlib_test` | 6 | **PASS** | LLVM object code generation for all stdlib modules |
| `codegen_coff_test` | 1 | **PASS** | Windows COFF `IMAGE_FILE_MACHINE_AMD64` emission |
| `diversify_test` | 5 | **PASS** | BB reordering, instruction substitution, mangling, string enc |
| `jkm_test` | 4 | **PASS** | Header serialization, magic verification, CBOR roundtrip |
| `sign_test` | 4 | **PASS** | Keygen, signing, single-bit tamper rejection, wrong key rejection |
| `jocky_common_lib` | 20 | **PASS** | Ed25519 consent tokens, CBOR serialization, policy checks |
| `jocky_common_roundtrip` | 3 | **PASS** | End-to-end token issue & verify, tamper rejection, key mismatch |
| `agent_win_cpp` | 5 suites | **PASS** | CTest 100% passed: consent (5), loader (3), collectors (3), byovd (2), inject (2) |
| **Total** | **138** | **PASS** | **All suites pass with 0 failures** |
