# 05 — Multi-Language Build & CI Toolchain

**JOCKY v0.1 Toolchain Specification**  
Problem Statement: **SIH26148 (NTRO)**  
Blueprint Section: **§4 CI/CD Pipeline & Build Orchestration**

---

## 1. Toolchain Rationale & Division of Responsibilities

JOCKY utilizes a polyglot build and runtime architecture where each language is chosen strictly for its domain fitness:

| Language | Components | Purpose & Scope |
|---|---|---|
| **Rust** | `compiler/`, `jocky-verify` | Core language parser, typechecker, denylist enforcer, LLVM 17 codegen, diversification passes, `.jkm` container serializer, Ed25519 cryptography. |
| **Go** | `ci/go/`, `manager/go/` | Portable, single-binary CI artifact manager (`jocky-artifact`), and lightweight management server scaffold (`jocky-manager`). |
| **Python** | `ci/py/` | Supply chain attestation: BLAKE3/SHA-256 cryptographic hashing, SPDX 2.3 JSON SBOM generation, artifact catalog registry. |
| **Bash** | `ci/*.sh`, `ci/lib/common.sh` | Linux & macOS POSIX CI automation with syntax checks, logging, and error traps. |
| **PowerShell** | `ci/ps/*.ps1` | Windows native CI automation with parameter binding and color logging (compatible with Windows PowerShell 5.1 and PowerShell Core 7+). |
| **Batch** | `ci/diversify.bat` | Zero-dependency CMD command wrapper delegating to PowerShell. |
| **C++20** | `agent/windows-cpp/` | Native Windows agent scaffold built with CMake and MSVC (`cl.exe`). |
| **C (eBPF)**| `agent/linux-ebpf/` | Linux kernel visibility scaffold targeting BPF bytecode (`clang -target bpf`). |
| **Swift 5.9**| `agent/macos-swift/`| Native macOS agent scaffold managed via Swift Package Manager (`Package.swift`). |
| **Just / Make**| `justfile`, `Makefile` | Unified top-level runner dispatching tasks across platforms. |

---

## 2. Directory Layout

```
sihmaim/
├── compiler/                 # Rust compiler crate (jockyc, jocky-verify)
│   ├── src/
│   │   ├── bin/jocky-verify.rs
│   │   ├── codegen/llvm.rs   # ELF64 and Windows COFF-x86-64 support
│   │   ├── jkm/              # Container, manifest (CBOR), and Ed25519 signing
│   │   ├── passes/diversify.rs # 4 diversification passes
│   │   └── main.rs
│   └── tests/
├── ci/
│   ├── go/                   # Go artifact management CLI (jocky-artifact)
│   ├── py/                   # Python SBOM, hashing, registry client
│   ├── ps/                   # PowerShell scripts for Windows
│   ├── lib/                  # Bash shell library
│   ├── diversify.sh          # Linux/macOS diversification runner
│   ├── sign.sh               # Linux/macOS signing script
│   ├── verify.sh             # Linux/macOS verification script
│   ├── sbom.sh               # Linux/macOS SBOM script
│   └── diversify.bat         # Windows batch wrapper
├── agent/
│   ├── windows-cpp/          # C++20 Windows agent scaffold (CMake)
│   ├── linux-ebpf/           # C eBPF syscall trace scaffold (Makefile)
│   └── macos-swift/          # Swift macOS agent scaffold (Package.swift)
├── manager/
│   └── go/                   # Go management server scaffold
├── justfile                  # Primary build runner (just)
├── Makefile                  # Fallback runner (make)
└── .github/workflows/ci.yml  # Multi-platform CI pipeline
```

---

## 3. Environment & Prerequisites

### Windows Environment
- **LLVM 17**: `C:\Users\Aryan\miniconda3\envs\llvm17\Library` (inkwell bindings)
- **Rust**: 1.80+ (MSVC toolchain)
- **Go**: 1.22+ (x64)
- **Python**: 3.10+ with `blake3` and `ciborium`
- **CMake**: 3.20+ with Visual Studio Build Tools 2019/2022
- **PowerShell**: Windows PowerShell 5.1 / PowerShell 7 Core

### Linux & macOS Environment
- **Clang/LLVM 17**: Package manager install (`llvm-17`, `clang-17`)
- **libbpf**: `libbpf-dev` for eBPF targets on Linux
- **Xcode / Swift**: macOS 13+ with Xcode 15+ for Swift agent

---

## 4. Platform Verification Commands

| Component | Target OS | Verification Command | Expected Result |
|---|---|---|---|
| Rust Compiler | Cross-Platform | `cargo test -p jockyc` | All unit & integration tests pass |
| Go CI Tool | Cross-Platform | `cd ci/go && go build ./... && go vet ./...` | Compiles with exit code 0 |
| Go Manager | Cross-Platform | `cd manager/go && go build ./... && go vet ./...` | Compiles with exit code 0 |
| Python Suite | Cross-Platform | `python -m py_compile ci/py/*.py` | Byte-compiles without syntax error |
| Bash Scripts | Linux/macOS (Win: syntax) | `bash -n ci/*.sh ci/lib/*.sh` | Passes shell syntax check |
| PowerShell | Windows / Linux | `pwsh -NoProfile -File ci/ps/diversify.ps1 -Help` | Prints usage and exits 0 |
| Batch Wrapper | Windows | `cmd /c ci\diversify.bat --help` | Prints usage and exits 0 |
| Windows C++ | Windows | `cmake -S agent/windows-cpp -B build && cmake --build build` | Emits `jocky-agent-win.exe` |
| Orchestrator | Cross-Platform | `just --list` or `make help` | Displays recipe targets |
