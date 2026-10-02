# JOCKY

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![LLVM](https://img.shields.io/badge/LLVM-17.0.6-yellow.svg)](https://llvm.org/)

> **A consent-bound DFIR platform for authorized incident response in environments where security tooling has been degraded or blinded.**

Problem Statement: **SIH26148 (NTRO)** — *"Creation of scripts/functions with new programming language to commence Computer & Network forensic analysis without triggering security solutions."*

---

## 1. Project Status

| Phase | Milestone | Status | Details |
| --- | --- | --- | --- |
| **STEP 1.5** | Compiler Frontend | **COMPLETE** | Lexer (`logos`), AST, recursive-descent parser, denylist pass, typechecker. |
| **STEP 2A** | LLVM 17 Code Generation | **COMPLETE** | Emits valid SysV x86_64 ELF objects via `inkwell` and LLVM 17 (conda-forge). |
| **STEP 2B** | Diversification, .jkm, Signing, COFF | **COMPLETE** | 4 diversification passes, `.jkm` container, Ed25519 sign/verify, Windows COFF target, multi-language CI toolchain. |
| **STEP 3** | Agents, Manager, Frontend | **COMPLETE** | Full RESTful Go Central Manager with SHA-256 audit chaining & RFC 8949 consent issuance; modern React 18/Vite/Tailwind DFIR dashboard with live script IDE, AST denylist verification & polymorphic simulation; Windows agent in-process loader. |

All automated tests in the test suite pass with zero failures (including 100% Go manager tests and frontend build validation).

---

## 2. Problem Context & Defensive Mission

During active cybersecurity incidents, adversaries frequently blind or disable endpoint detection and response (EDR) systems, unload minifilter drivers, terminate forensic logging daemons (`auditd`, `sysmon`), or install brittle hash-based blocklists to impede investigative response.

JOCKY provides authorized incident response teams with **resilient forensic continuity**. When standard endpoint tools are degraded, JOCKY compiles forensic scripts into cryptographically attested, structurally diversified binary modules (`.jkm`) capable of gathering evidence without being blocked by brittle static signature rules.

### Defensive Non-Goal

JOCKY is strictly **blue-team software**. It is designed solely for authorized forensic investigation on infrastructure owned by the operator or under written engagement terms. It contains zero offensive capabilities, zero exploits, and zero stealth mechanisms designed to evade legitimate administrative oversight.

---

## 3. What JOCKY Is

- **Domain-Specific Language (JOCKY v0.1)**: Statically typed language tailored specifically for forensic artifact collection (process inspection, memory scanning, BYOVD driver verification, syscall auditing).
- **Hardened Compiler Frontend (`jockyc`)**: Implements strict lexing, recursive-descent parsing, static typechecking, and an AST-level security denylist.
- **LLVM 17 Backend**: High-performance native code generation supporting both Linux (`x86_64-unknown-linux-gnu`) ELF64 and Windows (`x86_64-pc-windows-msvc`) COFF-x86-64 objects.
- **Polymorphic Diversification Engine**: Applies seeded basic-block reordering, algebraic instruction substitution, ChaCha20 symbol mangling, and BLAKE3-derived string encryption.
- **Attested Container Format (`.jkm`)**: Binary container packaging raw machine code, an RFC 8949 CBOR metadata manifest, and a 64-byte Ed25519 digital signature.
- **Independent Verifier (`jocky-verify`)**: Standalone binary for validating module provenance, manifest claims, and cryptographic signatures before execution.
- **Multi-Language Build Toolchain**: Go artifact manager (`ci/go`), Python SPDX 2.3 SBOM generator (`ci/py`), Bash and PowerShell scripts, and C++/eBPF/Swift scaffolding.

---

## 4. What JOCKY Is Not

- **Not Malware**: Does not contain payloads, backdoors, rootkits, or dropper logic.
- **Not a Command-and-Control (C2) Framework**: Contains no beacons, interactive shells, or covert command dispatchers.
- **Not an Evasion or Obfuscation Tool for Adversaries**: Polymorphism is used exclusively to defeat brittle hash collision and signature blocking, paired with explicit digital attestation and auditable manifests.
- **No Offensive Capabilities**: The compiler enforces an uncompromising compile-time denylist that rejects offensive operations at the AST level.

---

## 5. Security & Safety Model

### Compile-Time Capability Denylist

The compiler frontend scans every parsed AST against a 23-primitive denylist. Any script calling or referencing these functions is rejected immediately:

```text
inject_remote_process      write_process_memory     create_service
dump_lsass                 install_driver           harvest_credentials
bypass_uac                 create_remote_thread     virtual_alloc_ex
set_run_key                schedule_task            disable_etw
patch_amsi                 token_steal              revert_to_self
keylog                     screenshare              exfiltrate_dns
disable_defender           clear_event_log          modify_firewall
encrypt_volume             zero_mbr
```

### Digital Attestation

Every `.jkm` container embeds:

- A 64-byte binary header with container magic `JKM\x01` and section offsets.
- Machine code section (ELF64 or COFF-x86-64).
- A CBOR manifest detailing compiler version, UTC timestamp, build seed, BLAKE3 and SHA-256 digests, and symbol mappings.
- An Ed25519 digital signature over `header + code + manifest` (Trap T3 specification).

---

## 6. Repository Layout

```text
sihmaim/
├── compiler/                 # Rust compiler crate (jockyc, jocky-verify)
│   ├── src/                  # Lexer, parser, AST, HIR, typecheck, codegen, jkm, diversify
│   └── tests/                # 110 unit and integration tests
├── stdlib/jocky/             # Forensic collection standard library (.jky scripts)
├── ci/
│   ├── go/                   # Go single-binary artifact manager (jocky-artifact)
│   ├── py/                   # Python SBOM generator (SPDX 2.3), hash, and registry
│   ├── ps/                   # PowerShell CI automation for Windows
│   ├── lib/                  # Bash shared library for POSIX
│   └── diversify.sh / .bat   # Cross-platform diversification runners
├── agent/                    # Language-specific agent scaffolds
│   ├── windows-cpp/          # C++20 Windows agent (CMake)
│   ├── linux-ebpf/           # C eBPF kernel visibility scaffold (Makefile)
│   └── macos-swift/          # Swift 5.9 macOS agent (Package.swift)
├── manager/go/               # Lightweight Go manager service scaffold
├── docs/                     # Technical specifications, threat models, and runbooks
├── justfile / Makefile       # Top-level build orchestration runners
└── .github/                  # CI workflow matrix and issue templates
```

---

## 7. Quick Start

### Prerequisites

- **Rust**: 1.80+ (`cargo`, `rustc`)
- **LLVM 17**: LLVM 17.0.6 development headers and libraries.
  - On Windows: Conda-forge `llvmdev` in an isolated conda environment:

    ```powershell
    $env:LLVM_SYS_170_PREFIX = "$HOME\miniconda3\envs\llvm17\Library" # Or your LLVM 17 install path
    $env:Path = "$env:LLVM_SYS_170_PREFIX\bin;" + $env:Path
    ```

  - On Linux: `sudo apt-get install llvm-17-dev clang-17`
- **Go**: 1.22+ (for CI artifact manager and Manager service)
- **Python**: 3.10+ with `blake3`
- **Node.js**: 18+ (for frontend dashboard)

### Building the Compiler

```bash
cargo build --workspace
```

### Running Tests

```bash
cargo test -p jockyc -- --nocapture
```

### Running the Central Manager Service (Go)

```bash
cd manager/go
go test -v ./...
go run ./cmd/jocky-manager -addr :8080
```

### Running the DFIR Operations Dashboard (React / Vite)

```bash
cd frontend
npm install
npm run dev
# Dashboard accessible at http://localhost:5173
```

---

## 8. Writing and Compiling a JOCKY Script

A sample forensic script inspecting a process ID and validating memory bounds:

```jocky
// inspect.jky - Process verification primitive
fn inspect_target(pid: i64) -> i64 {
    if (pid <= 0) {
        return 0;
    }
    let threshold: i64 = 4096;
    let baseline: i64 = pid + threshold;
    return baseline;
}

fn main() -> i64 {
    let result: i64 = inspect_target(1337);
    return result;
}
```

### Compilation Commands

1. **Compile to Linux ELF64 Object**:

   ```bash
   cargo run -p jockyc -- build inspect.jky --target x86_64-unknown-linux-gnu --out inspect.o
   ```

2. **Compile to Windows COFF Object**:

   ```bash
   cargo run -p jockyc -- build inspect.jky --target x86_64-pc-windows-msvc --out inspect.obj
   ```

3. **Compile, Diversify, and Sign into a `.jkm` Container**:

   ```bash
   cargo run -p jockyc -- keygen --out signing.key
   cargo run -p jockyc -- build inspect.jky \
       --target x86_64-pc-windows-msvc \
       --seed 42 \
       --sign --key signing.key \
       --out inspect.jkm
   ```

4. **Verify Container Attestation**:

   ```bash
   cargo run -p jockyc --bin jocky-verify -- inspect.jkm --pubkey signing.pub --verbose
   ```

---

## 9. Verification & Test Matrix

The test suite covers:

- **18 Typecheck Tests**: Primitive typechecking, struct validation, method resolution, error spans.
- **55 Frontend Tests**: Full lexical analysis, grammar precedence, AST generation, and 14 explicit denylist test cases.
- **11 Codegen Tests**: Arithmetic, control flow, functions, loops, structs, string constants, LLVM IR emission.
- **6 Stdlib Codegen Tests**: End-to-end compilation of all forensic modules in `stdlib/jocky`.
- **6 Stdlib AST Tests**: Verification of stdlib source code structure.
- **5 Diversification Tests**: Seed determinism, BB reordering, instruction substitution, symbol mangling, string XOR encryption.
- **4 .jkm Container Tests**: Header roundtrip, binary serialization, magic validation, CBOR manifest extraction.
- **4 Ed25519 Signing Tests**: Key generation, happy path verification, single-bit tamper detection, mismatched public key rejection.
- **1 Windows COFF Test**: Full verification of `IMAGE_FILE_MACHINE_AMD64` COFF binary emission.

---

## 10. Documentation Index

- [00-blueprint.md](docs/00-blueprint.md): Complete architecture blueprint, constraints, and non-goals.
- [01-threat-model.md](docs/01-threat-model.md): Threat model, trust boundaries, and consent framework.
- [02-language-and-compiler.md](docs/02-language-and-compiler.md): JOCKY language grammar and compiler architecture.
- [03-typechecker-and-codegen.md](docs/03-typechecker-and-codegen.md): Type system, HIR, and LLVM 17 IR lowering.
- [03-agent-runtime.md](docs/03-agent-runtime.md): Agent execution environment, sandbox, and consent token verification.
- [04-cicd-polymorphism.md](docs/04-cicd-polymorphism.md): Polymorphic diversification, `.jkm` specification, and attestation.
- [05-manager-and-cloud.md](docs/05-manager-and-cloud.md): Central management server and audit logging.
- [05-multi-language-toolchain.md](docs/05-multi-language-toolchain.md): Polyglot build system, environments, and CI orchestration.
- [06-frontend-dashboard.md](docs/06-frontend-dashboard.md): Forensic investigation dashboard specification.
- [07-security-and-ops.md](docs/07-security-and-ops.md): Operational security, key management, and deployment guidelines.
- [08-testing-plan.md](docs/08-testing-plan.md): Test methodology, differential testing, and fuzzing plan.
- [runbook.md](docs/runbook.md): Incident responder operator runbook.
- [GLOSSARY.md](docs/GLOSSARY.md): Comprehensive DFIR and JOCKY terminology reference.

---

## 11. Community & Governance

- **Security Policy**: See [SECURITY.md](SECURITY.md) for vulnerability disclosure guidelines.
- **Contributing**: Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening pull requests.
- **Code of Conduct**: JOCKY adheres to the Contributor Covenant v2.1. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## 12. License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

Copyright © 2026 The JOCKY Authors.

---

## 13. Acknowledgments

- **The LLVM Project** for robust target lowering and code generation infrastructure.
- **The conda-forge Community** for packaging portable Windows LLVM 17 builds.
- **The Rust Ecosystem**: `inkwell`, `logos`, `clap`, `ed25519-dalek`, `ciborium`, `blake3`, `rand_chacha`, and `serde`.
- **Smart India Hackathon (SIH) & NTRO** for Problem Statement SIH26148.
