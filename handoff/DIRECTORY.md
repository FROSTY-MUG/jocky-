# Repository Directory

This document describes the directory tree of the repository, providing one-line descriptions for every major top-level and subsystem component.

```text
sihmaim/
├── .github/                   # GitHub configurations, templates, and CI/CD pipelines
│   ├── ISSUE_TEMPLATE/        # Standardized bug, feature, and security issue templates
│   ├── workflows/ci.yml       # Multi-language CI matrix (Ubuntu, Windows, macOS)
│   ├── dependabot.yml         # Automated dependency version monitoring configuration
│   └── PULL_REQUEST_TEMPLATE.md # Review checklist enforcing denylist and test gates
│
├── agent/                     # Multi-platform agent implementations and scaffolds
│   ├── common/                # Shared Rust data structures (consent token, protocol, manifest)
│   ├── windows-cpp/           # C++20 Windows endpoint agent scaffold (CMake project)
│   ├── linux-ebpf/            # Linux kernel visibility eBPF programs (C + Makefile)
│   ├── macos-swift/           # macOS endpoint agent scaffold (Swift 5.9 Package)
│   ├── windows/               # Windows Rust agent scaffold
│   └── linux/                 # Linux Rust agent scaffold
│
├── ci/                        # Multi-language build and CI orchestration tooling
│   ├── go/                    # Go single-binary artifact manager (jocky-artifact CLI)
│   ├── py/                    # Python SBOM generator (SPDX 2.3), hash, and registry client
│   ├── ps/                    # PowerShell automation scripts for Windows CI
│   ├── lib/                   # POSIX Bash shared functions library (common.sh)
│   ├── diversify.sh / .bat    # Cross-platform polymorphic diversification runners
│   ├── sign.sh / verify.sh    # Ed25519 signing and verification CLI wrappers
│   └── sbom.sh                # Automated SBOM emission wrapper
│
├── compiler/                  # The JOCKY domain compiler and toolchain
│   ├── src/
│   │   ├── ast/               # Abstract Syntax Tree node definitions
│   │   ├── bin/               # Standalone binaries: jocky-verify attestation tool
│   │   ├── codegen/           # LLVM 17 lowering engine (Linux ELF64 & Windows COFF)
│   │   ├── diag/              # Compiler diagnostics, spans, and ANSI error formatting
│   │   ├── hir/               # High-Level Intermediate Representation
│   │   ├── jkm/               # .jkm container packaging, CBOR manifest, Ed25519 signing
│   │   ├── lexer/             # Tokenizer powered by logos
│   │   ├── parser/            # Recursive-descent parser with Pratt expression precedence
│   │   ├── passes/            # Denylist checker, typechecker, and 4 diversification passes
│   │   ├── prelude/           # Built-in type definitions and primitive declarations
│   │   ├── lib.rs             # Crate root library interface
│   │   └── main.rs            # jockyc compiler driver CLI
│   └── tests/                 # 110 automated tests (unit, integration, codegen, diversify)
│
├── docs/                      # Architectural specifications, threat models, and guides
│   ├── 00-blueprint.md        # Master architectural blueprint and safety invariants
│   ├── 01-threat-model.md     # STRIDE threat model and consent boundaries
│   ├── 02-language-and-compiler.md # Language grammar and compiler architecture
│   ├── 03-agent-runtime.md    # Agent runtime specification and sandboxing
│   ├── 03-typechecker-and-codegen.md # Type system and LLVM IR lowering
│   ├── 04-cicd-polymorphism.md # Diversification passes and .jkm specification
│   ├── 05-manager-and-cloud.md # Central management plane and audit log chaining
│   ├── 05-multi-language-toolchain.md # Multi-language build toolchain documentation
│   ├── 06-frontend-dashboard.md # Investigation dashboard UI specifications
│   ├── 07-security-and-ops.md # Operational security and cryptographic procedures
│   ├── 08-testing-plan.md     # QA strategy and differential testing methodology
│   ├── runbook.md             # Incident responder operational field guide
│   ├── GLOSSARY.md            # DFIR, compiler, and cryptographic terminology index
│   └── ARCHITECTURE.md        # High-level architecture map and pointer file
│
├── frontend/                  # React + Tailwind incident response web dashboard scaffold
│   └── src/                   # Dashboard components, state stores, and layout styles
│
├── handoff/                   # Authoritative handoff documentation for resuming work
│   ├── README.md              # Entry point for resuming developers or agents
│   ├── STATE.md               # Verified phase completion, ledger, and test counts
│   ├── ARCHITECTURE.md        # System design, data flows, and trust boundaries
│   ├── DIRECTORY.md           # Tree structure description and component catalog
│   ├── ENVIRONMENT.md         # Exact toolchain setup for Windows and Linux
│   ├── DECISIONS.md           # Architectural Decision Records (ADRs)
│   ├── GOTCHAS.md             # Documented failure modes and verified fixes
│   ├── NEXT.md                # Immediate next task with ready-to-execute prompts
│   └── SESSIONS.md            # Chronological engineering log
│
├── manager/                   # Central management server implementations
│   ├── go/                    # Lightweight Go management HTTP service scaffold
│   ├── src/                   # Rust manager service implementation scaffold
│   └── migrations/            # Database schema migration definitions
│
├── stdlib/jocky/              # Forensic analysis standard library scripts (.jky)
│   ├── byovd.jky              # BYOVD driver verification and LOLDrivers detector
│   ├── inject.jky             # Process memory anomaly and injection detector
│   ├── memory.jky             # Memory region scanner and PE header validator
│   ├── network.jky            # Network connection auditing and telemetry collector
│   ├── process.jky            # Process tree traversal and metadata inspector
│   └── syscall.jky            # Syscall hook verification and integrity probe
│
├── Cargo.toml / Cargo.lock    # Cargo workspace configuration
├── justfile / Makefile        # Top-level cross-platform orchestration runners
├── README.md                  # Project overview, quick start, and test metrics
├── SECURITY.md                # Responsible vulnerability disclosure policy
├── CONTRIBUTING.md            # Contribution guidelines, denylist rules, and style guide
├── CODE_OF_CONDUCT.md         # Contributor Covenant v2.1 code of conduct
├── CHANGELOG.md               # Keep a Changelog release notes (v0.1.0)
├── AUTHORS.md                 # Maintainers and contributors list
├── CITATION.cff               # Academic citation metadata (CFF v1.2.0)
├── LICENSE                    # Apache License 2.0 full text
├── .editorconfig              # Editor indentation and line-ending rules
├── .gitattributes             # Git line ending normalization and binary rules
└── .gitignore                 # Artifact, build directory, and secret ignore rules
```
