# Contributing to JOCKY

Thank you for your interest in contributing to JOCKY! We welcome contributions that advance our defensive digital forensics and incident response (DFIR) mission.

---

## 1. Code of Conduct

All contributors and participants are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). Please report unacceptable behavior through our security contact channel.

---

## 2. Before You Contribute

Before writing code or proposing changes:

1. Review the architecture and non-goals in [docs/00-blueprint.md](docs/00-blueprint.md).
2. Read the project security guidelines in [SECURITY.md](SECURITY.md).
3. Confirm that your proposed change adheres to our defensive-only mandate.

---

## 3. What We Welcome

- **Defensive Forensic Primitives**: Validated evidence collection routines (memory artifact scanners, registry inspectors, event log parsers) with full test coverage.
- **Forensic Detection Scripts**: Real-world DFIR detection routines added to `stdlib/jocky/` (e.g., detecting BYOVD driver exploitation, process injection anomalies).
- **Tooling & Infrastructure**: Enhancements to the multi-language CI toolchain, reproducible build pipelines, or SBOM generators.
- **Documentation & Verification**: Fixes to technical documentation, additional negative test cases, or grammar clarifications.

---

## 4. What We Will NOT Accept

To maintain the project's strict defensive posture:

- **No Offensive Capabilities**: Pull requests attempting to implement process injection, credential dumping, lateral movement, persistence, or rootkits will be closed immediately.
- **No Denylist Weakening**: Any PR that modifies, bypasses, or removes primitives from the 23-primitive capability denylist will be rejected.
- **No Consent Bypasses**: Pull requests weakening signature verification, container checksums, or consent token validation will not be merged.
- **No External Targeting**: Test cases must never target third-party systems or public networks.

---

## 5. Development Setup & Testing

### Toolchain Prerequisites

- **Rust 1.80+** with `cargo` and `rustc`.
- **LLVM 17**:
  - Windows: Conda-forge `llvmdev` in the `llvm17` environment.

    ```powershell
    $env:LLVM_SYS_170_PREFIX = "$HOME\miniconda3\envs\llvm17\Library" # Or your LLVM 17 install path
    $env:Path = "$env:LLVM_SYS_170_PREFIX\bin;" + $env:Path
    ```

  - Linux: `sudo apt-get install llvm-17-dev clang-17`
- **Go 1.22+**, **Node.js 18+**, and **Python 3.10+** (with `blake3`).

### Running the Test Suite

```bash
cargo build --workspace
cargo test -p jockyc -- --nocapture
```

All 110+ unit, integration, and codegen tests must pass before submitting a pull request.

---

## 6. Code Style Standards

- **Rust**: Format with `cargo fmt`. Check with `cargo clippy --workspace -- -D warnings`.
- **Go**: Format with `gofmt -s -w .`. Check with `go vet ./...`.
- **Python**: Follow PEP 8 guidelines. Verify with `python -m py_compile`.
- **Bash / POSIX**: Syntax-checked with `bash -n`. Lint with `shellcheck`.
- **PowerShell**: Adhere to CmdletBinding standards and script parameter conventions.

---

## 7. Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```text
<type>(<scope>): <short description>

[optional body explaining technical rationale]
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`.

---

## 8. Pull Request Workflow

1. Fork the repository and create a feature branch from `main`.
2. Keep pull requests focused on a single logical change.
3. Include new test fixtures for any new language features or stdlib scripts.
4. Fill out the [Pull Request Template](.github/PULL_REQUEST_TEMPLATE.md) completely, including test verification output.
5. Ensure all CI workflow checks pass cleanly.
