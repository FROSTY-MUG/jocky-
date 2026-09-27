# Environment & Toolchain Setup

This document records the exact, verified development environment required to build, test, and diversify JOCKY modules across Windows and Linux.

---

## 1. Windows Host Setup (Current Machine)

The current development environment is Windows 11 x64. Because LLVM 17 cannot link on Windows when installed from generic binary installers, an isolated **conda-forge `llvm17` environment** is used.

### Mandatory Environment Variables (PowerShell)
Execute this block in every PowerShell session prior to building:

```powershell
$llvmRoot = "C:\Users\Aryan\miniconda3\envs\llvm17\Library"
$goRoot   = "C:\Program Files\Go\bin"
$cmakeDir = "C:\vcpkg\downloads\tools\cmake-4.4.3-windows\cmake-4.4.3-windows-x86_64\bin"

$env:LLVM_SYS_170_PREFIX = $llvmRoot
$env:Path = "$llvmRoot\bin;$goRoot;$cmakeDir;" + $env:Path

# Verify LLVM 17 toolchain
llvm-config --version
# Expected: 17.0.6
```

### Critical Linker Inputs (One-Time Setup)
When LLVM 17 static libraries link with MSVC `link.exe`, the linker requires `z.lib` and `zstd.dll.lib`. These have already been copied into the environment's lib directory:
```powershell
# Verified location of dependencies:
Test-Path "C:\Users\Aryan\miniconda3\envs\llvm17\Library\lib\z.lib"        # True
Test-Path "C:\Users\Aryan\miniconda3\envs\llvm17\Library\lib\zstd.dll.lib" # True
```

### Installed Tooling Versions
- **Rust**: 1.86.0-nightly (`rustc`, `cargo`)
- **LLVM**: 17.0.6 (conda-forge `llvmdev` in `llvm17` env)
- **Go**: go1.27.0 windows/amd64 (`C:\Program Files\Go\bin\go.exe`)
- **Python**: 3.14.7 (`C:\Users\Aryan\miniconda3\python.exe`) with `blake3` (1.0.9) and `ciborium`
- **CMake**: 4.4.3 (`C:\vcpkg\downloads\tools\cmake-4.4.3-windows\cmake-4.4.3-windows-x86_64\bin\cmake.exe`)
- **MSVC**: Visual Studio 2019 Build Tools (v142 toolset, x64)
- **Just**: 1.58.0 (`C:\Users\Aryan\miniconda3\envs\llvm17\Library\bin\just.exe`)
- **Bash**: GNU Bash 5.2.37 (Git for Windows at `C:\Program Files\Git\bin\bash.exe`)
- **PowerShell**: Windows PowerShell 5.1 with `pwsh.cmd` shim redirecting to `powershell.exe`

---

## 2. Linux Setup (Ubuntu 22.04 / 24.04 / CI)

### Toolchain Installation
```bash
sudo apt-get update
sudo apt-get install -y \
    llvm-17-dev \
    clang-17 \
    libclang-17-dev \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    golang-go \
    python3 \
    python3-pip \
    make

export LLVM_SYS_170_PREFIX=/usr/lib/llvm-17
```

### Rust Setup
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable
```

---

## 3. macOS Setup (For Swift Agent)

Requires macOS 13+ with Xcode 15+ installed.
```bash
brew install llvm@17 go python@3.11 just
export LLVM_SYS_170_PREFIX="$(brew --prefix llvm@17)"
```

---

## 4. Verification Smoke Test

Run the five-minute smoke test to verify all toolchains:

```powershell
# 1. Rust workspace build & test
cargo build --workspace
cargo test -p jockyc --test diversify_test -- --nocapture

# 2. Go tooling build
cd ci/go; go build ./...; cd ../..

# 3. Python tooling compilation
python -m py_compile ci/py/hash.py ci/py/sbom.py ci/py/registry.py

# 4. Justfile recipes list
just --list
```
If all four steps exit 0, the environment is fully operational.
