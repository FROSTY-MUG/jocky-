# JOCKY Windows Agent (C++20)

Native Windows DFIR agent runtime implementing in-process .jkm module execution, read-only host collectors, and kernel detection mechanisms under cryptographically enforced Ed25519 consent.

## Core Capabilities

- **Cryptographic Consent Enforcement**: Every operation and module execution requires an unexpired, Ed25519-signed consent token verified via the shared Rust C ABI (`jocky-common`).
- **Attested In-Process Module Execution**: .jkm container signature is verified before mapping. Code section is allocated with `PAGE_READWRITE`, copied, transitioned to `PAGE_EXECUTE_READ` (never RWX), executed in-process, and released with `VirtualFree`.
- **Read-Only Forensic Collectors**:
  - `processes`: Enumerates running processes using `NtQuerySystemInformation(SystemProcessInformation)` and `QueryFullProcessImageName` opened with `PROCESS_QUERY_LIMITED_INFORMATION`.
  - `network`: TCP and UDP connection tables via `GetExtendedTcpTable` / `GetExtendedUdpTable`.
  - `drivers`: Enumerates loaded drivers via `EnumDeviceDrivers` and computes SHA256 hashes via Windows BCrypt.
- **Defensive Detection Modules**:
  - `byovd`: Cross-references loaded kernel drivers against a bundled LOLDrivers blocklist (`loldrivers_subset.json`).
  - `inject`: Consumes real-time ETW events from `Microsoft-Windows-Kernel-Process` and `Microsoft-Windows-Threat-Intelligence` to detect suspicious memory modifications.

## Blue-Team Safety Guarantees

In accordance with strict safety constraints (C6, C7, C8, C9):
- **Read-only host access**: Opens process handles strictly with `PROCESS_QUERY_LIMITED_INFORMATION`. Never requests `PROCESS_ALL_ACCESS` or `PROCESS_VM_WRITE`.
- **No injection primitives**: Contains no remote thread creation, APC queuing, or cross-process memory writing.
- **In-process execution**: .jkm modules execute strictly within the agent's own process space. No cross-process memory mapping or temporary file dropping.
- **W^X Memory Protection**: Pages are allocated `PAGE_READWRITE`, populated, and protected as `PAGE_EXECUTE_READ`. RWX permissions are prohibited.
- **Audit Logging**: Any failed consent check writes a timestamped record to `%ProgramData%\JOCKY\audit.log` before terminating non-zero.

## Building

### Requirements
- Windows 10/11 or Windows Server 2019/2022 (x64)
- CMake 3.20+ (e.g. `C:\vcpkg\downloads\tools\cmake-4.4.3-windows\cmake-4.4.3-windows-x86_64\bin\cmake.exe`)
- Visual Studio 2019 / 2022 C++ Build Tools
- Rust toolchain (for building `jocky-common` cdylib)

### Build Commands
```powershell
# 1. Build Rust FFI library
cargo build -p jocky-common --release

# 2. Configure and build C++ Agent
cmake -S agent/windows-cpp -B agent/windows-cpp/build -G "Visual Studio 16 2019" -A x64
cmake --build agent/windows-cpp/build --config Release
```

The build automatically copies `jocky_common.dll` adjacent to `jocky-agent-win.exe` as a post-build step.

## CLI Usage

```powershell
# Check agent version
.\jocky-agent-win.exe --version

# Verify consent token from environment
$env:JOCKY_CONSENT_TOKEN = "<base64 CBOR/JSON token>"
$env:JOCKY_MANAGER_PUBKEY = "<base64 Ed25519 public key>"
.\jocky-agent-win.exe consent-check

# Run read-only collectors
.\jocky-agent-win.exe collect --mode processes
.\jocky-agent-win.exe collect --mode network
.\jocky-agent-win.exe collect --mode drivers

# Run detection modules
.\jocky-agent-win.exe detect --mode byovd
.\jocky-agent-win.exe detect --mode inject --duration 30

# Execute signed .jkm module
.\jocky-agent-win.exe run --module .\scratch\min.jkm
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Consent token missing, malformed, expired, or signature verification failed |
| `2` | Module .jkm container signature or format invalid |
| `3` | Host collector failed |
| `4` | Detection module failed |

## Running Tests

```powershell
# Run individual test executables
.\agent\windows-cpp\build\Release\test_consent.exe
.\agent\windows-cpp\build\Release\test_module_loader.exe
.\agent\windows-cpp\build\Release\test_collectors.exe
.\agent\windows-cpp\build\Release\test_byovd.exe
.\agent\windows-cpp\build\Release\test_inject.exe

# Or run all tests via CTest target
cmake --build agent/windows-cpp/build --config Release --target run_all_tests
```
