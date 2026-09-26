# JOCKY Windows Agent (C++)

STEP 2B scaffold for the native Windows agent. It builds and runs, but contains
no agent logic — detection, collection, and enforcement are deferred to STEP 3.

## What is here

| Path | Purpose |
|---|---|
| `CMakeLists.txt` | Build definition (CMake 3.20+, C++20). |
| `src/main.cpp` | Entry point. Prints name/version, exits 0. |

## Build and verify

Requires Windows, CMake 3.20+, and MSVC (Visual Studio 2019+ Build Tools or
full Visual Studio).

```powershell
cmake -S agent/windows-cpp -B agent/windows-cpp/build -G "Visual Studio 16 2019" -A x64
cmake --build agent/windows-cpp/build --config Release
.\agent\windows-cpp\build\Release\jocky-agent-win.exe --version
```

Expected: `jocky-agent-win 0.1.0`, exit code 0.

If `cmake` is not on PATH, use the vcpkg-downloaded copy:
`C:\vcpkg\downloads\tools\cmake-<version>-windows\...\bin\cmake.exe`.

## Why C++

The Windows agent needs Win32 ETW consumers and native handle/process
enumeration, which have no first-class Rust or Go bindings. C++ with MSVC is the
only option that links directly against the platform SDK for those APIs.

## Status

SCAFFOLD — builds and runs; agent logic lands in STEP 3.
