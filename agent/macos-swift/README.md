# JOCKY macOS Agent (Swift)

STEP 2B scaffold for the native macOS agent. It declares a valid Swift package
and contains an entry point that prints its version — no agent logic, which is
deferred to STEP 3.

## What is here

| Path | Purpose |
|---|---|
| `Package.swift` | SwiftPM manifest, macOS 13+ platform, tools version 5.9. |
| `Sources/JockyAgent/main.swift` | Entry point. Prints name/version, exits 0. |

## Required environment — macOS only

This package **cannot be built or verified on Windows or Linux**. The Swift
toolchain is distributed by Apple for macOS only; there is no `swift` compiler
for Windows.

To build and verify on macOS 13+ with Xcode 15+:

```bash
swift build
swift run jocky-agent-macos --version
```

Expected: `jocky-agent-macos 0.1.0`, exit code 0.

## Why Swift

EndpointSecurity — the framework macOS requires for legitimate security
product visibility — has an Objective-C/Swift API surface. Swift is the
supported binding language and is what Apple documents for new products.

## Status

SCAFFOLD — written and reviewed, not compiled in this environment (requires
macOS 13+ with Xcode 15+). EndpointSecurity client lands in STEP 3.
