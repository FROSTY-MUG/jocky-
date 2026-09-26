// swift-tools-version:5.9
// ==============================================================================
// JOCKY macOS Agent - Swift Package manifest
//
// Purpose:   Declares the JOCKY macOS agent executable target.
// Blueprint: Section 3 Agent Runtime (STEP 2B scaffold).
//
// Required environment: macOS 13+ with Xcode 15+ and the Swift 5.9 toolchain.
// This package CANNOT be built on Windows - the Swift toolchain is provided by
// Apple for macOS only. Verification is deferred to the macOS CI runner.
// ==============================================================================

import PackageDescription

let package = Package(
    name: "JockyAgent",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "jocky-agent-macos", targets: ["JockyAgent"])
    ],
    targets: [
        .executableTarget(
            name: "JockyAgent",
            path: "Sources/JockyAgent"
        )
    ]
)
