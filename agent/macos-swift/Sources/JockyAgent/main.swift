// ==============================================================================
// JOCKY macOS Agent - entry point (STEP 2B scaffold)
//
// Purpose:
//   Placeholder entry point for the native macOS agent. It reports the agent
//   name and version and exits successfully. No EndpointSecurity, file
//   monitoring, or collection logic lives here - that is deliberately
//   deferred to STEP 3.
//
// Inputs:
//   --version, -v   Print the agent version and exit 0.
//   --help,   -h   Print this usage summary and exit 0.
//   (no arguments) Print the version banner and exit 0.
//
// Outputs:
//   Version / usage lines on stdout; usage errors on stderr.
//
// Exit Codes:
//   0 - Ran successfully (including --version and --help).
//   1 - Unrecognised argument.
//
// Required environment:
//   macOS 13+ with Xcode 15+. The Swift toolchain does not exist on Windows or
//   Linux, so `swift build` cannot be verified there.
//
// Blueprint Section:
//   Section 3 Agent Runtime (STEP 2B scaffold).
// ==============================================================================

import Foundation

let agentName = "jocky-agent-macos"
let agentVersion = "0.1.0"

func printVersion() {
    print("\(agentName) \(agentVersion)")
}

func printUsage(program: String) {
    print("""
    Usage: \(program) [OPTIONS]

    JOCKY macOS agent (STEP 2B scaffold).

    Options:
      -v, --version   Print the agent version and exit.
      -h, --help      Print this help message and exit.
    """)
}

let arguments = CommandLine.arguments
let program = arguments.first ?? agentName

if arguments.count > 1 {
    switch arguments[1] {
    case "-v", "--version":
        printVersion()
        exit(0)
    case "-h", "--help":
        printUsage(program: program)
        exit(0)
    default:
        FileHandle.standardError.write(
            Data("error: unrecognised argument: \(arguments[1])\n\n".utf8)
        )
        printUsage(program: program)
        exit(1)
    }
}

printVersion()
exit(0)
