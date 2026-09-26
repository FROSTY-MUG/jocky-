// ==============================================================================
// JOCKY Windows Agent - entry point (STEP 2B scaffold)
//
// Purpose:
//   Placeholder entry point for the native Windows agent. It reports the
//   agent name and version and exits successfully. No detection, collection,
//   or enforcement logic lives here - that is deliberately deferred to STEP 3.
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
// Blueprint Section:
//   Section 3 Agent Runtime (STEP 2B scaffold).
// ==============================================================================

#include <iostream>
#include <string>
#include <string_view>

#ifndef JOCKY_AGENT_VERSION
#define JOCKY_AGENT_VERSION "0.0.0"
#endif

#ifndef JOCKY_AGENT_NAME
#define JOCKY_AGENT_NAME "jocky-agent-win"
#endif

namespace {

void PrintVersion() {
    std::cout << JOCKY_AGENT_NAME << " " << JOCKY_AGENT_VERSION << '\n';
}

void PrintUsage(std::string_view program) {
    std::cout << "Usage: " << program << " [OPTIONS]\n"
              << "\n"
              << "JOCKY Windows agent (STEP 2B scaffold).\n"
              << "\n"
              << "Options:\n"
              << "  -v, --version   Print the agent version and exit.\n"
              << "  -h, --help      Print this help message and exit.\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::string program = (argc > 0 && argv[0] != nullptr)
                                    ? std::string(argv[0])
                                    : std::string(JOCKY_AGENT_NAME);

    if (argc > 1) {
        const std::string_view arg = argv[1];
        if (arg == "-v" || arg == "--version") {
            PrintVersion();
            return 0;
        }
        if (arg == "-h" || arg == "--help") {
            PrintUsage(program);
            return 0;
        }
        std::cerr << "error: unrecognised argument: " << arg << "\n\n";
        PrintUsage(program);
        return 1;
    }

    PrintVersion();
    return 0;
}
