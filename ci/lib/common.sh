#!/usr/bin/env bash
# ==============================================================================
# JOCKY CI Common Shell Library (common.sh)
#
# Purpose:
#   Provides shared logging primitives, exit code constants, error handling traps,
#   and environment validation routines for JOCKY Linux/macOS CI shell scripts.
#
# Requirements:
#   Requires bash 5+. Runs on Linux/macOS. Windows: syntax check only.
#
# Inputs:
#   Source inclusion: `source "$(dirname "${BASH_SOURCE[0]}")/common.sh"` or via ci/lib.
#
# Outputs:
#   Formatted ANSI color log messages to stdout/stderr.
#
# Exit Codes:
#   0 - Success.
#   1 - Invalid arguments or generic failure.
#   2 - Build failure.
#   3 - Verification / attestation failure.
#
# Blueprint Section:
#   §4 CI/CD Polymorphism & Attestation; §0.4 Binary Diversification.
# ==============================================================================

# Standard Exit Codes
readonly EXIT_SUCCESS=0
readonly EXIT_INVALID_ARGS=1
readonly EXIT_BUILD_FAILED=2
readonly EXIT_VERIFY_FAILED=3

# Color definitions (disabled if NO_COLOR is set or non-tty)
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    readonly C_RESET='\033[0m'
    readonly C_RED='\033[0;31m'
    readonly C_GREEN='\033[0;32m'
    readonly C_YELLOW='\033[0;33m'
    readonly C_BLUE='\033[0;34m'
    readonly C_BOLD='\033[1m'
else
    readonly C_RESET=''
    readonly C_RED=''
    readonly C_GREEN=''
    readonly C_YELLOW=''
    readonly C_BLUE=''
    readonly C_BOLD=''
fi

log_info() {
    printf "${C_BLUE}[INFO]${C_RESET} %s\n" "$*"
}

log_success() {
    printf "${C_GREEN}[OK]${C_RESET} %s\n" "$*"
}

log_warn() {
    printf "${C_YELLOW}[WARN]${C_RESET} %s\n" "$*" >&2
}

log_error() {
    printf "${C_RED}[ERROR]${C_RESET} %s\n" "$*" >&2
}

log_fatal() {
    log_error "$*"
    exit "${EXIT_INVALID_ARGS}"
}

check_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        log_fatal "Required tool '${cmd}' is not installed or not in PATH."
    fi
}
