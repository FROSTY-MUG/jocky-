#!/usr/bin/env bash
# ==============================================================================
# JOCKY SBOM Generation Tool (sbom.sh)
#
# Purpose:
#   Generates an SPDX 2.3 Software Bill of Materials (SBOM) in JSON format for
#   compiled JOCKY modules, recording BLAKE3 and SHA-256 hashes and toolchain info.
#
# Requirements:
#   Requires bash 5+. Runs on Linux/macOS. Windows: syntax check only.
#
# Inputs:
#   --artifact <file>   : Path to compiled artifact (.jkm, .o, .obj) [Required]
#   --output <file>     : Output path for SPDX JSON (default: stdout)
#   --name <str>        : Package name (default: jocky-module)
#   --version <str>     : Package version (default: 0.1.0)
#   --help, -h          : Show usage instructions
#
# Outputs:
#   SPDX 2.3 JSON written to the specified output or printed to stdout.
#
# Exit Codes:
#   0 - Successfully generated SBOM.
#   1 - Missing artifact or Python runtime error.
#
# Blueprint Section:
#   §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_COMMON="${SCRIPT_DIR}/lib/common.sh"

if [[ -f "${LIB_COMMON}" ]]; then
    # shellcheck source=lib/common.sh
    source "${LIB_COMMON}"
else
    log_info() { echo "[INFO] $*"; }
    log_success() { echo "[OK] $*"; }
    log_error() { echo "[ERROR] $*" >&2; }
    log_fatal() { echo "[FATAL] $*" >&2; exit 1; }
fi

usage() {
    cat <<EOF
Usage: $(basename "$0") --artifact <path> [options]

Options:
  --artifact <path>   Path to compiled binary artifact [Required]
  --output <path>     Output path for SPDX JSON (default: stdout)
  --name <str>        Package name (default: jocky-module)
  --version <str>     Package version (default: 0.1.0)
  -h, --help          Display this help message and exit
EOF
}

ARTIFACT=""
OUTPUT=""
NAME="jocky-module"
VERSION="0.1.0"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --artifact)
            ARTIFACT="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --name)
            NAME="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${ARTIFACT}" ]]; then
    log_error "Missing required option: --artifact <path>"
    usage
    exit 1
fi

if [[ ! -f "${ARTIFACT}" ]]; then
    log_fatal "Artifact not found: ${ARTIFACT}"
fi

PYTHON_CMD="python3"
if ! command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

SBOM_PY="${SCRIPT_DIR}/py/sbom.py"

CMD=("${PYTHON_CMD}" "${SBOM_PY}" --artifact "${ARTIFACT}" --name "${NAME}" --version "${VERSION}")
if [[ -n "${OUTPUT}" ]]; then
    CMD+=(--output "${OUTPUT}")
fi

"${CMD[@]}"
exit 0
EOF
