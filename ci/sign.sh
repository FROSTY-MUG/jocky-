#!/usr/bin/env bash
# ==============================================================================
# JOCKY Module Ed25519 Signer (sign.sh)
#
# Purpose:
#   Signs compiled JOCKY .jkm modules with Ed25519 private keys to guarantee
#   tamper-evident provenance, supply chain attestation, and binary integrity.
#
# Requirements:
#   Requires bash 5+. Runs on Linux/macOS. Windows: syntax check only.
#
# Inputs:
#   --source <path.jky> : Source file to compile and sign
#   --key <path.key>    : Path to Ed25519 private key [Required]
#   --out <path.jkm>    : Path for signed container output
#   --target <triple>   : Compilation target triple (default: x86_64-unknown-linux-gnu)
#   --seed <integer>    : Seed for compilation (optional)
#   --keygen <path.key> : Generate a new keypair at this path and exit
#   --help, -h          : Show usage instructions
#
# Outputs:
#   Signed .jkm container or generated keypair files.
#
# Exit Codes:
#   0 - Successfully signed module or generated keys.
#   1 - Missing required arguments or file not found.
#   2 - Signing or compilation failure.
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
Usage: $(basename "$0") [options]

Signing Options:
  --source <file.jky> Path to JOCKY source code
  --key <file.key>    Path to Ed25519 private key
  --out <file.jkm>    Output path for signed .jkm module
  --target <triple>   Target architecture triple (default: x86_64-unknown-linux-gnu)
  --seed <seed>       Diversification seed (optional)

Keygen Options:
  --keygen <file.key> Generate new Ed25519 keypair and exit
  -h, --help          Display this help message and exit
EOF
}

SOURCE_FILE=""
KEY_FILE=""
OUT_FILE=""
TARGET="x86_64-unknown-linux-gnu"
SEED=""
KEYGEN_OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --keygen)
            KEYGEN_OUT="$2"
            shift 2
            ;;
        --source)
            SOURCE_FILE="$2"
            shift 2
            ;;
        --key)
            KEY_FILE="$2"
            shift 2
            ;;
        --out)
            OUT_FILE="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -n "${KEYGEN_OUT}" ]]; then
    log_info "Generating Ed25519 keypair at ${KEYGEN_OUT}..."
    cargo run --bin jockyc -- keygen --out "${KEYGEN_OUT}"
    log_success "Keypair generated successfully."
    exit 0
fi

if [[ -z "${SOURCE_FILE}" || -z "${KEY_FILE}" || -z "${OUT_FILE}" ]]; then
    log_error "Missing required options: --source, --key, and --out are all required for signing."
    usage
    exit 1
fi

if [[ ! -f "${SOURCE_FILE}" ]]; then
    log_fatal "Source file does not exist: ${SOURCE_FILE}"
fi

if [[ ! -f "${KEY_FILE}" ]]; then
    log_fatal "Private key file does not exist: ${KEY_FILE}"
fi

CMD=(cargo run --bin jockyc -- build "${SOURCE_FILE}" --target "${TARGET}" --sign --key "${KEY_FILE}" --out "${OUT_FILE}")

if [[ -n "${SEED}" ]]; then
    CMD+=(--seed "${SEED}")
fi

log_info "Compiling and signing ${SOURCE_FILE} -> ${OUT_FILE}..."
"${CMD[@]}"
log_success "Signed module created: ${OUT_FILE}"
exit 0
EOF
