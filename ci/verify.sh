#!/usr/bin/env bash
# ==============================================================================
# JOCKY Container Attestation Verifier (verify.sh)
#
# Purpose:
#   Verifies the Ed25519 signature and structural integrity of a .jkm module
#   against a trusted public key, detecting byte-level tampering or forgery.
#
# Requirements:
#   Requires bash 5+. Runs on Linux/macOS. Windows: syntax check only.
#
# Inputs:
#   --container <path.jkm> : Path to the .jkm container to verify [Required]
#   --pubkey <path.pub>    : Path to the trusted Ed25519 public key [Required]
#   --verbose, -v          : Display full CBOR manifest and symbol map
#   --help, -h             : Show usage instructions
#
# Outputs:
#   Attestation verification report to stdout.
#
# Exit Codes:
#   0 - Signature valid and container integrity confirmed.
#   1 - Signature invalid, container tampered, or missing arguments.
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
Usage: $(basename "$0") --container <file.jkm> --pubkey <file.pub> [options]

Options:
  --container <file.jkm>  Path to .jkm container file [Required]
  --pubkey <file.pub>     Path to Ed25519 public key [Required]
  -v, --verbose           Print verbose manifest and symbol mappings
  -h, --help              Display this help message and exit
EOF
}

CONTAINER=""
PUBKEY=""
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --container)
            CONTAINER="$2"
            shift 2
            ;;
        --pubkey)
            PUBKEY="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${CONTAINER}" || -z "${PUBKEY}" ]]; then
    log_error "Missing required options: both --container and --pubkey are required."
    usage
    exit 1
fi

if [[ ! -f "${CONTAINER}" ]]; then
    log_fatal "Container file not found: ${CONTAINER}"
fi

if [[ ! -f "${PUBKEY}" ]]; then
    log_fatal "Public key file not found: ${PUBKEY}"
fi

log_info "Verifying container ${CONTAINER} against public key ${PUBKEY}..."

CMD=(cargo run --bin jocky-verify -- "${CONTAINER}" --pubkey "${PUBKEY}")
if [[ "${VERBOSE}" == "true" ]]; then
    CMD+=(--verbose)
fi

if "${CMD[@]}"; then
    log_success "Attestation verified successfully."
    exit 0
else
    log_error "Attestation verification FAILED. Container may be tampered or signature invalid."
    exit 1
fi
EOF
