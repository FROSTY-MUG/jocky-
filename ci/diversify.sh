#!/usr/bin/env bash
# ==============================================================================
# JOCKY Polymorphic Diversification Runner (diversify.sh)
#
# Purpose:
#   Compiles a JOCKY source program (.jky) into N uniquely diversified,
#   cryptographically attested binary modules (.jkm) across distinct seeds.
#
# Requirements:
#   Requires bash 5+. Runs on Linux/macOS. Windows: syntax check only.
#
# Inputs:
#   --source <path>     : JOCKY source file path (.jky) [Required]
#   --count <N>         : Number of polymorphic variants to generate (default: 3)
#   --out-dir <path>    : Destination directory for generated .jkm files (default: dist/variants)
#   --target <triple>   : Target triple (default: x86_64-unknown-linux-gnu)
#   --base-seed <seed>  : Base integer seed for PRNG derivation (default: 1000)
#   --help, -h          : Show usage instructions
#
# Outputs:
#   Generated .jkm module files in output directory.
#
# Exit Codes:
#   0 - Successfully built all requested variants.
#   1 - Invalid arguments or missing prerequisites.
#   2 - Compiler failure during variant generation.
#
# Blueprint Section:
#   §0.4 Binary Diversification & Polymorphism; §4 CI/CD Polymorphism.
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
Usage: $(basename "$0") --source <path.jky> [options]

Options:
  --source <path>     Path to JOCKY source file (.jky) [Required]
  --count <N>         Number of variants to emit (default: 3)
  --out-dir <dir>     Output directory for .jkm files (default: dist/variants)
  --target <triple>   LLVM target triple (default: x86_64-unknown-linux-gnu)
  --base-seed <seed>  Starting seed integer (default: 1000)
  -h, --help          Display this help message and exit
EOF
}

SOURCE_FILE=""
COUNT=3
OUT_DIR="dist/variants"
TARGET="x86_64-unknown-linux-gnu"
BASE_SEED=1000

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --source)
            SOURCE_FILE="$2"
            shift 2
            ;;
        --count)
            COUNT="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --target)
            TARGET="$2"
            shift 2
            ;;
        --base-seed)
            BASE_SEED="$2"
            shift 2
            ;;
        *)
            log_error "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${SOURCE_FILE}" ]]; then
    log_error "Missing required option: --source <file.jky>"
    usage
    exit 1
fi

if [[ ! -f "${SOURCE_FILE}" ]]; then
    log_fatal "Source file not found: ${SOURCE_FILE}"
fi

mkdir -p "${OUT_DIR}"
STEM="$(basename "${SOURCE_FILE}" .jky)"

log_info "Generating ${COUNT} polymorphic variants for ${SOURCE_FILE} (Target: ${TARGET})..."

for ((i = 0; i < COUNT; i++)); do
    SEED=$((BASE_SEED + i))
    OUT_FILE="${OUT_DIR}/${STEM}_seed${SEED}.jkm"
    log_info "  -> Building variant $((i+1))/${COUNT} (seed: ${SEED}) => ${OUT_FILE}"

    cargo run --bin jockyc -- build "${SOURCE_FILE}" \
        --target "${TARGET}" \
        --seed "${SEED}" \
        --out "${OUT_FILE}"
done

log_success "Successfully generated ${COUNT} polymorphic variants in ${OUT_DIR}."
exit 0
EOF
