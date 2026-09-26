# ==============================================================================
# JOCKY top-level build orchestration
#
# Purpose: Single entry point that dispatches to the correct per-platform
#          script. Use `just --list` (or `make help`) to see every target.
# Blueprint: Section 4 CI/CD Polymorphism & Attestation.
#
# Platform note:
#   - On Linux/macOS this dispatches to the bash scripts in ci/.
#   - On Windows this dispatches to the PowerShell scripts in ci/ps/.
#   The `os` variable below is set by `just` automatically.
# ==============================================================================

export LLVM_SYS_170_PREFIX := env_var_or_default("LLVM_SYS_170_PREFIX", "")
export PATH := justfile_directory() / ".tools" / "go" / "bin" + ":" + env_var_or_default("PATH", "/usr/bin:/bin")

os := os()

# --- shared variables ---------------------------------------------------------
source_jky    := "scratch/min.jky"
out_dir       := "dist"
variants      := "3"
base_seed     := "1000"
target_linux  := "x86_64-unknown-linux-gnu"
target_win    := "x86_64-pc-windows-msvc"
private_key   := "scratch/test.key"
public_key    := "scratch/test.pub"

# Show the available targets (GATE 14).
default:
    @just --list

# Print this help text when make is used instead of just.
help:
    @echo "JOCKY build targets:"
    @echo "  test           Run the full Rust test suite"
    @echo "  build          Build the whole Cargo workspace"
    @echo "  diversify      Emit N diversified .jkm variants"
    @echo "  sign           Sign a built .jkm with the Ed25519 key"
    @echo "  verify         Verify a signed .jkm against a public key"
    @echo "  sbom           Generate an SPDX 2.3 SBOM for an artifact"
    @echo "  hash           Print BLAKE3 + SHA-256 digests of an artifact"
    @echo "  go-build       Build and vet the Go tooling"
    @echo "  py-check       Byte-compile the Python tooling"
    @echo "  all-checks     Run every verification gate available here"

# --- Rust ---------------------------------------------------------------------
build:
    cargo build --workspace

test:
    cargo test -p jockyc -- --nocapture

# --- diversification / signing (platform dispatch) ----------------------------
diversify:
    @if [ "{{ os }}" = "windows" ]; then \
        pwsh -NoProfile -File ci/ps/diversify.ps1 -Source {{ source_jky }} -Count {{ variants }} -OutDir {{ out_dir }}/variants -BaseSeed {{ base_seed }}; \
    else \
        bash ci/diversify.sh --source {{ source_jky }} --count {{ variants }} --out-dir {{ out_dir }}/variants --base-seed {{ base_seed }}; \
    fi

sign:
    @if [ "{{ os }}" = "windows" ]; then \
        pwsh -NoProfile -File ci/ps/sign.ps1 -Input {{ out_dir }}/variants/variant_1.jkm -Key {{ private_key }}; \
    else \
        bash ci/sign.sh --input {{ out_dir }}/variants/variant_1.jkm --key {{ private_key }}; \
    fi

verify:
    @if [ "{{ os }}" = "windows" ]; then \
        pwsh -NoProfile -File ci/ps/verify.ps1 -Input {{ out_dir }}/variants/variant_1.jkm -PubKey {{ public_key }}; \
    else \
        bash ci/verify.sh --input {{ out_dir }}/variants/variant_1.jkm --pubkey {{ public_key }}; \
    fi

sbom:
    @if [ "{{ os }}" = "windows" ]; then \
        pwsh -NoProfile -File ci/ps/sbom.ps1 -Artifact {{ out_dir }}/variants/variant_1.jkm; \
    else \
        bash ci/sbom.sh --artifact {{ out_dir }}/variants/variant_1.jkm; \
    fi

# --- Python / Go toolchains ----------------------------------------------------
hash artifact=source_jky:
    python ci/py/hash.py {{ artifact }}

py-check:
    python -m py_compile ci/py/__init__.py ci/py/hash.py ci/py/sbom.py ci/py/registry.py

go-build:
    cd ci/go && go build ./... && go vet ./...
    cd manager/go && go build ./... && go vet ./...

# --- aggregate -----------------------------------------------------------------
all-checks: build test py-check go-build
    @echo "[OK] all locally-runnable checks passed"
