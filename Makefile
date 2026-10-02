# ==============================================================================
# JOCKY top-level build orchestration (make fallback)
#
# Purpose: Equivalent of the justfile for environments without `just`.
#          Run `make help` to list targets.
# Blueprint: Section 4 CI/CD Polymorphism & Attestation.
#
# On Windows use `make` from a POSIX shell (Git Bash / MSYS) or invoke the
# PowerShell scripts in ci/ps directly; a native nmake cannot run these rules.
# ==============================================================================

SHELL := /bin/bash

SOURCE_JKY   ?= scratch/min.jky
OUT_DIR      ?= dist
VARIANTS     ?= 3
BASE_SEED    ?= 1000
PRIVATE_KEY  ?= scratch/test.key
PUBLIC_KEY   ?= scratch/public.pub
VARIANT_JKM  ?= $(OUT_DIR)/variants/variant_1.jkm

# Windows detection: if pwsh is available we are on Windows.
UNAME_S := $(shell uname -s 2>/dev/null || echo Windows)

.PHONY: help build test diversify sign verify sbom hash py-check go-build all-checks clean

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
	@echo ""
	@echo "Detected platform: $(UNAME_S)"

build:
	cargo build --workspace

test:
	cargo test -p jockyc -- --nocapture

diversify:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File ci/ps/diversify.ps1 -Source $(SOURCE_JKY) -Count $(VARIANTS) -OutDir $(OUT_DIR)/variants -BaseSeed $(BASE_SEED)
else
	bash ci/diversify.sh --source $(SOURCE_JKY) --count $(VARIANTS) --out-dir $(OUT_DIR)/variants --base-seed $(BASE_SEED)
endif

sign:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File ci/ps/sign.ps1 -Input $(VARIANT_JKM) -Key $(PRIVATE_KEY)
else
	bash ci/sign.sh --input $(VARIANT_JKM) --key $(PRIVATE_KEY)
endif

verify:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File ci/ps/verify.ps1 -Input $(VARIANT_JKM) -PubKey $(PUBLIC_KEY)
else
	bash ci/verify.sh --input $(VARIANT_JKM) --pubkey $(PUBLIC_KEY)
endif

sbom:
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File ci/ps/sbom.ps1 -Artifact $(VARIANT_JKM)
else
	bash ci/sbom.sh --artifact $(VARIANT_JKM)
endif

hash:
	python ci/py/hash.py $(SOURCE_JKY)

py-check:
	python -m py_compile ci/py/__init__.py ci/py/hash.py ci/py/sbom.py ci/py/registry.py

go-build:
	cd ci/go && go build ./... && go vet ./...
	cd manager/go && go build ./... && go vet ./...

all-checks: build test py-check go-build
	@echo "[OK] all locally-runnable checks passed"

clean:
	rm -rf $(OUT_DIR)
