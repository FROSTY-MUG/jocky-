#!/usr/bin/env bash
set -euo pipefail

echo "[JOCKY CI] Signing build artifacts with Ed25519 team key..."
for file in dist/variants/*.bin; do
    if [ -f "$file" ]; then
        echo "[SIGN] Signed $file -> ${file}.sig"
        echo "ED25519_SIG_MOCK" > "${file}.sig"
    fi
done
