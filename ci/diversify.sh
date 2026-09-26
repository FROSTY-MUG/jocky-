#!/usr/bin/env bash
set -euo pipefail

SCRIPT="${1:-stdlib/jocky/process.jky}"
N="${2:-8}"
OUT="${3:-dist/variants}"

mkdir -p "$OUT"
rm -f "$OUT/hashes.txt"

echo "[JOCKY CI] Generating $N polymorphic variants for script: $SCRIPT"

for i in $(seq 1 "$N"); do
    SEED=$(openssl rand -hex 8 2>/dev/null || echo "$RANDOM$RANDOM")
    echo "[BUILD] Variant $i (Seed: $SEED)"
    # Execution driver stub for jockyc build
    echo "variant_${i}_seed_${SEED}" > "$OUT/variant_${i}.bin"
    sha256sum "$OUT/variant_${i}.bin" >> "$OUT/hashes.txt"
done

echo "[JOCKY CI] Unique binary hashes generated:"
cat "$OUT/hashes.txt"
