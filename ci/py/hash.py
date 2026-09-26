#!/usr/bin/env python3
"""
JOCKY Artifact Cryptographic Hasher (BLAKE3 + SHA-256)

Purpose:
    Computes cryptographic digests (BLAKE3 and SHA-256) for compiled JOCKY
    artifacts (.jkm, .o, .obj) to support supply chain attestation and SBOM verification.

Inputs:
    CLI Argument: Path to target artifact file.
    API Argument: filepath (str or Path).

Outputs:
    CLI stdout:
        BLAKE3: <hex_digest>
        SHA256: <hex_digest>
    API: Dict[str, str] with keys 'blake3' and 'sha256'.

Exit Codes:
    0 - Successfully hashed file.
    1 - File not found, unreadable, or invalid CLI arguments.

Blueprint Section:
    §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism & Attestation.
"""

import sys
import os
import hashlib
from pathlib import Path
from typing import Dict

try:
    import blake3
except ImportError:
    blake3 = None


def hash_file(filepath: str | Path) -> Dict[str, str]:
    """Compute BLAKE3 and SHA-256 digests for the given file."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Artifact not found: {path}")

    sha256_hasher = hashlib.sha256()
    b3_hasher = blake3.blake3() if blake3 is not None else None

    with open(path, "rb") as f:
        while chunk := f.read(65536):
            sha256_hasher.update(chunk)
            if b3_hasher is not None:
                b3_hasher.update(chunk)

    sha256_digest = sha256_hasher.hexdigest()
    blake3_digest = b3_hasher.hexdigest() if b3_hasher is not None else "unavailable (blake3 missing)"

    return {
        "sha256": sha256_digest,
        "blake3": blake3_digest,
    }


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(f"Usage: {sys.argv[0]} <path-to-artifact>")
        sys.exit(0 if len(sys.argv) >= 2 and sys.argv[1] in ("-h", "--help") else 1)

    target_path = Path(sys.argv[1])
    try:
        digests = hash_file(target_path)
        print(f"BLAKE3: {digests['blake3']}")
        print(f"SHA256: {digests['sha256']}")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Failed to hash {target_path}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
