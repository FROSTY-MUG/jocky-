#!/usr/bin/env python3
"""
JOCKY Software Bill of Materials (SBOM) Generator (SPDX 2.3 JSON)

Purpose:
    Generates a formal, machine-readable Software Bill of Materials (SBOM) in SPDX 2.3
    JSON specification format, capturing cryptographic hashes, provenance, compiler
    version, and dependencies for JOCKY binary modules and packages.

Inputs:
    CLI Arguments:
        --artifact <path>: Compiled .jkm or binary object to catalog.
        --output <path>: Destination for SPDX JSON (default: stdout).
        --name <str>: Package/module name.
        --version <str>: Module/compiler version.

Outputs:
    SPDX 2.3 JSON document written to the specified output file or printed to stdout.

Exit Codes:
    0 - SBOM generated successfully.
    1 - Missing input files, schema errors, or I/O failure.

Blueprint Section:
    §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism & Attestation.
"""

import sys
import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from ci.py.hash import hash_file
except ImportError:
    from hash import hash_file


def generate_spdx_sbom(
    artifact_path: str | Path,
    package_name: str = "jocky-module",
    version: str = "0.1.0",
    supplier: str = "Organization: FROSTY-MUG",
) -> Dict[str, Any]:
    """Generate SPDX 2.3 JSON structure for a compiled JOCKY artifact."""
    path = Path(artifact_path)
    if not path.is_file():
        raise FileNotFoundError(f"Artifact not found: {path}")

    digests = hash_file(path)
    file_size = path.stat().st_size
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{package_name}-sbom",
        "documentNamespace": f"https://github.com/FROSTY-MUG/jocky/spdx/{uuid.uuid4()}",
        "creationInfo": {
            "created": timestamp,
            "creators": [
                supplier,
                "Tool: jocky-sbom-0.1.0"
            ],
            "licenseListVersion": "3.20"
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-JOCKY",
                "name": package_name,
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "supplier": supplier,
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": digests["sha256"]
                    }
                ],
                "description": "JOCKY DFIR compiled binary module with polymorphic attestation"
            }
        ],
        "files": [
            {
                "SPDXID": f"SPDXRef-File-{path.name}",
                "fileName": path.name,
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": digests["sha256"]
                    },
                    {
                        "algorithm": "BLAKE3",
                        "checksumValue": digests["blake3"]
                    }
                ],
                "licenseConcluded": "Apache-2.0",
                "fileTypes": ["BINARY", "APPLICATION"]
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-JOCKY"
            },
            {
                "spdxElementId": "SPDXRef-Package-JOCKY",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": f"SPDXRef-File-{path.name}"
            }
        ]
    }
    return spdx_doc


def main():
    import argparse
    parser = argparse.ArgumentParser(description="JOCKY SPDX 2.3 SBOM Generator")
    parser.add_argument("--artifact", required=True, help="Path to compiled artifact (.jkm, .o, .obj)")
    parser.add_argument("--output", "-o", help="Output file path for SPDX JSON (default: stdout)")
    parser.add_argument("--name", default="jocky-module", help="Package name")
    parser.add_argument("--version", default="0.1.0", help="Package version")

    args = parser.parse_args()

    try:
        sbom = generate_spdx_sbom(args.artifact, args.name, args.version)
        sbom_str = json.dumps(sbom, indent=2)
        if args.output:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(sbom_str, encoding="utf-8")
            print(f"[OK] SBOM written to {args.output}")
        else:
            print(sbom_str)
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Failed to generate SBOM: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
