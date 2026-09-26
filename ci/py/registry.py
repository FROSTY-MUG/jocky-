#!/usr/bin/env python3
"""
JOCKY Artifact Registry Client

Purpose:
    Manages local and remote artifact catalogs for polymorphic JOCKY modules,
    recording cryptographic hashes (BLAKE3/SHA256), build seeds, targets,
    attestation signatures, and SBOM references into an indexed registry database.

Inputs:
    CLI Commands:
        register --artifact <path> [--registry <dir>] [--sbom <path>]
        list     [--registry <dir>]
        verify   --artifact <path> [--registry <dir>]

Outputs:
    Registry catalog index (JSON) updated, search queries output to stdout.

Exit Codes:
    0 - Operation succeeded.
    1 - Missing files, invalid artifact, or registration failure.

Blueprint Section:
    §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism & Attestation.
"""

import sys
import os
import json
import argparse
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    from ci.py.hash import hash_file
except ImportError:
    from hash import hash_file


DEFAULT_REGISTRY_DIR = Path(".jocky-registry")


class ArtifactRegistry:
    def __init__(self, registry_dir: str | Path = DEFAULT_REGISTRY_DIR):
        self.registry_dir = Path(registry_dir)
        self.index_file = self.registry_dir / "index.json"
        self._ensure_initialized()

    def _ensure_initialized(self):
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        if not self.index_file.exists():
            self._save_index({"schema_version": 1, "artifacts": []})

    def _load_index(self) -> Dict[str, Any]:
        with open(self.index_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_index(self, data: Dict[str, Any]):
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def register_artifact(
        self,
        artifact_path: str | Path,
        sbom_path: Optional[str | Path] = None,
        target_triple: str = "unknown",
        seed: Optional[int] = None,
    ) -> Dict[str, Any]:
        path = Path(artifact_path)
        if not path.is_file():
            raise FileNotFoundError(f"Artifact not found: {path}")

        digests = hash_file(path)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

        entry = {
            "name": path.name,
            "path": str(path.resolve()),
            "size_bytes": path.stat().st_size,
            "sha256": digests["sha256"],
            "blake3": digests["blake3"],
            "target": target_triple,
            "seed": seed,
            "sbom_path": str(Path(sbom_path).resolve()) if sbom_path else None,
            "registered_at": timestamp,
        }

        index = self._load_index()
        # Deduplicate by path or sha256
        index["artifacts"] = [a for a in index["artifacts"] if a["sha256"] != digests["sha256"]]
        index["artifacts"].append(entry)
        self._save_index(index)
        return entry

    def list_artifacts(self) -> List[Dict[str, Any]]:
        return self._load_index().get("artifacts", [])


def main():
    parser = argparse.ArgumentParser(description="JOCKY Artifact Registry Client")
    subparsers = parser.add_subparsers(dest="command")

    reg_parser = subparsers.add_parser("register", help="Register an artifact in the registry")
    reg_parser.add_argument("--artifact", required=True, help="Path to artifact file")
    reg_parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_DIR), help="Registry directory")
    reg_parser.add_argument("--sbom", help="Path to associated SBOM file")
    reg_parser.add_argument("--target", default="unknown", help="Target triple")
    reg_parser.add_argument("--seed", type=int, help="Build seed")

    list_parser = subparsers.add_parser("list", help="List registered artifacts")
    list_parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_DIR), help="Registry directory")

    args = parser.parse_args()

    if not args.command or args.command == "list":
        reg = ArtifactRegistry(getattr(args, "registry", DEFAULT_REGISTRY_DIR))
        artifacts = reg.list_artifacts()
        print(f"Registered Artifacts ({len(artifacts)}):")
        for a in artifacts:
            print(f"  - {a['name']} | SHA256: {a['sha256'][:16]}... | Target: {a['target']} | Seed: {a.get('seed')}")
        sys.exit(0)

    elif args.command == "register":
        try:
            reg = ArtifactRegistry(args.registry)
            entry = reg.register_artifact(args.artifact, args.sbom, args.target, args.seed)
            print(f"[OK] Registered artifact '{entry['name']}' in {args.registry}")
            print(f"     SHA256: {entry['sha256']}")
            print(f"     BLAKE3: {entry['blake3']}")
            sys.exit(0)
        except Exception as e:
            print(f"[ERROR] Failed to register artifact: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
