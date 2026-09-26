import sys
import json
import hashlib
import datetime

def register_build(build_id, file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    file_hash = hashlib.sha256(content).hexdigest()
    
    registry_entry = {
        "build_id": build_id,
        "binary_hash": file_hash,
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "attested": True
    }
    print(f"[REGISTRY] Registered binary hash {file_hash} for build {build_id}")
    return registry_entry

if __name__ == "__main__":
    if len(sys.argv) > 2:
        register_build(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python registry.py <build_id> <binary_path>")
