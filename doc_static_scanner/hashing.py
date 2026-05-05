from __future__ import annotations

import hashlib
from pathlib import Path


def calculate_hashes(path: Path, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    hashers = {
        "md5": hashlib.md5(usedforsecurity=False),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            for hasher in hashers.values():
                hasher.update(chunk)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}

