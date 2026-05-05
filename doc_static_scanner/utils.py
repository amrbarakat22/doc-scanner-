from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def local_timestamp_for_path() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_bytes_limited(path: Path, limit: int | None = None) -> bytes:
    if limit is None:
        return path.read_bytes()
    with path.open("rb") as handle:
        return handle.read(limit)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True, default=str), encoding="utf-8")


def truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return text[:max_chars] + f"\n\n[truncated: {omitted} characters omitted from preview]"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def entropy_interpretation(entropy: float) -> str:
    if entropy < 3.5:
        return "low"
    if entropy < 7.0:
        return "normal"
    if entropy < 7.5:
        return "high"
    return "very high; possibly packed, encrypted, or compressed"


def safe_preview_bytes(data: bytes, length: int = 16) -> str:
    return data[:length].hex(" ")


def dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        key = item.casefold()
        if key not in seen:
            seen.add(key)
            output.append(item)
    return output

