from __future__ import annotations

import mimetypes
import shutil
import subprocess
from pathlib import Path

from .utils import entropy_interpretation, read_bytes_limited, shannon_entropy, utc_iso


def collect_file_info(path: Path) -> dict[str, object]:
    resolved = path.resolve()
    stat = resolved.stat()
    python_mime = mimetypes.guess_type(str(resolved))[0] or "unknown"
    file_command = run_file_command(resolved)
    data = read_bytes_limited(resolved)
    entropy = shannon_entropy(data)
    return {
        "absolute_path": str(resolved),
        "file_name": resolved.name,
        "extension": resolved.suffix.lower(),
        "size_bytes": stat.st_size,
        "created_or_changed_time_utc": utc_iso(stat.st_ctime),
        "modified_time_utc": utc_iso(stat.st_mtime),
        "accessed_time_utc": utc_iso(stat.st_atime),
        "python_mime": python_mime,
        "file_command": file_command,
        "entropy": round(entropy, 4),
        "entropy_interpretation": entropy_interpretation(entropy),
    }


def run_file_command(path: Path) -> dict[str, object]:
    executable = shutil.which("file")
    if not executable:
        return {"installed": False, "status": "Not installed / skipped", "output": ""}
    try:
        proc = subprocess.run(
            [executable, "-b", "--mime-type", str(path)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"installed": True, "status": "Timed out", "output": ""}
    return {
        "installed": True,
        "status": "ok" if proc.returncode == 0 else f"exit {proc.returncode}",
        "output": proc.stdout.strip() or proc.stderr.strip(),
    }

