from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import safe_preview_bytes

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MACRO_STREAM_MARKERS = ("vba", "dir", "project", "_vba_project")
EMBEDDED_MARKERS = ("oleobject", "embeddings", "package", "objectpool", "\x01ole")


def analyze_ole(path: Path) -> dict[str, Any]:
    header = path.read_bytes()[:8]
    result: dict[str, Any] = {
        "is_ole_magic": header == OLE_MAGIC,
        "olefile_available": False,
        "is_ole": False,
        "streams": [],
        "macro_related_streams": [],
        "embedded_object_indicators": [],
        "errors": [],
    }
    try:
        import olefile  # type: ignore
    except ImportError:
        result["errors"].append("olefile is not installed")
        return result

    result["olefile_available"] = True
    try:
        result["is_ole"] = bool(olefile.isOleFile(str(path)))
        if not result["is_ole"]:
            return result
        with olefile.OleFileIO(str(path)) as ole:
            for entry in ole.listdir(streams=True, storages=True):
                name = "/".join(entry)
                lower_name = name.lower()
                stream_info: dict[str, Any] = {
                    "name": name,
                    "path_parts": entry,
                    "size": None,
                    "first_bytes": "",
                    "is_stream": False,
                }
                try:
                    if ole.exists(entry):
                        stream = ole.openstream(entry)
                        first = stream.read(32)
                        stream_info["first_bytes"] = safe_preview_bytes(first, 32)
                        stream_info["size"] = ole.get_size(entry)
                        stream_info["is_stream"] = True
                except Exception as exc:
                    stream_info["error"] = str(exc)
                result["streams"].append(stream_info)
                if any(marker in lower_name for marker in MACRO_STREAM_MARKERS):
                    result["macro_related_streams"].append(stream_info)
                if any(marker in lower_name for marker in EMBEDDED_MARKERS):
                    result["embedded_object_indicators"].append(stream_info)
    except Exception as exc:
        result["errors"].append(str(exc))
    return result

