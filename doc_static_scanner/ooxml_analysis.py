from __future__ import annotations

import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any


def analyze_ooxml(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "is_zip": False,
        "is_ooxml": False,
        "entries": [],
        "vba_projects": [],
        "external_links": [],
        "embeddings": [],
        "activex": [],
        "custom_xml": [],
        "external_relationships": [],
        "errors": [],
    }
    if not zipfile.is_zipfile(path):
        return result
    result["is_zip"] = True
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            result["is_ooxml"] = "[Content_Types].xml" in names and any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names
            )
            for info in archive.infolist():
                entry = {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                }
                result["entries"].append(entry)
                lower = info.filename.lower()
                if lower.endswith("vbaproject.bin"):
                    result["vba_projects"].append(entry)
                if "externallinks/" in lower:
                    result["external_links"].append(entry)
                if "embeddings/" in lower:
                    result["embeddings"].append(entry)
                if "activex/" in lower:
                    result["activex"].append(entry)
                if lower.startswith("customxml/"):
                    result["custom_xml"].append(entry)
                if lower.endswith(".rels"):
                    result["external_relationships"].extend(_extract_external_relationships(archive, info.filename))
    except Exception as exc:
        result["errors"].append(str(exc))
    return result


def _extract_external_relationships(archive: zipfile.ZipFile, name: str) -> list[dict[str, str]]:
    external: list[dict[str, str]] = []
    try:
        data = archive.read(name)
        root = ET.fromstring(data)
    except Exception:
        return external
    for rel in root:
        target_mode = rel.attrib.get("TargetMode", "")
        target = rel.attrib.get("Target", "")
        if target_mode.casefold() == "external" or target.lower().startswith(("http://", "https://", "file://", "\\\\")):
            external.append(
                {
                    "relationship_file": name,
                    "id": rel.attrib.get("Id", ""),
                    "type": rel.attrib.get("Type", ""),
                    "target": target,
                    "target_mode": target_mode,
                }
            )
    return external

