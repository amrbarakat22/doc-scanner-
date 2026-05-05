from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .utils import dedupe_keep_order

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|top|xyz|online|site|io|co|uk|de|fr|it|nl|br|ir|in|su)\b", re.IGNORECASE)
WIN_PATH_RE = re.compile(r"\b[A-Z]:\\[^\r\n\t\"'<>|]+", re.IGNORECASE)
REGISTRY_RE = re.compile(r"\b(?:HKCU|HKLM|HKCR|HKU|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\r\n\t\"']+", re.IGNORECASE)
BASE64_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b")
SUSPICIOUS_EXES = (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
)


def extract_strings(path: Path, max_bytes: int | None = None) -> list[str]:
    data = path.read_bytes() if max_bytes is None else _read_limited(path, max_bytes)
    ascii_strings = [match.group().decode("utf-8", errors="replace") for match in ASCII_RE.finditer(data)]
    utf16_strings = _extract_utf16le_strings(data)
    return dedupe_keep_order(ascii_strings + utf16_strings)


def _read_limited(path: Path, max_bytes: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(max_bytes)


def _extract_utf16le_strings(data: bytes, min_chars: int = 4) -> list[str]:
    found: list[str] = []
    current = bytearray()
    for index in range(0, len(data) - 1, 2):
        char = data[index]
        nul = data[index + 1]
        if nul == 0 and 32 <= char <= 126:
            current.extend((char, nul))
        else:
            if len(current) >= min_chars * 2:
                found.append(current.decode("utf-16le", errors="replace"))
            current.clear()
    if len(current) >= min_chars * 2:
        found.append(current.decode("utf-16le", errors="replace"))
    return found


def extract_iocs(strings: list[str]) -> dict[str, list[str]]:
    joined = "\n".join(strings)
    urls = URL_RE.findall(joined)
    domains = DOMAIN_RE.findall(joined)
    emails = EMAIL_RE.findall(joined)
    ips = IPV4_RE.findall(joined)
    win_paths = WIN_PATH_RE.findall(joined)
    registry_keys = REGISTRY_RE.findall(joined)
    base64_blobs = [value for value in BASE64_RE.findall(joined) if _looks_like_base64(value)]
    suspicious_exes = [exe for exe in SUSPICIOUS_EXES if exe.casefold() in joined.casefold()]
    powershell_commands = [
        value
        for value in strings
        if "powershell" in value.casefold() or re.search(r"\s-(?:enc|encodedcommand|nop|w\s+hidden)\b", value, re.IGNORECASE)
    ]
    return {
        "urls": dedupe_keep_order(urls),
        "domains": dedupe_keep_order(domains),
        "ipv4_addresses": dedupe_keep_order(ips),
        "email_addresses": dedupe_keep_order(emails),
        "windows_paths": dedupe_keep_order(win_paths),
        "registry_keys": dedupe_keep_order(registry_keys),
        "base64_blobs": dedupe_keep_order(base64_blobs),
        "powershell_commands": dedupe_keep_order(powershell_commands),
        "suspicious_executables": suspicious_exes,
    }


def iocs_to_text(iocs: dict[str, list[str]]) -> str:
    lines: list[str] = []
    for category, values in iocs.items():
        lines.append(f"[{category}]")
        lines.extend(values or ["<none>"])
        lines.append("")
    return "\n".join(lines)


def summarize_iocs(iocs: dict[str, list[str]]) -> dict[str, Any]:
    return {key: {"count": len(values), "values": values[:100]} for key, values in iocs.items()}


def _looks_like_base64(value: str) -> bool:
    if len(value) % 4 != 0:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value))

