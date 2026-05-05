from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PatternRule:
    category: str
    pattern: str
    description: str


PATTERNS: tuple[PatternRule, ...] = (
    PatternRule("Auto-execution macros", r"\b(?:AutoOpen|AutoClose|AutoExec|Auto_Open|Auto_Close|Document_Open|Workbook_Open)\b", "Macro auto-execution entry point"),
    PatternRule("Process execution", r"\b(?:Shell|WScript\.Shell|CreateObject|WinExec|ShellExecute)\b", "Process or COM object execution primitive"),
    PatternRule("Download/network", r"\b(?:URLDownloadToFile|XMLHTTP|MSXML2\.XMLHTTP|WinHttpRequest|ADODB\.Stream)\b", "Network download or stream primitive"),
    PatternRule("Obfuscation", r"\b(?:ChrW?|Asc|StrReverse|Replace|Mid|Left|Right|Xor|Base64|FromBase64String)\b", "Common macro obfuscation primitive"),
    PatternRule("File system", r"\b(?:FileSystemObject|CreateTextFile|OpenTextFile|SaveToFile|DeleteFile|Kill)\b", "File write/read/delete primitive"),
    PatternRule("Registry", r"\b(?:RegWrite|RegRead|RegDelete)\b", "Registry modification primitive"),
    PatternRule("Office abuse", r"\b(?:DDE|DDEAUTO|OLEObject|ObjectPool|attachedTemplate|TargetMode\s*=\s*[\"']?External)\b", "Office abuse or external template indicator"),
)


def find_suspicious_patterns(texts: list[str]) -> dict[str, list[dict[str, str]]]:
    haystack = "\n".join(texts)
    findings: dict[str, list[dict[str, str]]] = {}
    for rule in PATTERNS:
        regex = re.compile(rule.pattern, re.IGNORECASE)
        matches = sorted({match.group(0) for match in regex.finditer(haystack)}, key=str.casefold)
        if matches:
            findings.setdefault(rule.category, []).append(
                {
                    "pattern": rule.pattern,
                    "description": rule.description,
                    "matches": ", ".join(matches[:50]),
                }
            )
    return findings

