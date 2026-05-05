from __future__ import annotations

from typing import Any


LEVELS = (
    (75, "Critical"),
    (50, "High"),
    (25, "Medium"),
    (0, "Low"),
)


def risk_level(score: int) -> str:
    for threshold, level in LEVELS:
        if score >= threshold:
            return level
    return "Low"


def calculate_risk(analysis: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[dict[str, Any]] = []

    def add(points: int, reason: str, evidence: str = "") -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        reasons.append({"points": points, "reason": reason, "evidence": evidence})

    ole = analysis.get("ole", {})
    ooxml = analysis.get("ooxml", {})
    iocs = analysis.get("iocs", {})
    patterns = analysis.get("suspicious_patterns", {})
    tools = analysis.get("external_tools", {})
    file_info = analysis.get("file_info", {})

    macros = len(ole.get("macro_related_streams", [])) + len(ooxml.get("vba_projects", []))
    if macros:
        add(20, "Macro-related streams or VBA project present", f"{macros} indicator(s)")

    if patterns.get("Auto-execution macros"):
        add(20, "Auto-execution macro indicator found", _pattern_evidence(patterns, "Auto-execution macros"))

    if patterns.get("Process execution"):
        add(15, "Shell or process execution indicator found", _pattern_evidence(patterns, "Process execution"))

    if patterns.get("Download/network"):
        add(15, "Download or network indicator found", _pattern_evidence(patterns, "Download/network"))

    embedded = len(ole.get("embedded_object_indicators", [])) + len(ooxml.get("embeddings", [])) + len(ooxml.get("activex", []))
    if embedded:
        add(12, "Embedded object or ActiveX indicator found", f"{embedded} indicator(s)")

    external = len(ooxml.get("external_links", [])) + len(ooxml.get("external_relationships", []))
    if external or patterns.get("Office abuse"):
        add(12, "External link/template or Office abuse indicator found", f"{external} OOXML relationship indicator(s)")

    if patterns.get("Obfuscation"):
        add(10, "Obfuscation indicator found", _pattern_evidence(patterns, "Obfuscation"))

    if patterns.get("File system"):
        add(6, "File system manipulation indicator found", _pattern_evidence(patterns, "File system"))

    if patterns.get("Registry"):
        add(8, "Registry access indicator found", _pattern_evidence(patterns, "Registry"))

    suspicious_ioc_count = sum(len(iocs.get(key, [])) for key in ("urls", "domains", "ipv4_addresses", "registry_keys", "powershell_commands", "suspicious_executables"))
    if suspicious_ioc_count:
        add(min(12, 4 + suspicious_ioc_count), "Suspicious IOC strings found", f"{suspicious_ioc_count} IOC value(s)")

    entropy = float(file_info.get("entropy", 0.0) or 0.0)
    if entropy >= 7.5:
        add(10, "Very high file entropy", f"{entropy:.2f}")
    elif entropy >= 7.0:
        add(6, "High file entropy", f"{entropy:.2f}")

    clamscan = tools.get("clamscan", {})
    if clamscan.get("exit_code") == 1 or "FOUND" in str(clamscan.get("stdout", "")):
        add(30, "ClamAV reported a detection", "clamscan returned a malware finding")

    yara = tools.get("yara", {})
    yara_output = (str(yara.get("stdout", "")) + str(yara.get("stderr", ""))).strip()
    if yara.get("exit_code") == 0 and yara_output and not yara.get("skipped_reason"):
        add(25, "YARA rule matched", "YARA produced match output")

    score = min(score, 100)
    return {"score": score, "level": risk_level(score), "reasons": reasons}


def _pattern_evidence(patterns: dict[str, list[dict[str, str]]], category: str) -> str:
    entries = patterns.get(category, [])
    return "; ".join(entry.get("matches", "") for entry in entries if entry.get("matches"))[:500]

