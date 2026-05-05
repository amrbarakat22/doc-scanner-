from doc_static_scanner.suspicious_patterns import find_suspicious_patterns


def test_find_suspicious_patterns() -> None:
    findings = find_suspicious_patterns([
        "Sub AutoOpen()",
        "CreateObject(\"WScript.Shell\").Run \"cmd.exe /c calc\"",
        "URLDownloadToFile and StrReverse",
        "RegWrite",
    ])
    assert "Auto-execution macros" in findings
    assert "Process execution" in findings
    assert "Download/network" in findings
    assert "Obfuscation" in findings
    assert "Registry" in findings

