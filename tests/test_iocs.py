from doc_static_scanner.strings_iocs import extract_iocs


def test_extract_iocs() -> None:
    strings = [
        "Visit http://bad.example.com/a.exe",
        "Contact admin@example.org",
        "Run powershell.exe -enc AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "C:\\Users\\Public\\dropper.exe",
        "192.0.2.10",
    ]
    iocs = extract_iocs(strings)
    assert "http://bad.example.com/a.exe" in iocs["urls"]
    assert "bad.example.com" in iocs["domains"]
    assert "admin@example.org" in iocs["email_addresses"]
    assert "192.0.2.10" in iocs["ipv4_addresses"]
    assert "powershell.exe" in iocs["suspicious_executables"]
    assert iocs["registry_keys"]
    assert iocs["windows_paths"]

