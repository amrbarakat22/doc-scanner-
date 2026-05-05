from doc_static_scanner.scoring import calculate_risk, risk_level


def test_risk_level_boundaries() -> None:
    assert risk_level(0) == "Low"
    assert risk_level(25) == "Medium"
    assert risk_level(50) == "High"
    assert risk_level(75) == "Critical"


def test_calculate_risk_explains_points() -> None:
    analysis = {
        "ole": {"macro_related_streams": [{"name": "VBA/dir"}], "embedded_object_indicators": []},
        "ooxml": {"vba_projects": [], "embeddings": [], "activex": [], "external_links": [], "external_relationships": []},
        "iocs": {"urls": ["http://example.com"], "domains": [], "ipv4_addresses": [], "registry_keys": [], "powershell_commands": [], "suspicious_executables": ["powershell.exe"]},
        "suspicious_patterns": {
            "Auto-execution macros": [{"matches": "AutoOpen"}],
            "Process execution": [{"matches": "Shell"}],
        },
        "external_tools": {},
        "file_info": {"entropy": 7.6},
    }
    risk = calculate_risk(analysis)
    assert risk["score"] >= 60
    assert risk["reasons"]
    assert any("Macro" in reason["reason"] for reason in risk["reasons"])

