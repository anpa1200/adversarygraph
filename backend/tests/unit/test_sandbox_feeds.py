from app.services.sandbox_feeds import parse_sandbox_report


def test_parse_sandbox_report_extracts_behavior_context():
    report = {
        "sha256": "a" * 64,
        "verdict": "malicious",
        "score": 88,
        "family": "ExampleLoader",
        "tags": ["loader"],
        "signatures": [{"name": "Creates Run key", "severity": "high"}],
        "processes": [{"process_name": "powershell.exe", "command_line": "powershell -enc AAA"}],
        "network": {"domains": ["c2.example.com"], "ips": ["8.8.8.8"]},
        "mitre_attacks": [{"id": "T1059.001", "name": "PowerShell"}],
    }

    parsed = parse_sandbox_report(report, "https://sandbox.local/feed.json")

    assert parsed["hashes"] == ["a" * 64]
    assert parsed["verdict"] == "malicious"
    assert parsed["confidence"] == 88
    assert parsed["malware_family"] == "ExampleLoader"
    assert "T1059.001" in parsed["ttps"]
    assert parsed["signatures"][0]["name"] == "Creates Run key"
    assert "powershell.exe" in parsed["processes"][0]
    assert "c2.example.com" in parsed["network"]["domains"]


def test_parse_sandbox_report_supports_nested_hash_and_stable_id():
    report = {
        "target": {"file": {"md5": "d41d8cd98f00b204e9800998ecf8427e"}},
        "behavior": ["Observed T1105 network download"],
    }

    parsed = parse_sandbox_report(report)

    assert "d41d8cd98f00b204e9800998ecf8427e" in parsed["hashes"]
    assert parsed["report_id"]
    assert "T1105" in parsed["ttps"]
