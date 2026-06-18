from app.services.detection_feeds import _parse_rule_text
from app.services.detections import generate_detection, validate_detection


def test_parse_sigma_rule_extracts_attack_tag():
    text = """
title: Suspicious PowerShell
id: test-rule
tags:
  - attack.t1059.001
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
"""
    item = _parse_rule_text(text, "sigma", "https://example/rule.yml")
    assert item is not None
    assert item.title == "Suspicious PowerShell"
    assert item.technique_id == "T1059.001"
    assert item.rule_id == "test-rule"


def test_parse_yara_rule_extracts_attack_id_and_name():
    text = """
rule cobalt_strike_beacon
{
  meta:
    attack = "T1059"
  strings:
    $a = "beacon"
  condition:
    $a
}
"""
    item = _parse_rule_text(text, "yara", "https://example/rule.yar")
    assert item is not None
    assert item.title == "cobalt_strike_beacon"
    assert item.technique_id == "T1059"


def test_yara_generation_and_validation():
    content = generate_detection("Example YARA", "T1059.001", "yara", [])
    validation = validate_detection("yara", content)
    assert validation["valid"] is True
    assert "rule Example_YARA" in content
