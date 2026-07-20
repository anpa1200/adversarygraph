from app.services.detection_feeds import YARA_RULE_URLS, YARA_RULES_URL, YARAL_RULES_URL, _candidate_rule_urls, _parse_rule_text
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


def test_yaral_generation_and_validation():
    content = generate_detection("Chronicle Process Behavior", "T1059.001", "yaral", ["PROCESS_LAUNCH"])
    validation = validate_detection("yaral", content)
    assert validation["valid"] is True
    assert "events:" in content
    assert "condition:" in content
    assert 'attack = "T1059.001"' in content


def test_default_yara_rules_source_is_public_tree():
    assert YARA_RULES_URL == "https://github.com/Yara-Rules/rules/tree/master/malware"
    assert YARA_RULE_URLS
    assert all(url.endswith(".yar") for url in YARA_RULE_URLS)


def test_explicit_rule_urls_do_not_require_github_tree_listing():
    urls = _candidate_rule_urls(YARA_RULES_URL, "yara", 2, explicit_urls=YARA_RULE_URLS)
    assert urls == YARA_RULE_URLS[:2]


def test_yaral_community_tree_and_extension_are_supported():
    assert YARAL_RULES_URL == "https://github.com/chronicle/detection-rules/tree/main/rules/community"
    item = _parse_rule_text(
        'rule suspicious_login {\n meta:\n  mitre_attack = "T1078"\n events:\n  $e.metadata.event_type = "USER_LOGIN"\n condition:\n  $e\n}',
        "yaral",
        "https://raw.githubusercontent.com/chronicle/detection-rules/main/rules/community/example.yaral",
    )
    assert item is not None
    assert item.format == "yaral"
    assert item.technique_id == "T1078"
