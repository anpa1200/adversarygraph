from datetime import datetime, timezone

from app.models.ioc import IOCIndicator
from app.services.opencti_sync import (
    _connect_url,
    _guess_ioc_type,
    _indicator_node_to_import_item,
    _indicator_to_opencti_input,
    _observable_node_to_import_item,
)


def test_opencti_indicator_node_maps_pattern_labels_and_attack_ids():
    item = _indicator_node_to_import_item(
        {
            "id": "indicator--1",
            "name": "Example",
            "description": "Uses T1059.001 during execution",
            "pattern": "[domain-name:value = 'evil.example']",
            "confidence": 80,
            "labels": {"edges": [{"node": {"value": "apt-test"}}]},
            "externalReferences": {"edges": [{"node": {"url": "https://example.test/report"}}]},
        }
    )

    assert item is not None
    assert item.value == "evil.example"
    assert item.indicator_type == "domain"
    assert item.source == "opencti"
    assert "apt-test" in item.tags
    assert "opencti-indicator" in item.tags
    assert item.technique_ids == ["T1059.001"]
    assert item.source_url == "https://example.test/report"


def test_opencti_observable_node_maps_ioc_value():
    item = _observable_node_to_import_item(
        {
            "id": "observable--1",
            "entity_type": "IPv4-Addr",
            "observable_value": "8.8.8.8",
            "labels": [{"value": "dns"}],
        }
    )

    assert item is not None
    assert item.value == "8.8.8.8"
    assert item.indicator_type == "ipv4"
    assert "opencti-observable" in item.tags


def test_opencti_push_indicator_input_uses_stix_pattern():
    indicator = IOCIndicator(
        value="a" * 64,
        indicator_type="sha256",
        source_id="manual-report-import",
        source_url="",
        first_seen="2026-06-20T01:02:03Z",
        last_seen="2026-06-20T01:02:03Z",
        confidence=77,
        tlp="clear",
        malware_family="",
        campaign="",
        technique_ids=["T1486"],
        description="test hash",
        tags=["ransomware"],
        raw={},
        updated_at=datetime.now(timezone.utc),
    )

    payload = _indicator_to_opencti_input(indicator)
    assert payload is not None
    assert payload["pattern"] == f"[file:hashes.'SHA-256' = '{'a' * 64}']"
    assert payload["x_opencti_main_observable_type"] == "StixFile"
    assert payload["confidence"] == 77
    assert "ransomware" in payload["labels"]


def test_opencti_guess_ioc_type_for_common_values():
    assert _guess_ioc_type("1.2.3.4") == {"type": "ipv4", "value": "1.2.3.4"}
    assert _guess_ioc_type("https://example.test/a") == {"type": "url", "value": "https://example.test/a"}
    assert _guess_ioc_type("b" * 40) == {"type": "sha1", "value": "b" * 40}


def test_opencti_localhost_url_is_translated_for_docker(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "opencti_url", "http://localhost:8080/")
    assert _connect_url() == "http://host.docker.internal:8080"
