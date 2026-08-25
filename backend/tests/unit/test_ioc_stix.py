from unittest.mock import AsyncMock

import pytest

from app.services import ioc_stix
from app.services.ioc_stix import (
    ReportBearingSTIXError,
    _indicator_pattern,
    _parse_pattern,
    _sco_value,
)


def test_ioc_stix_pattern_roundtrip_for_hash_domain_ip_url():
    cases = [
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("domain", "example.com"),
        ("url", "https://example.com/a"),
        ("ipv4", "8.8.8.8"),
        ("ip:port", "8.8.8.8:443"),
    ]
    for kind, value in cases:
        pattern = _indicator_pattern(kind, value)
        parsed = _parse_pattern(pattern)
        assert parsed is not None
        if kind == "ip:port":
            assert parsed == {"type": "ipv4", "value": "8.8.8.8"}
        else:
            assert parsed["value"] == value


def test_ioc_stix_sco_values_from_observed_data_objects():
    assert _sco_value({"type": "domain-name", "value": "example.com"}) == {"type": "domain", "value": "example.com"}
    assert _sco_value({"type": "ipv4-addr", "value": "1.2.3.4"}) == {"type": "ipv4", "value": "1.2.3.4"}
    assert _sco_value({"type": "file", "hashes": {"SHA-256": "a" * 64}}) == {"type": "sha256", "value": "a" * 64}


@pytest.mark.asyncio
async def test_report_bearing_bundle_is_rejected_before_database_activity(monkeypatch):
    create_source = AsyncMock()
    import_items = AsyncMock()
    monkeypatch.setattr(ioc_stix, "create_ioc_source", create_source)
    monkeypatch.setattr(ioc_stix, "import_iocs", import_items)

    with pytest.raises(ReportBearingSTIXError, match="Reports / Research"):
        await ioc_stix.import_ioc_stix_bundle(
            object(),
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "report",
                        "id": "report--22222222-2222-4222-8222-222222222222",
                        "object_refs": ["indicator--11111111-1111-4111-8111-111111111111"],
                    },
                    {
                        "type": "indicator",
                        "id": "indicator--11111111-1111-4111-8111-111111111111",
                        "pattern": "[domain-name:value = 'unreviewed.example']",
                    },
                ],
            },
        )

    create_source.assert_not_awaited()
    import_items.assert_not_awaited()


@pytest.mark.asyncio
async def test_report_bearing_taxii_collection_is_rejected_before_database_activity(
    monkeypatch,
):
    class _Response:
        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {
                "objects": [
                    {
                        "type": "report",
                        "id": "report--22222222-2222-4222-8222-222222222222",
                        "object_refs": ["indicator--11111111-1111-4111-8111-111111111111"],
                    },
                    {
                        "type": "indicator",
                        "id": "indicator--11111111-1111-4111-8111-111111111111",
                        "pattern": "[domain-name:value = 'unreviewed.example']",
                    },
                ]
            }

    fetch = AsyncMock(return_value=_Response())
    create_source = AsyncMock()
    import_items = AsyncMock()
    monkeypatch.setattr(ioc_stix, "async_safe_get", fetch)
    monkeypatch.setattr(ioc_stix, "create_ioc_source", create_source)
    monkeypatch.setattr(ioc_stix, "import_iocs", import_items)

    with pytest.raises(ReportBearingSTIXError, match="Reports / Research"):
        await ioc_stix.import_taxii_collection(
            object(),
            objects_url="https://taxii.example.test/collections/reports/objects/",
        )

    fetch.assert_awaited_once()
    create_source.assert_not_awaited()
    import_items.assert_not_awaited()
