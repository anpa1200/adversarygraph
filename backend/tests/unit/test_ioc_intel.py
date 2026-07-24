import pytest

from app.services.ioc_intel import (
    IOCImportItem,
    _SQL_IN_BATCH_SIZE,
    enrich_ioc_ttp_mappings,
    _otx_get_json,
    _otx_subscribed_pulses,
    _item_technique_ids,
    _malpedia_family_to_import_item,
    _mapping_evidence_from_item,
    _normalize_ioc_type,
)


def test_malpedia_family_to_import_item_maps_attribution_and_context():
    item = _malpedia_family_to_import_item(
        "win.example",
        {
            "common_name": "ExampleRat",
            "alt_names": ["Example RAT", "ExampleTool"],
            "attribution": ["APT28", "Fancy Bear"],
            "urls": ["https://example.test/report"],
            "sources": ["vendor report"],
            "updated": "2026-06-01",
            "uuid": "abc",
        },
    )

    assert item.value == "win.example"
    assert item.indicator_type == "malware-family"
    assert item.malware_family == "ExampleRat"
    assert item.actor_name == "APT28, Fancy Bear"
    assert item.source_url == "https://example.test/report"
    assert "tag:example-rat" in item.tags
    assert "tag:apt28" in item.tags


def test_ioc_item_technique_ids_extracts_explicit_and_raw_attack_ids():
    item = IOCImportItem(
        value="203.0.113.10",
        indicator_type="ipv4",
        technique_ids=["T1105"],
        tags=["command-and-control", "T1071.001"],
        description="Observed alongside PowerShell T1059.001.",
        raw={"mitre": [{"technique_id": "T1566"}]},
    )

    assert _item_technique_ids(item) == ["T1059.001", "T1071.001", "T1105", "T1566"]


def test_ioc_type_normalization_handles_provider_hash_names():
    assert _normalize_ioc_type("sha256_hash", "a" * 64) == "sha256"
    assert _normalize_ioc_type("sha1_hash", "a" * 40) == "sha1"
    assert _normalize_ioc_type("md5_hash", "a" * 32) == "md5"


def test_ioc_ttp_mapping_evidence_preserves_priority():
    item = IOCImportItem(
        value="d41d8cd98f00b204e9800998ecf8427e",
        indicator_type="md5_hash",
        technique_ids=["T1105"],
        tags=["T1059"],
        raw={"platform_tag": "T1566"},
    )

    evidence = _mapping_evidence_from_item(item)
    by_id = {row["attack_id"]: row["priority"] for row in evidence}

    assert by_id["T1105"] == "strict-report"
    assert by_id["T1059"] == "enrichment-platform"
    assert by_id["T1566"] == "enrichment-platform"


async def test_enrich_ioc_ttp_mappings_batches_large_indicator_id_lists():
    class EmptyRows:
        class EmptyScalars:
            def all(self):
                return []

        def scalars(self):
            return self.EmptyScalars()

    class FakeSession:
        def __init__(self):
            self.execute_calls = 0
            self.flushed = False

        async def execute(self, _stmt):
            self.execute_calls += 1
            return EmptyRows()

        async def flush(self):
            self.flushed = True

    session = FakeSession()
    indicator_ids = list(range((_SQL_IN_BATCH_SIZE * 3) + 5))

    result = await enrich_ioc_ttp_mappings(session, indicator_ids=indicator_ids, use_ai=False)

    assert session.execute_calls == 4
    assert session.flushed is True
    assert result["checked"] == 0


async def test_otx_get_json_retries_transient_timeout(monkeypatch):
    from app.core.config import settings
    from app.services import ioc_intel

    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"id": "pulse-1"}]}

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            raise ioc_intel.requests.ReadTimeout("slow OTX response")
        return Response()

    monkeypatch.setattr(settings, "otx_api_key", "test-key")
    monkeypatch.setattr(settings, "otx_connect_timeout_seconds", 3)
    monkeypatch.setattr(settings, "otx_read_timeout_seconds", 30)
    monkeypatch.setattr(settings, "otx_retries", 1)
    monkeypatch.setattr(ioc_intel.requests, "get", fake_get)
    async def fake_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(ioc_intel.asyncio, "sleep", fake_sleep)

    payload = await _otx_get_json("https://otx.example.test/api", params={"limit": 1})

    assert payload["results"][0]["id"] == "pulse-1"
    assert len(calls) == 2
    assert calls[1][1]["headers"]["X-OTX-API-KEY"] == "test-key"
    assert calls[1][1]["timeout"] == (3, 30)


async def test_otx_get_json_retries_transient_http_error(monkeypatch):
    from app.core.config import settings
    from app.services import ioc_intel

    calls = []

    class GatewayTimeoutResponse:
        status_code = 504
        reason = "Gateway Time-out"
        url = "https://otx.example.test/api"

        def raise_for_status(self):
            raise ioc_intel.requests.HTTPError(
                "504 Server Error: Gateway Time-out for url: https://otx.example.test/api",
                response=self,
            )

    class SuccessResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"id": "pulse-2"}]}

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        if len(calls) == 1:
            return GatewayTimeoutResponse()
        return SuccessResponse()

    monkeypatch.setattr(settings, "otx_api_key", "test-key")
    monkeypatch.setattr(settings, "otx_connect_timeout_seconds", 3)
    monkeypatch.setattr(settings, "otx_read_timeout_seconds", 30)
    monkeypatch.setattr(settings, "otx_retries", 1)
    monkeypatch.setattr(ioc_intel.requests, "get", fake_get)

    async def fake_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(ioc_intel.asyncio, "sleep", fake_sleep)

    payload = await _otx_get_json("https://otx.example.test/api", params={"limit": 1})

    assert payload["results"][0]["id"] == "pulse-2"
    assert len(calls) == 2


async def test_otx_get_json_raises_transient_error_after_http_retries(monkeypatch):
    from app.core.config import settings
    from app.services import ioc_intel

    class GatewayTimeoutResponse:
        status_code = 504
        reason = "Gateway Time-out"
        url = "https://otx.example.test/api"

        def raise_for_status(self):
            raise ioc_intel.requests.HTTPError(
                "504 Server Error: Gateway Time-out for url: https://otx.example.test/api",
                response=self,
            )

    def fake_get(*args, **kwargs):
        return GatewayTimeoutResponse()

    monkeypatch.setattr(settings, "otx_api_key", "test-key")
    monkeypatch.setattr(settings, "otx_connect_timeout_seconds", 3)
    monkeypatch.setattr(settings, "otx_read_timeout_seconds", 30)
    monkeypatch.setattr(settings, "otx_retries", 1)
    monkeypatch.setattr(ioc_intel.requests, "get", fake_get)

    async def fake_sleep(*_args, **_kwargs):
        return None

    monkeypatch.setattr(ioc_intel.asyncio, "sleep", fake_sleep)

    with pytest.raises(ioc_intel.TransientOTXError) as exc:
        await _otx_get_json("https://otx.example.test/api", params={"limit": 1})

    assert "HTTP 504" in str(exc.value)
    assert "Cached OTX indicators are preserved" in str(exc.value)


async def test_otx_subscribed_pulses_clamps_limit_and_uses_configured_timeout(monkeypatch):
    from app.core.config import settings
    from app.services import ioc_intel

    calls = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": [{"id": "pulse-1"}, "skip-me"]}

    def fake_get(*args, **kwargs):
        calls.append((args, kwargs))
        return Response()

    monkeypatch.setattr(settings, "otx_api_key", "test-key")
    monkeypatch.setattr(settings, "otx_connect_timeout_seconds", 4)
    monkeypatch.setattr(settings, "otx_read_timeout_seconds", 45)
    monkeypatch.setattr(settings, "otx_retries", 0)
    monkeypatch.setattr(ioc_intel.requests, "get", fake_get)

    pulses = await _otx_subscribed_pulses(limit=999)

    assert pulses == [{"id": "pulse-1"}]
    assert calls[0][1]["params"]["limit"] == 500
    assert calls[0][1]["timeout"] == (4, 45)
