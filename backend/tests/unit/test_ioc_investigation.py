from app.services.ioc_investigation import _dedupe_actors, _urlscan_heuristic_analysis
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.services.ioc_investigation import _exact_indicator_key, _local_enrichment, _safe_source


def test_dedupe_actors_uses_string_key_not_tuple_lower():
    actors = [
        {"attack_id": "G0006", "name": "APT1", "source": "local"},
        {"attack_id": "G0006", "name": "APT1", "source": "other"},
        {"attack_id": "G0049", "name": "OilRig", "source": "local"},
    ]

    deduped = _dedupe_actors(actors)

    assert [item["attack_id"] for item in deduped] == ["G0006", "G0049"]


def test_urlscan_heuristic_analysis_extracts_suspicious_patterns():
    result = _urlscan_heuristic_analysis(
        "http://example.test/login",
        [
            {
                "page": {"url": "http://redirect.example/payload", "domain": "redirect.example", "ip": "203.0.113.10"},
                "task": {"url": "http://example.test/login"},
                "verdicts": {"overall": {"malicious": True}},
                "stats": {"uniqIPs": 6},
            }
        ],
        {},
    )

    patterns = {item["pattern"] for item in result["findings"]}

    assert result["mode"] == "heuristic"
    assert "malicious urlscan verdict" in patterns
    assert "multiple network destinations" in patterns
    assert "redirect or hosted-content pivot" in patterns
    assert result["technique_ids"] == []


def test_urlscan_false_verdict_is_not_reported_as_malicious():
    result = _urlscan_heuristic_analysis('example.test', [
        {'verdicts': {'overall': {'malicious': False}, 'engines': {'malicious': 'false'}}},
    ], {})
    assert not any(f['pattern'] == 'malicious urlscan verdict' for f in result['findings'])
    assert result['technique_ids'] == []


def test_urlscan_keyword_metadata_does_not_establish_attack_behavior():
    result = _urlscan_heuristic_analysis('example.test', [
        {'page': {'title': 'Security documentation about phishing login malware payloads'}},
    ], {})
    assert result['findings']
    assert result['technique_ids'] == []


def test_exact_indicator_types_and_url_case():
    assert _exact_indicator_key('hash', 'A'*64) == ('sha256', 'a'*64)
    assert _exact_indicator_key('domain', 'Example.TEST.') == ('domain', 'example.test')
    assert _exact_indicator_key('url', 'https://example.test/A') != _exact_indicator_key('url', 'https://example.test/a')
    assert _exact_indicator_key('ja3', 'a'*32) != _exact_indicator_key('md5', 'a'*32)


@pytest.mark.asyncio
async def test_local_enrichment_rejects_substring_description_and_wrong_type():
    def row(kind, value):
        return SimpleNamespace(indicator_type=kind, value=value, actor_links=[], description='example.test', source_id='test', technique_ids=[], raw={})
    result = MagicMock()
    result.scalars.return_value.all.return_value = [row('domain','example.test'), row('domain','notexample.test'), row('url','example.test')]
    session = SimpleNamespace(execute=AsyncMock(return_value=result))
    enriched = await _local_enrichment(session, 'example.test', 'domain', 'enterprise-attack')
    assert enriched['raw']['matched_records'] == 1
    query = str(session.execute.call_args.args[0])
    assert 'description' not in query.split('WHERE')[1]
    assert ' LIKE ' not in query


@pytest.mark.asyncio
async def test_provider_error_does_not_leak_query_credentials(caplog):
    async def failed():
        request = httpx.Request('GET', 'https://provider.test/lookup?key=secret-regression-key')
        raise httpx.HTTPStatusError('secret-regression-key', request=request, response=httpx.Response(429, request=request))
    with caplog.at_level(logging.WARNING):
        result = await _safe_source('provider-test', failed)
    assert result['error_category'] == 'rate_limited'
    assert result['http_status'] == 429
    assert 'secret-regression-key' not in str(result)
    assert 'secret-regression-key' not in caplog.text
