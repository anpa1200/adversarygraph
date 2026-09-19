from app.services.ioc_investigation import _dedupe_actors, _urlscan_heuristic_analysis
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
import httpx
import pytest
from app.services.ioc_investigation import _exact_indicator_key, _local_enrichment, _safe_source
from app.services import ioc_investigation as investigation


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


def test_urlscan_empty_results_do_not_classify_echoed_input():
    result = _urlscan_heuristic_analysis('c2' * 32, [], {'query': 'c2' * 32, 'results': []})
    assert result['findings'] == []
    assert result['technique_ids'] == []


@pytest.mark.parametrize('status', ['missing_query', 'illegal_hash', 'unknown_auth_key', None])
def test_abusech_application_errors_are_not_successful_empty_results(status):
    with pytest.raises(RuntimeError, match='rejected'):
        investigation._validate_query_status({'query_status': status}, {'ok', 'hash_not_found'})


@pytest.mark.asyncio
async def test_malwarebazaar_uses_form_encoded_lookup(monkeypatch):
    captured = []
    async def handler(request):
        captured.append(request)
        return httpx.Response(200, json={'query_status': 'ok', 'data': [{'sha256_hash': 'a' * 64, 'signature': 'Fixture'}]})
    original_client = httpx.AsyncClient
    monkeypatch.setattr(investigation.httpx, 'AsyncClient', lambda **kwargs: original_client(transport=httpx.MockTransport(handler), **kwargs))
    result = await investigation._malwarebazaar_enrichment('a' * 64)
    assert captured[0].headers['content-type'] == 'application/x-www-form-urlencoded'
    assert captured[0].content == b'query=get_info&hash=' + b'a' * 64
    assert result['status'] == 'ok'
    assert '1 sample' in result['summary']


@pytest.mark.asyncio
async def test_malwarebazaar_http_200_application_failure_is_error(monkeypatch):
    monkeypatch.setattr(investigation, '_post_form', AsyncMock(return_value={'query_status': 'missing_query'}))
    result = await _safe_source('malwarebazaar', lambda: investigation._malwarebazaar_enrichment('a' * 64))
    assert result['status'] == 'error'
    assert result['error_category'] == 'provider_error'


def test_technique_provenance_distinguishes_direct_and_related_pivots():
    direct = [{'source': 'virustotal', 'technique_ids': ['T1059.001']}]
    pivots = [{'source': 'local-db', 'technique_ids': ['T1059.001']}]
    evidence = investigation._technique_evidence_sources('T1059.001', direct, pivots)
    assert len(evidence) == 2
    assert 'submitted indicator' in evidence[0]
    assert 'related local pivot' in evidence[1]
    assert all('not packet execution proof' in item for item in evidence)


def test_hash_substrings_do_not_increase_risk_score():
    sources = [{'source': 'virustotal', 'status': 'ok', 'raw': {'indicator': 'c2' * 32}}]
    assert investigation._suspicion_score(sources, {}) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('query_status', ['no_result', 'hash_not_found', 'not_found'])
async def test_provider_absence_is_explicit_not_found(query_status):
    result = await _safe_source('test', AsyncMock(return_value={'status': 'ok', 'raw': {'query_status': query_status}}))
    assert result['status'] == 'not_found'


@pytest.mark.asyncio
async def test_http_404_is_absence_not_provider_failure():
    request = httpx.Request('GET', 'https://provider.invalid/lookup')
    error = httpx.HTTPStatusError('not found', request=request, response=httpx.Response(404, request=request))
    result = await _safe_source('test', AsyncMock(side_effect=error))
    assert result['status'] == 'not_found'
    assert result['http_status'] == 404


def test_graph_preserves_url_path_case_and_binds_normalized_domains():
    nodes, edges = {}, []
    result = {'source': 'urlscan', 'status': 'ok', 'relationships': [
        {'source':'Example.TEST','target':'https://example.test/AbC','target_type':'url'},
        {'source':'example.test','target':'https://example.test/abc','target_type':'url'},
        {'source':'EXAMPLE.TEST','target':'Child.Example.TEST','target_type':'domain'},
    ]}
    investigation._merge_graph(nodes, edges, result, 'example.test')
    assert len(nodes) == 4
    values = {node['value'] for node in nodes.values()}
    assert 'https://example.test/AbC' in values
    assert 'https://example.test/abc' in values
    assert 'child.example.test' in values
    assert all(edge['source'] in values and edge['target'] in values for edge in edges)
