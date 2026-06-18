import httpx
import pytest

from app.services.virustotal import _actor_context, _extract_ttp_evidence, _match_actor_terms, classify_indicator, lookup_virustotal_ioc


def test_extract_ttp_evidence_from_nested_vt_context():
    attributes = {
        "tags": ["attack.t1059.001"],
        "crowdsourced_yara_results": [
            {"rule_name": "loader", "description": "Observed MITRE technique T1105 during execution."}
        ],
    }
    rows = _extract_ttp_evidence(attributes, "object attributes")
    attack_ids = {row["attack_id"] for row in rows}

    assert "T1059.001" in attack_ids
    assert "T1105" in attack_ids


def test_actor_match_uses_aliases_and_separator_variants():
    attributes = {
        "popular_threat_classification": {"suggested_threat_label": "APT-28 loader"},
        "crowdsourced_yara_results": [{"rule_name": "Fancy Bear credential theft"}],
    }
    context = _actor_context(attributes, {})
    matched, evidence = _match_actor_terms(["APT28", "Fancy Bear"], context)

    assert matched == ["APT28", "Fancy Bear"]
    assert {row["term"] for row in evidence} == {"APT28", "Fancy Bear"}


def test_classify_indicator_normalizes_ip_port_for_vt():
    target = classify_indicator("18.232.64.100:443")

    assert target.value == "18.232.64.100"
    assert target.type == "ip"
    assert target.endpoint == "/ip_addresses/18.232.64.100"


def test_classify_indicator_normalizes_domain_port_for_vt():
    target = classify_indicator("example.com:443")

    assert target.value == "example.com"
    assert target.type == "domain"
    assert target.endpoint == "/domains/example.com"


def test_classify_indicator_uses_search_for_non_ioc_name():
    target = classify_indicator("win.snappy_client")

    assert target.value == "win.snappy_client"
    assert target.type == "search"
    assert target.endpoint == "/search"


@pytest.mark.asyncio
async def test_lookup_falls_back_to_search_when_domain_like_name_gets_400(monkeypatch):
    from app.core.config import settings
    from app.services import virustotal

    async def fake_vt_get(client, endpoint):
        request = httpx.Request("GET", f"https://www.virustotal.com/api/v3{endpoint}")
        response = httpx.Response(400, request=request)
        raise httpx.HTTPStatusError("bad domain", request=request, response=response)

    async def fake_vt_search(client, query):
        return {"data": []}

    async def fake_search_result(session, target, search_response, domain):
        return {"indicator": target.value, "type": target.type, "context": {"search_result_count": 0}}

    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")
    monkeypatch.setattr(virustotal, "_vt_get", fake_vt_get)
    monkeypatch.setattr(virustotal, "_vt_search", fake_vt_search)
    monkeypatch.setattr(virustotal, "_search_lookup_result", fake_search_result)

    result = await lookup_virustotal_ioc(None, "osx.waveshaper")

    assert result["indicator"] == "osx.waveshaper"
    assert result["type"] == "search"
