from types import SimpleNamespace

import pytest

from app.services import pcap_story
from tests.integration.test_pcap_enrichment_routes import seed


@pytest.mark.asyncio
async def test_preflight_has_no_model_side_effect_and_reports_staleness(client, app, monkeypatch):
    _, row, session = await seed(app)
    def forbidden(*args, **kwargs):
        pytest.fail("Read-only preflight must not construct an adapter")
    monkeypatch.setattr("app.services.threat_hunting_ai.create_adapter", forbidden)
    response = await client.get(f"/api/pcap/analyses/{row.id}/summary/preflight")
    assert response.status_code == 200, response.text
    value = response.json()
    assert value["summary"] is None and value["source_sha256"] == pcap_story.fingerprint(row, session)
    assert (await client.get(f"/api/pcap/analyses/{row.id}/summary")).json()["summary"] is None


@pytest.mark.asyncio
async def test_cloud_consent_and_classification_and_preflight_fingerprint(client, app, monkeypatch):
    _, row, session = await seed(app)
    monkeypatch.setattr("app.core.config.settings.openai_api_key", "synthetic-test-key")
    monkeypatch.setattr("app.core.config.settings.threat_hunting_ai_cloud_enabled", True)
    url = f"/api/pcap/analyses/{row.id}/summary"
    assert (await client.post(url, json={"provider": "openai"})).status_code == 422
    assert (await client.post(url, json={"expected_source_sha256": "0"*64})).status_code == 409
    session.tlp = "TLP:RED"
    assert (await client.post(url, json={"provider": "openai", "cloud_processing_acknowledged": True})).status_code == 403


@pytest.mark.asyncio
async def test_summary_saved_separately_from_authoritative_packet_report(client, app, monkeypatch):
    _, row, session = await seed(app)
    monkeypatch.setattr("app.services.threat_hunting_ai.create_adapter", lambda *args, **kwargs: SimpleNamespace(provider="fixture", model="fixture"))
    async def generate(*args):
        return {"id": "summary-fixture", "source_sha256": pcap_story.fingerprint(row, session),
            "requested_model": "fixture", "model": "fixture", "word_count": 30, "token_usage": None}
    monkeypatch.setattr(pcap_story, "generate", generate)
    url = f"/api/pcap/analyses/{row.id}/summary"
    for _ in range(7):
        response = await client.post(url, json={"provider": "local"})
        assert response.status_code == 200, response.text
    assert session.source_text == row.report_text == "Original evidence."
    assert session.source_provenance["content_sha256"] == "immutable"
    assert len(session.source_provenance["pcap_summary_history"]) == 5
    assert not (await client.get(url)).json()["summary"]["stale"]


@pytest.mark.asyncio
async def test_inflight_evidence_change_or_invalid_output_is_not_saved(client, app, monkeypatch):
    _, row, session = await seed(app)
    monkeypatch.setattr("app.services.threat_hunting_ai.create_adapter", lambda *args, **kwargs: SimpleNamespace(provider="fixture", model="fixture"))
    async def changed(*args):
        before = pcap_story.fingerprint(row, session)
        session.tlp = "TLP:RED"
        return {"source_sha256": before}
    monkeypatch.setattr(pcap_story, "generate", changed)
    url = f"/api/pcap/analyses/{row.id}/summary"
    assert (await client.post(url, json={"provider": "local"})).status_code == 409
    assert "pcap_investigation_summary" not in session.source_provenance
    async def invalid(*args):
        raise ValueError("Unknown summary evidence reference")
    monkeypatch.setattr(pcap_story, "generate", invalid)
    assert (await client.post(url, json={"provider": "local"})).status_code == 502
    assert "pcap_investigation_summary" not in session.source_provenance
