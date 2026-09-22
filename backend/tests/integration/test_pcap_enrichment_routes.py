import hashlib
import uuid

import pytest

from app.core.database import get_session
from app.models.analysis import AnalysisSession, AnalysisResult
from app.models.pcap import PcapAnalysis


async def seed(app, *, tlp="TLP:CLEAR", storage_path=None):
    db = await anext(app.dependency_overrides[get_session]())
    session = AnalysisSession(id=uuid.uuid4(), tlp=tlp, source_text="Original evidence.", source_provenance={"content_sha256": "immutable", "pcap_context": {}}, status="completed")
    result = {"semantic_sha256": "a"*64, "observables": [{"observable_id": "file1", "type": "sha256", "value": "b"*64, "roles": ["exported-object"], "evidence": []}],
              "artifacts": [{"artifact_id": "object1", "sha256": "b"*64, "size_bytes": 4, "filename": "../../untrusted.exe"}]}
    row = PcapAnalysis(id=uuid.uuid4(), session_id=session.id, filename="test.pcap", status="completed", source_sha256="c"*64,
                       source_size_bytes=24, semantic_sha256="a"*64, schema_version="pcap-analysis-v1", analysis_key="d"*64,
                       analyzer_manifest={}, result=result, report_text="Original evidence.", storage_path=storage_path)
    db.add(session); db.add(row)
    db.add(AnalysisResult(session_id=session.id, extracted_techniques=[], apt_matches=[], summary="Fixture"))
    await db.flush()
    return db, row, session


@pytest.mark.asyncio
async def test_enrichment_preserves_packet_and_source_authority(client, app, monkeypatch):
    _, row, session = await seed(app)
    calls = []
    async def fake(db, artifact, *, sources, options):
        calls.append(artifact)
        return [{"source": "virustotal", "status": "ok", "raw": {"indicator": artifact, "last_analysis_stats": {"malicious": 8}, "last_analysis_date": 123}}]
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", fake)
    response = await client.post(f"/api/pcap/analyses/{row.id}/enrich", json={"observable_ids": ["file1"], "providers": ["virustotal"], "consent": True})
    assert response.status_code == 200, response.text
    value = response.json()
    assert calls == ["b"*64]
    assert value["assessment"]["ioc_candidate_count"] == 1
    assert value["assessment"]["items"][0]["classification"] == "provider-reported-malicious"
    assert value["result"] == row.result and value["semantic_sha256"] == "a"*64
    assert session.source_text == row.report_text == "Original evidence."
    assert session.source_provenance["content_sha256"] == "immutable"
    assert "Evidence-backed IOC assessment" in value["report"]
    fetched = (await client.get(f"/api/pcap/analyses/{row.id}")).json()
    assert fetched["enrichment"] == value["enrichment"]
    assert fetched["assessment"] == value["assessment"]


@pytest.mark.asyncio
@pytest.mark.parametrize("marking", ["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN"])
async def test_tlp_blocks_external_disclosure_even_with_consent(client, app, monkeypatch, marking):
    _, row, _ = await seed(app, tlp=marking)
    async def forbidden(*args, **kwargs):
        pytest.fail("Provider must not be invoked")
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", forbidden)
    response = await client.post(f"/api/pcap/analyses/{row.id}/enrich", json={"observable_ids": ["file1"], "consent": True})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_consent_scope_and_provider_validation(client, app):
    _, row, _ = await seed(app)
    url = f"/api/pcap/analyses/{row.id}/enrich"
    for body in [{"observable_ids": ["file1"]}, {"observable_ids": ["file1"], "consent": False},
                 {"observable_ids": ["outside"], "consent": True}, {"observable_ids": ["file1"], "providers": ["active-scan"], "consent": True}]:
        assert (await client.post(url, json=body)).status_code == 422


@pytest.mark.asyncio
async def test_export_permission_is_required(client, app, monkeypatch):
    from app.services.auth import TeamUser, current_user
    from app.core.config import settings
    _, row, _ = await seed(app)
    monkeypatch.setattr(settings, "auth_enabled", True)
    async def limited():
        return TeamUser(name="test", roles=[], permissions=["read", "run_analysis"])
    app.dependency_overrides[current_user] = limited
    assert (await client.post(f"/api/pcap/analyses/{row.id}/enrich", json={"observable_ids": ["file1"], "consent": True})).status_code == 403
    assert (await client.get(f"/api/pcap/analyses/{row.id}/artifacts/object1/download")).status_code == 403


@pytest.mark.asyncio
async def test_file_download_is_authenticated_hash_named_and_never_inline(client, app, monkeypatch, tmp_path):
    from app.core.config import settings
    _, row, _ = await seed(app)
    url = f"/api/pcap/analyses/{row.id}/artifacts/object1/download"
    assert (await client.get(url)).status_code == 409
    assert (await client.get(url.replace("object1", "unknown"))).status_code == 404
    monkeypatch.setattr(settings, "pcap_storage_dir", str(tmp_path))
    row.storage_path = str(tmp_path / (row.source_sha256 + ".pcap"))
    async def fake(path, source_sha, artifact):
        assert path.parent == tmp_path and source_sha == row.source_sha256
        assert artifact["sha256"] == "b"*64
        return b"test"
    monkeypatch.setattr("app.api.routes.pcap.recover_artifact", fake)
    response = await client.get(url)
    assert response.status_code == 200 and response.content == b"test"
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == 'attachment; filename="' + "b"*64 + '.bin"'
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    row.storage_path = "/etc/passwd"
    assert (await client.get(url)).status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [b"test", b"evil", b"oversized"])
async def test_download_client_independently_checks_bytes(monkeypatch, tmp_path, content):
    import httpx
    from fastapi import FastAPI
    from fastapi.responses import Response
    from app.services.pcap_analyzer import recover_artifact, PcapAnalyzerError
    sidecar = FastAPI()
    @sidecar.post("/objects/{sha256}")
    async def body(sha256: str):
        return Response(content)
    client_class = httpx.AsyncClient
    monkeypatch.setattr("app.services.pcap_analyzer.httpx.AsyncClient", lambda **kwargs: client_class(transport=httpx.ASGITransport(app=sidecar), **kwargs))
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"synthetic capture bytes")
    source_sha = hashlib.sha256(capture.read_bytes()).hexdigest()
    artifact = {"sha256": hashlib.sha256(b"test").hexdigest(), "size_bytes": 4}
    if content == b"test":
        assert await recover_artifact(capture, source_sha, artifact) == b"test"
    else:
        with pytest.raises(PcapAnalyzerError) as exc:
            await recover_artifact(capture, source_sha, artifact)
        assert exc.value.status_code == 409
    with pytest.raises(PcapAnalyzerError, match="capture hash mismatch"):
        await recover_artifact(capture, "f"*64, artifact)
