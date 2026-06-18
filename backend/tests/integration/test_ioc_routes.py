import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_ioc_sources_shape(client: AsyncClient):
    resp = await client.get("/api/ioc/sources")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_actor_iocs_shape(client: AsyncClient):
    resp = await client.get("/api/ioc/actors/G0049")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_actor_ioc_summary_shape(client: AsyncClient):
    resp = await client.get("/api/ioc/actors/G0049/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["actor_attack_id"] == "G0049"
    assert isinstance(body["count"], int)


@pytest.mark.asyncio
async def test_actor_ioc_counts_shape(client: AsyncClient):
    resp = await client.get("/api/ioc/actors/counts", params={"actor_ids": ["G0049", "G0069"]})
    assert resp.status_code == 200
    assert isinstance(resp.json()["counts"], dict)


@pytest.mark.asyncio
async def test_ioc_library_shape(client: AsyncClient):
    resp = await client.get(
        "/api/ioc/library",
        params={"search": "example", "type": "domain", "sort": "type_asc", "limit": 25},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body["total"], int)
    assert body["limit"] == 25
    assert body["offset"] == 0
    assert isinstance(body["items"], list)


@pytest.mark.asyncio
async def test_ioc_library_accepts_multiple_actor_filters(client: AsyncClient):
    resp = await client.get(
        "/api/ioc/library",
        params=[("actor", "G0006"), ("actor", "G0049"), ("limit", "25")],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 25
    assert isinstance(body["items"], list)


@pytest.mark.asyncio
async def test_ioc_import_requires_indicators(client: AsyncClient):
    resp = await client.post("/api/ioc/import", json={"indicators": []})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_report_ioc_upload_extracts_iocs(client: AsyncClient, monkeypatch):
    from app.api.routes import ioc as ioc_route

    async def fake_import_iocs(session, items):
        return {"source": "manual-report-import", "inserted": len(items), "updated": 0, "actor_links": len(items)}

    monkeypatch.setattr(ioc_route, "import_iocs", fake_import_iocs)
    content = b"IOC list: 8.8.8.8, evil-example.com, https://c2.example.net/a, d41d8cd98f00b204e9800998ecf8427e"
    resp = await client.post(
        "/api/ioc/report",
        data={"actor_attack_id": "G0049", "actor_name": "OilRig"},
        files={"file": ("report.txt", content, "text/plain")},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["extracted"] >= 3
    assert isinstance(body["preview"], list)


@pytest.mark.asyncio
async def test_threatfox_sync_reports_missing_key(client: AsyncClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "threatfox_auth_key", "")
    resp = await client.post("/api/ioc/sync/threatfox?days=1")
    assert resp.status_code == 400
    assert "THREATFOX_AUTH_KEY" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_otx_sync_reports_missing_key(client: AsyncClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "otx_api_key", "")
    resp = await client.post("/api/ioc/sync/otx?max_groups=1")
    assert resp.status_code == 400
    assert "OTX_API_KEY" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_actor_otx_enrich_reports_missing_key(client: AsyncClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "otx_api_key", "")
    resp = await client.post("/api/ioc/actors/G0049/enrich/otx")
    assert resp.status_code == 400
    assert "OTX_API_KEY" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_virustotal_lookup_reports_missing_key(client: AsyncClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "virustotal_api_key", "")
    resp = await client.post("/api/ioc/virustotal/lookup", json={"indicator": "8.8.8.8"})
    assert resp.status_code == 400
    assert "VIRUSTOTAL_API_KEY" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_custom_ioc_source_kind_validation(client: AsyncClient):
    resp = await client.post(
        "/api/ioc/sources",
        json={"label": "Bad Feed", "url": "https://example.com/iocs", "kind": "custom-xml"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_custom_ioc_source_sync_missing_source(client: AsyncClient):
    resp = await client.post("/api/ioc/sync/custom-does-not-exist")
    assert resp.status_code == 400
    assert "not found" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ioc_stix_export_route_shape(client: AsyncClient):
    resp = await client.get("/api/ioc/library/export/stix", params={"limit": 10})
    assert resp.status_code == 200
    body = resp.json()
    assert body["type"] == "bundle"
    assert isinstance(body["objects"], list)


@pytest.mark.asyncio
async def test_ioc_stix_import_route_shape(client: AsyncClient, monkeypatch):
    from app.api.routes import ioc as ioc_route

    async def fake_import(session, bundle, source_label="STIX IOC Import", source_url=""):
        return {"source": "custom-stix-import", "inserted": 1, "updated": 0, "actor_links": 0, "items_seen": 1}

    monkeypatch.setattr(ioc_route, "import_ioc_stix_bundle", fake_import)
    resp = await client.post(
        "/api/ioc/import/stix",
        json={
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--11111111-1111-4111-8111-111111111111",
                    "pattern": "[domain-name:value = 'example.com']",
                    "pattern_type": "stix",
                }
            ],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["items_seen"] == 1
