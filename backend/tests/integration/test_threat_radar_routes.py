import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_threat_radar_signal_to_case_workflow(client: AsyncClient):
    payload = {
        "title": "CISA KEV exploitation against exposed gateway",
        "signal_type": "cisa_kev_active_exploitation",
        "description": "Active exploitation reported for a public-facing gateway component.",
        "source": {
            "name": "CISA KEV",
            "source_type": "kev",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "reliability": 5,
            "tlp": "TLP:CLEAR",
        },
        "confidence": 90,
        "severity": "critical",
        "cve_ids": ["CVE-2026-34909"],
        "technique_ids": ["T1190"],
        "product_mappings": [
            {
                "product": "Edge Gateway",
                "component": "Admin UI",
                "version": "4.2",
                "exposure": "internet",
                "environment": "production",
                "relevance": 5,
                "blast_radius": 4,
                "tags": ["customer-facing"],
                "technique_ids": ["T1190"],
            }
        ],
        "claims": [{"statement": "Confirmed active exploitation in the wild.", "credibility": 5}],
        "evidence": [{"title": "KEV entry", "summary": "Vendor advisory and KEV entry align."}],
        "create_case": True,
    }

    create = await client.post("/api/threat-radar/signals", json=payload)
    assert create.status_code == 201
    body = create.json()
    assert body["signal"]["score"]["score"] >= 80
    assert body["case"]["priority"] in {"P0 Emergency", "P1 High"}
    assert any(action["type"] == "psirt" for action in body["case"]["recommended_actions"])
    assert any(action["type"] == "hunt" for action in body["case"]["recommended_actions"])

    signal_id = body["signal"]["id"]
    case_id = body["case"]["id"]

    detail = await client.get(f"/api/threat-radar/signals/{signal_id}")
    assert detail.status_code == 200
    assert detail.json()["product_mappings"][0]["product"] == "edge-gateway"
    assert "product:edge-gateway" in detail.json()["product_mappings"][0]["tags"]
    assert "ttp:T1190" in detail.json()["product_mappings"][0]["tags"]

    product_map = await client.get("/api/threat-radar/product-exposure")
    assert product_map.status_code == 200
    assert any(item["product"] == "edge-gateway" for item in product_map.json())

    graph = await client.get(f"/api/threat-radar/cases/{case_id}/graph")
    assert graph.status_code == 200
    assert any(node["type"] == "cve" for node in graph.json()["nodes"])

    for path in ("create-hunt", "create-psirt-task", "create-ir-escalation", "create-detection-requirement"):
        response = await client.post(f"/api/threat-radar/cases/{case_id}/{path}")
        assert response.status_code == 201
        assert response.json()["case_id"] == case_id

    report = await client.post(f"/api/threat-radar/cases/{case_id}/generate-report", json={"report_type": "hunt_pack"})
    assert report.status_code == 201
    assert "Threat Hunt Pack" in report.json()["title"]
    assert "Product / Component Exposure" in report.json()["markdown"]


@pytest.mark.asyncio
async def test_threat_radar_restricted_signal_sanitizes_metadata(client: AsyncClient):
    create = await client.post(
        "/api/threat-radar/signals",
        json={
            "title": "Darknet source-code leak claim",
            "signal_type": "source_code_leak_claim",
            "description": "Sanitized provider metadata only.",
            "confidence": 70,
            "raw_metadata": {
                "forum": "provider-report",
                "password": "redaction-marker",
                "api_token": "redaction-marker",
            },
            "evidence": [
                {
                    "title": "Provider metadata",
                    "summary": "Claim mentions credential material and leaked files.",
                    "legal_sensitive": True,
                }
            ],
            "create_case": True,
        },
    )
    assert create.status_code == 201
    signal = create.json()["signal"]
    assert signal["legal_sensitive"] is True
    assert signal["raw_metadata"]["password"] == "[redacted]"
    assert "restricted_intelligence_handling" in signal["raw_metadata"]


@pytest.mark.asyncio
async def test_threat_radar_watchlists_and_queues(client: AsyncClient):
    response = await client.get("/api/threat-radar/watchlists/cve")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    for queue in ("hunts", "psirt", "ir", "detections", "reports", "actions", "audit"):
        queue_response = await client.get(f"/api/threat-radar/queues/{queue}")
        assert queue_response.status_code == 200
        assert isinstance(queue_response.json(), list)


@pytest.mark.asyncio
async def test_exposure_monitoring_provider_readiness_and_plan(client: AsyncClient):
    providers = await client.get("/api/threat-radar/exposure/providers")
    assert providers.status_code == 200
    provider_ids = {item["id"] for item in providers.json()}
    assert {"recorded-future", "virustotal-retrohunt", "virustotal-livehunt", "hibp", "darkowl", "kela"}.issubset(provider_ids)

    plan = await client.post(
        "/api/threat-radar/exposure/plan",
        json={
            "providers": ["recorded-future", "virustotal-retrohunt", "darkowl"],
            "watch_terms": [
                {"value": "BlueField", "type": "product", "products": ["BlueField"], "tags": ["product-security"]},
                {"value": "DPU firmware", "type": "component", "components": ["DPU firmware"], "tags": ["firmware"]},
            ],
        },
    )
    assert plan.status_code == 200
    body = plan.json()
    assert len(body["providers"]) == 3
    assert body["watch_terms"][0]["products"] == ["bluefield"]


@pytest.mark.asyncio
async def test_exposure_monitoring_classifies_prototype_sale(client: AsyncClient):
    response = await client.post(
        "/api/threat-radar/exposure/classify",
        json={
            "provider": "recorded-future",
            "title": "Engineering sample prototype offered for sale",
            "summary": "Sanitized provider note mentions BlueField engineering sample prototype for sale by broker.",
            "product": "BlueField",
            "component": "DPU firmware",
            "confidence": 65,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["signal_type"] == "marketplace_hardware_listing"
    assert body["confidence"] >= 75
    assert "tag:prototype-sale" in body["tags"]
    assert "product:bluefield" in body["tags"]


@pytest.mark.asyncio
async def test_exposure_monitoring_ingest_creates_case_and_sanitizes(client: AsyncClient):
    response = await client.post(
        "/api/threat-radar/exposure/ingest",
        json={
            "provider": "darkowl",
            "title": "Possible firmware dump claim",
            "summary": "Sanitized source claims firmware dump. Credential markers must be redacted.",
            "url": "https://provider.example/case/123",
            "product": "Jetson",
            "component": "bootloader",
            "confidence": 72,
            "metadata": {
                "api_token": "redaction-marker",
                "note": "credential marker appeared in analyst input",
            },
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["signal_id"]
    assert body["case_id"]
    assert body["classification"]["signal_type"] == "firmware_dump_claim"

    signal = await client.get(f"/api/threat-radar/signals/{body['signal_id']}")
    assert signal.status_code == 200
    data = signal.json()
    assert data["legal_sensitive"] is True
    assert data["raw_metadata"]["raw_metadata"] == "[redacted]" or "restricted_intelligence_handling" in data["raw_metadata"]
    assert any(mapping["product"] == "jetson" for mapping in data["product_mappings"])

    marketplace = await client.get("/api/threat-radar/queues/marketplace")
    assert marketplace.status_code == 200
    assert any(item["signal_id"] == body["signal_id"] for item in marketplace.json())
