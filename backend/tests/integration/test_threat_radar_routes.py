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
    assert detail.json()["product_mappings"][0]["product"] == "Edge Gateway"

    product_map = await client.get("/api/threat-radar/product-exposure")
    assert product_map.status_code == 200
    assert any(item["product"] == "Edge Gateway" for item in product_map.json())

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
                "password": "super-secret-password",
                "api_token": "abc123456789secret",
            },
            "evidence": [
                {
                    "title": "Provider metadata",
                    "summary": "Claim mentions password=super-secret-password and leaked files.",
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
