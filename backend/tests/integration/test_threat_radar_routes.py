import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.services.auth import TeamUser, current_user


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
        "tlp": "TLP:CLEAR",
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

    unified = await client.get("/api/threat-radar/unified/entities")
    assert unified.status_code == 200
    unified_entities = unified.json()
    assert any(item["entity_type"] == "product" and item["value"] == "edge-gateway" for item in unified_entities)
    assert any(
        item["entity_type"] == "signal"
        and any(rel["relationship"] == "mentions-cve" and rel["target_value"] == "CVE-2026-34909" for rel in item["metadata"].get("relationships", []))
        for item in unified_entities
    )

    hunt_response = await client.post(f"/api/threat-radar/cases/{case_id}/create-hunt")
    assert hunt_response.status_code == 201
    hunt = hunt_response.json()
    assert hunt["case_id"] == case_id
    assert hunt["source_type"] == "threat_radar"
    assert hunt["source_ref"] == case_id
    assert hunt["priority"] == body["case"]["priority"]
    assert hunt["tlp"] == "TLP:CLEAR"
    assert hunt["owner"] == "local"
    assert hunt["created_by"] == "local"
    assert hunt["status"] == "queued"
    assert hunt["telemetry"]
    assert hunt["description"] == payload["description"]

    for path in ("create-psirt-task", "create-ir-escalation", "create-detection-requirement"):
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
async def test_company_space_assets_monitors_and_ai_steps(client: AsyncClient):
    create_space = await client.post(
        "/api/threat-radar/spaces",
        json={
            "name": "NVIDIA Product Security",
            "description": "Private monitored space for products, assets, and exposure signals.",
            "owner": "PSIRT",
            "sector": "Technology",
            "region": "Global",
            "tags": ["product-security", "gpu"],
        },
    )
    assert create_space.status_code == 201
    space = create_space.json()
    assert space["slug"] == "nvidia-product-security"
    assert space["counts"]["dashboards"] == 1
    assert space["counts"]["monitors"] == 2

    metrics = await client.get("/api/threat-radar/spaces/metrics")
    assert metrics.status_code == 200
    assert metrics.json()["spaces"] >= 1

    asset = await client.post(
        f"/api/threat-radar/spaces/{space['id']}/assets",
        json={
            "asset_id": "prod-bluefield-edge-001",
            "name": "BlueField edge gateway",
            "asset_type": "appliance",
            "environment": "production",
            "owner": "Platform Security",
            "criticality": "critical",
            "exposure": "internet",
            "products": ["BlueField"],
            "components": ["DPU firmware"],
            "technologies": ["DOCA", "Linux"],
            "domains": ["edge.example.test"],
            "tags": ["customer-facing"],
        },
    )
    assert asset.status_code == 201
    assert asset.json()["products"] == ["bluefield"]
    assert asset.json()["criticality"] == "critical"

    create_signal = await client.post(
        "/api/threat-radar/signals",
        json={
            "title": "BlueField firmware dump claim",
            "signal_type": "firmware_dump_claim",
            "description": "Sanitized provider note references BlueField DPU firmware exposure.",
            "confidence": 75,
            "product_mappings": [
                {
                    "product": "BlueField",
                    "component": "DPU firmware",
                    "exposure": "internet",
                    "environment": "production",
                    "relevance": 5,
                    "blast_radius": 4,
                }
            ],
            "create_case": True,
        },
    )
    assert create_signal.status_code == 201

    detail = await client.get(f"/api/threat-radar/spaces/{space['id']}")
    assert detail.status_code == 200
    monitors = detail.json()["monitors"]
    assert monitors

    run = await client.post(f"/api/threat-radar/spaces/{space['id']}/monitors/{monitors[0]['id']}/run")
    assert run.status_code == 200
    run_body = run.json()
    assert run_body["last_result"]["asset_count"] == 1
    assert run_body["last_result"]["match_count"] >= 1

    dashboard = await client.post(f"/api/threat-radar/spaces/{space['id']}/dashboards/generate")
    assert dashboard.status_code == 201
    dashboard_body = dashboard.json()
    assert dashboard_body["dashboard_type"] == "threat-monitor"
    widget_ids = {widget["id"] for widget in dashboard_body["widgets"]}
    assert {
        "status-strip",
        "alert-asset-match",
        "alert-technology-match",
        "alert-supply-chain-match",
        "alerts",
        "cve-exposure",
        "breach-leak-exposure",
    }.issubset(widget_ids)
    assert not {"space-readiness", "space-assets", "asset-exposure", "product-pressure", "workflow-queues", "ai-next-actions"} & widget_ids
    alerts = next(widget for widget in dashboard_body["widgets"] if widget["id"] == "alerts")
    assert alerts["metrics"][0]["value"] >= 1
    supply_chain_alerts = next(widget for widget in dashboard_body["widgets"] if widget["id"] == "alert-supply-chain-match")
    assert supply_chain_alerts["metrics"][0]["value"] >= 1
    assert supply_chain_alerts["rows"][0]["match_type"] == "supply-chain"
    assert "dpu-firmware" in [item.lower() for item in supply_chain_alerts["rows"][0]["matched_terms"]]
    persisted_alerts = await client.get(f"/api/threat-radar/spaces/{space['id']}/alerts")
    assert persisted_alerts.status_code == 200
    assert persisted_alerts.json()
    assert persisted_alerts.json()[0]["dedup_key"]
    assert persisted_alerts.json()[0]["status"] == "new"
    unified_asset = await client.get("/api/threat-radar/unified/entities?q=bluefield")
    assert unified_asset.status_code == 200
    entity_rows = unified_asset.json()
    assert any(item["entity_type"] == "asset" for item in entity_rows)
    assert any(item["entity_type"] == "product" and item["value"] == "bluefield" for item in entity_rows)
    assert any(item["entity_type"] == "alert" for item in entity_rows)
    search = await client.post(
        f"/api/threat-radar/spaces/{space['id']}/search",
        json={"query": "match_type:supply-chain | stats count by priority", "limit": 25},
    )
    assert search.status_code == 200
    assert search.json()["matched"] >= 1
    assert search.json()["rows"][0]["match_type"] == "supply-chain"
    update_alert = await client.post(
        f"/api/threat-radar/spaces/{space['id']}/alerts/{persisted_alerts.json()[0]['id']}/status",
        json={"status": "triaged", "assignee": "psirt"},
    )
    assert update_alert.status_code == 200
    assert update_alert.json()["status"] == "triaged"
    ai = await client.post(
        f"/api/threat-radar/spaces/{space['id']}/ai-assistant",
        json={"step": "upload_inventory", "context": {"goal": "prepare PSIRT relevance matching"}},
    )
    assert ai.status_code == 200
    assert "inventory" in ai.json()["title"].lower()
    assert len(ai.json()["checklist"]) >= 3


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


@pytest.mark.asyncio
async def test_detection_engineer_cannot_mutate_cti_or_read_radar_audit(app, client, monkeypatch):
    async def detection_engineer():
        return TeamUser(
            name="detection-engineer",
            roles=["detection_engineer", "analyst", "viewer"],
            permissions=["read", "run_analysis", "manage_detections", "export_data"],
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    app.dependency_overrides[current_user] = detection_engineer
    try:
        assert (await client.get("/api/threat-radar/sources")).status_code == 200
        denied_source = await client.post(
            "/api/threat-radar/sources",
            json={"name": "Unauthorized feed", "source_type": "manual"},
        )
        assert denied_source.status_code == 403
        assert (await client.get("/api/threat-radar/queues/audit")).status_code == 403

        # The detection permission passes; validation then rejects the fake case ID.
        detection = await client.post(
            "/api/threat-radar/cases/not-a-uuid/create-detection-requirement"
        )
        assert detection.status_code == 400
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous
