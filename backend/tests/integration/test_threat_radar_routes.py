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
    asset_body = asset.json()

    duplicate = await client.post(
        f"/api/threat-radar/spaces/{space['id']}/assets",
        json={
            "asset_id": "PROD-BLUEFIELD-EDGE-001",
            "name": "Duplicate inventory identity",
        },
    )
    assert duplicate.status_code == 409

    update = await client.put(
        f"/api/threat-radar/spaces/{space['id']}/assets/{asset_body['id']}",
        json={
            "asset_id": asset_body["asset_id"],
            "name": "BlueField production edge gateway",
            "asset_type": "appliance",
            "environment": "production",
            "owner": "Product Security",
            "criticality": "high",
            "exposure": "internet",
            "products": ["BlueField-3"],
            "components": ["DPU management firmware"],
            "technologies": ["DOCA", "Linux", "Redfish"],
            "ip_addresses": ["192.0.2.44"],
            "domains": ["EDGE.EXAMPLE.TEST"],
            "tags": ["customer-facing", "edited-in-company-space"],
            "metadata": {"ports": [443, 8443]},
        },
    )
    assert update.status_code == 200
    updated_asset = update.json()
    assert updated_asset["id"] == asset_body["id"]
    assert updated_asset["asset_id"] == asset_body["asset_id"]
    assert updated_asset["name"] == "BlueField production edge gateway"
    assert updated_asset["owner"] == "Product Security"
    assert updated_asset["criticality"] == "high"
    assert updated_asset["products"] == ["bluefield-3"]
    assert updated_asset["domains"] == ["edge.example.test"]
    assert updated_asset["metadata"]["ports"] == ["443", "8443"]

    change_identity = await client.put(
        f"/api/threat-radar/spaces/{space['id']}/assets/{asset_body['id']}",
        json={
            "asset_id": "replacement-asset-id",
            "name": "BlueField production edge gateway",
        },
    )
    assert change_identity.status_code == 422

    asset_list = await client.get(
        f"/api/threat-radar/spaces/{space['id']}/assets",
        params={"q": "edited-in-company-space"},
    )
    assert asset_list.status_code == 200
    assert asset_list.json()["total"] == 1
    assert asset_list.json()["items"][0]["id"] == asset_body["id"]

    unified_after_edit = await client.get("/api/threat-radar/unified/entities")
    assert unified_after_edit.status_code == 200
    unified_asset = next(
        row for row in unified_after_edit.json()
        if row["entity_type"] == "asset"
        and row["metadata"].get("asset_uuid") == asset_body["id"]
    )
    assert unified_asset["label"] == "BlueField production edge gateway"
    assert unified_asset["metadata"]["products"] == ["bluefield-3"]
    inventory_relationships = unified_asset["metadata"].get("relationships", [])
    assert any(
        row["relationship"] == "runs-product" and row["target_value"] == "bluefield-3"
        for row in inventory_relationships
    )
    assert not any(
        row["relationship"] == "runs-product" and row["target_value"] == "bluefield"
        for row in inventory_relationships
    )

    create_signal = await client.post(
        "/api/threat-radar/signals",
        json={
            "title": "BlueField firmware dump claim",
            "signal_type": "firmware_dump_claim",
            "description": "Sanitized provider note references BlueField-3 DPU management firmware exposure.",
            "confidence": 75,
            "product_mappings": [
                {
                    "product": "BlueField-3",
                    "component": "DPU management firmware",
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
    assert "dpu-management-firmware" in [item.lower() for item in supply_chain_alerts["rows"][0]["matched_terms"]]
    persisted_alerts = await client.get(f"/api/threat-radar/spaces/{space['id']}/alerts")
    assert persisted_alerts.status_code == 200
    assert persisted_alerts.json()
    assert persisted_alerts.json()[0]["dedup_key"]
    assert persisted_alerts.json()[0]["status"] == "new"
    unified_asset = await client.get("/api/threat-radar/unified/entities?q=bluefield")
    assert unified_asset.status_code == 200
    entity_rows = unified_asset.json()
    assert any(item["entity_type"] == "asset" for item in entity_rows)
    assert any(item["entity_type"] == "product" and item["value"] == "bluefield-3" for item in entity_rows)
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
async def test_saved_assets_are_listed_and_have_evidence_labelled_detail(client: AsyncClient):
    space = await client.post(
        "/api/threat-radar/spaces",
        json={"name": "Asset Registry Detail Test"},
    )
    assert space.status_code == 201
    space_id = space.json()["id"]
    asset = await client.post(
        f"/api/threat-radar/spaces/{space_id}/assets",
        json={
            "asset_id": "edge-prod-01",
            "name": "Production edge appliance",
            "asset_type": "appliance",
            "environment": "production",
            "owner": "Platform Security",
            "criticality": "critical",
            "exposure": "internet",
            "products": ["EdgeShield"],
            "components": ["Management API"],
            "technologies": ["nginx"],
            "ip_addresses": ["192.0.2.44"],
            "domains": ["edge.example.test"],
            "metadata": {"ttp_candidates": ["T1190"]},
        },
    )
    assert asset.status_code == 201
    asset_id = asset.json()["id"]

    signal = await client.post(
        "/api/threat-radar/signals",
        json={
            "title": "EdgeShield exploitation report",
            "signal_type": "cisa_kev_active_exploitation",
            "description": "A source-backed report references the EdgeShield management API.",
            "source": {"name": "Vendor advisory", "source_type": "advisory"},
            "confidence": 88,
            "severity": "critical",
            "cve_ids": ["CVE-2026-45678"],
            "technique_ids": ["T1190"],
            "iocs": [{"value": "198.51.100.8", "type": "ip", "confidence": 75}],
            "product_mappings": [{
                "product": "EdgeShield",
                "component": "Management API",
                "exposure": "internet",
                "environment": "production",
                "relevance": 5,
                "blast_radius": 4,
            }],
        },
    )
    assert signal.status_code == 201
    dashboard = await client.post(
        f"/api/threat-radar/spaces/{space_id}/dashboards/generate"
    )
    assert dashboard.status_code == 201

    registry = await client.get(
        f"/api/threat-radar/spaces/{space_id}/assets",
        params={"q": "edge", "criticality": "critical"},
    )
    assert registry.status_code == 200
    assert registry.json()["total"] == 1
    assert registry.json()["items"][0]["id"] == asset_id

    detail = await client.get(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/intelligence"
    )
    assert detail.status_code == 200
    body = detail.json()
    assert body["asset"]["asset_id"] == "edge-prod-01"
    assert body["space"]["id"] == space_id
    assert body["summary"]["alerts"] >= 1
    assert any(row["cve_id"] == "CVE-2026-45678" for row in body["cves"])
    assert any(row["attack_id"] == "T1190" for row in body["ttps"])
    assert any(
        row["value"] == "198.51.100.8"
        and row["evidence_level"] == "matched-signal"
        for row in body["iocs"]
    )
    assert body["evidence_boundary"]
    assert body["recent_scans"] == []


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


@pytest.mark.asyncio
async def test_inventory_bound_asset_assessment_workflow(client: AsyncClient, monkeypatch):
    from app.api.routes import threat_radar as threat_radar_route

    space_response = await client.post(
        "/api/threat-radar/spaces",
        json={"name": "Authorized Scanner Test", "sector": "Technology"},
    )
    assert space_response.status_code == 201
    space_id = space_response.json()["id"]
    asset_response = await client.post(
        f"/api/threat-radar/spaces/{space_id}/assets",
        json={
            "asset_id": "edge-scanner-001",
            "name": "Authorized edge endpoint",
            "asset_type": "server",
            "environment": "production",
            "criticality": "high",
            "exposure": "internet",
            "ip_addresses": ["192.0.2.10"],
            "domains": ["edge.example.test"],
        },
    )
    assert asset_response.status_code == 201
    asset_id = asset_response.json()["id"]

    provider_response = await client.get("/api/threat-radar/asset-scanner/providers")
    assert provider_response.status_code == 200
    assert provider_response.json()["nmap"]["profile"] == "safe-service-discovery"
    assert "No NSE scripts" in provider_response.json()["nmap"]["boundary"]
    assert provider_response.json()["web"]["profile"] == "safe-root-http-posture"
    assert "No redirect following" in provider_response.json()["web"]["boundary"]

    missing_authorization = await client.post(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/scans",
        json={"target": "192.0.2.10"},
    )
    assert missing_authorization.status_code == 422

    outside_inventory = await client.post(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/scans",
        json={"target": "192.0.2.11", "authorization_confirmed": True},
    )
    assert outside_inventory.status_code == 422
    assert "not recorded" in outside_inventory.json()["detail"]

    async def fake_resolve(target):
        assert target.host == "192.0.2.10"
        return ["192.0.2.10"]

    async def fake_passive(session, target, providers, resolved):
        return ([{
            "source": "shodan",
            "status": "ok",
            "summary": "Shodan returned 1 open port.",
            "relationships": [{
                "source": target.value,
                "target": "443",
                "target_type": "service-port",
                "evidence_source": "shodan",
                "tier": 1,
                "evidence": "Open service port",
            }, {
                "source": target.value,
                "target": "edge-observed.example.test",
                "target_type": "domain",
                "evidence_source": "shodan",
                "tier": 1,
                "evidence": "Shodan hostname",
            }],
            "raw": {},
        }], [])

    async def fake_nmap(target, resolved):
        return {
            "status": "ok",
            "profile": "safe-service-discovery",
            "summary": "Nmap found 1 open service.",
            "open_port_count": 1,
            "hosts": [{
                "status": "up",
                "addresses": [{"address": "192.0.2.10", "type": "ipv4"}],
                "hostnames": [],
                "ports": [{
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "reason": "syn-ack",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.24",
                    "extra_info": "",
                    "tunnel": "ssl",
                    "cpes": ["cpe:/a:nginx:nginx:1.24"],
                }],
            }],
        }

    async def fake_cves(session, result):
        return [{
            "cve_id": "CVE-2026-12345",
            "severity": "HIGH",
            "score": "8.1",
            "known_exploited": False,
            "description": "Candidate only.",
            "matched_cpe": "cpe:/a:nginx:nginx:1.24",
            "status": "candidate",
            "verification_required": True,
            "note": "Verify the affected range.",
        }]

    async def fake_web_probe(target):
        return {
            "status": "ok",
            "profile": "safe-root-http-posture",
            "summary": "Safe web posture checked one endpoint.",
            "probes": [{
                "url": "https://192.0.2.10/",
                "status": "observed",
                "status_code": 200,
                "headers": {"server": "nginx"},
            }],
            "findings": [{
                "category": "web-posture",
                "severity": "low",
                "title": "Content-Security-Policy header not observed",
                "evidence": "Header absent.",
                "source": "safe-web-posture",
                "status": "observed",
                "verification_required": True,
            }],
        }

    monkeypatch.setattr(threat_radar_route.asset_scanner, "resolve_target", fake_resolve)
    monkeypatch.setattr(threat_radar_route.asset_scanner, "run_passive_assessment", fake_passive)
    monkeypatch.setattr(threat_radar_route.asset_scanner, "run_nmap_discovery", fake_nmap)
    monkeypatch.setattr(threat_radar_route.asset_scanner, "run_web_posture_probe", fake_web_probe)
    monkeypatch.setattr(threat_radar_route.asset_scanner, "match_local_cves", fake_cves)

    response = await client.post(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/scans",
        json={
            "target": "192.0.2.10",
            "providers": ["shodan"],
            "run_nmap": True,
            "run_web_probe": True,
            "update_inventory": True,
            "authorization_confirmed": True,
        },
    )
    assert response.status_code == 201
    scan = response.json()
    assert scan["status"] == "completed"
    assert scan["nmap_result"]["open_port_count"] == 1
    assert scan["web_probe_result"]["status"] == "ok"
    assert scan["inventory_update"]["changed"] is True
    assert scan["inventory_update"]["added"]["domains"] == ["edge-observed.example.test"]
    assert scan["inventory_update"]["added"]["ports"] == [443]
    assert "nginx" in scan["inventory_update"]["added"]["technologies"]
    assert scan["ai_analysis"]["provider"] == "deterministic"
    assert scan["ai_analysis"]["cve_candidates"][0]["verification_required"] is True
    assert any(item["category"] == "open-service" for item in scan["findings"])
    assert any(item["category"] == "local-cve-candidate" for item in scan["findings"])

    history = await client.get(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/scans"
    )
    assert history.status_code == 200
    assert history.json()[0]["id"] == scan["id"]

    detail = await client.get(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/scans/{scan['id']}"
    )
    assert detail.status_code == 200
    assert detail.json()["target_host"] == "192.0.2.10"

    updated_asset = await client.get(
        f"/api/threat-radar/spaces/{space_id}/assets/{asset_id}/intelligence"
    )
    assert updated_asset.status_code == 200
    assert "edge-observed.example.test" in updated_asset.json()["asset"]["domains"]
    assert 443 in updated_asset.json()["asset"]["metadata"]["ports"]
    assert updated_asset.json()["asset"]["metadata"]["last_surface_scan_id"] == scan["id"]


@pytest.mark.asyncio
async def test_active_asset_assessment_requires_simulation_permission(
    app,
    client,
    monkeypatch,
):
    async def analyst_without_active_scan():
        return TeamUser(
            name="analyst",
            roles=["analyst"],
            permissions=["read", "run_analysis", "manage_intel"],
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    app.dependency_overrides[current_user] = analyst_without_active_scan
    try:
        space = await client.post(
            "/api/threat-radar/spaces",
            json={"name": "Permission Scanner Test"},
        )
        assert space.status_code == 201
        asset = await client.post(
            f"/api/threat-radar/spaces/{space.json()['id']}/assets",
            json={
                "name": "Inventory target",
                "ip_addresses": ["192.0.2.20"],
            },
        )
        assert asset.status_code == 201
        denied = await client.post(
            f"/api/threat-radar/spaces/{space.json()['id']}/assets/{asset.json()['id']}/scans",
            json={
                "target": "192.0.2.20",
                "run_nmap": True,
                "authorization_confirmed": True,
            },
        )
        assert denied.status_code == 403
        assert "run_attack_simulation" in denied.json()["detail"]
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous
