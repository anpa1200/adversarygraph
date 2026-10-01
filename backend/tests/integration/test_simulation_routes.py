import pytest


def _ai_attack_flow_result():
    return {
        "run_id": "run-test-flow",
        "mode": "actor",
        "ai_provider": "local",
        "ai_model": "deterministic-test",
        "ai_used": False,
        "ai_error": "",
        "ai_planner_summary": "Generated deterministic test chain.",
        "scenario": {
            "id": "apt29-identity-chain",
            "name": "APT29-style identity chain",
        },
        "complicated_attack": True,
        "actor_profile": "apt29",
        "technique_ids": ["T1589.002", "T1110.001", "T1078"],
        "attack_plan": {
            "summary": "Password spray to valid-account foothold.",
            "phases": [
                {"technique_id": "T1589.002", "name": "User Enumeration", "event_count": 2},
                {"technique_id": "T1110.001", "name": "Password Spraying", "event_count": 3},
                {"technique_id": "T1078", "name": "Valid Account", "event_count": 1},
            ],
        },
        "events": [
            {
                "timestamp": "2026-06-30T12:00:00Z",
                "source": "application_auth",
                "event_id": "AG-AUTH-USER-ENUM",
                "technique_id": "T1589.002",
                "message": "Username enumeration response differential",
            },
            {
                "timestamp": "2026-06-30T12:00:03Z",
                "source": "windows_security",
                "event_id": "4625",
                "technique_id": "T1110.001",
                "message": "Failed logon for shared password candidate",
            },
        ],
        "delivery": {
            "ok": True,
            "status": 200,
            "error": "",
            "destination_url": "http://127.0.0.1:30304/logeye/api/logger.jsp?source=test",
            "event_count": 2,
            "sent_event_count": 2,
            "duration_ms": 12,
        },
        "log_file": "/tmp/adversarygraph-test-logs/attack-simulation/ai-assistant-telemetry.jsonl",
    }


@pytest.mark.asyncio
async def test_simulation_catalog_route(client):
    response = await client.get("/api/simulation/catalog")
    assert response.status_code == 200
    assert any(item["technique_id"] == "T1595" for item in response.json())


@pytest.mark.asyncio
async def test_simulation_plan_route(client):
    response = await client.post(
        "/api/simulation/plan",
        json={"simulation_id": "sim-t1595-http-fingerprint", "target_id": "lab-web-01"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is True
    assert payload["execution_mode"] == "dry_run_required"


@pytest.mark.asyncio
async def test_simulation_run_record_route_collects_local_web_telemetry(client):
    response = await client.post(
        "/api/simulation/run",
        json={"simulation_id": "sim-t1595-http-fingerprint", "target_id": "lab-web-01", "analyst_note": "route test"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["traffic_emitted"] is True
    assert payload["status"] == "completed_with_local_lab_telemetry"
    assert payload["telemetry"]["server"]["url"].startswith(("http://127.0.0.1:", "http://attack-lab-web:"))
    assert payload["telemetry"]["request_count"] == 2
    logs = await client.get("/api/simulation/logs", params={"source": "web", "run_id": payload["run_id"], "limit": 10})
    assert logs.status_code == 200
    log_payload = logs.json()
    assert log_payload["exists"] is True
    assert log_payload["events"]
    assert all(item["run_id"] == payload["run_id"] for item in log_payload["events"])


@pytest.mark.asyncio
async def test_simulation_forward_logs_rejects_unsafe_scheme(client):
    response = await client.post(
        "/api/simulation/forward-logs",
        json={"source": "web", "destination_url": "file:///tmp/collector", "limit": 10},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_synthetic_evidence_validate_route_preserves_boundary(client, monkeypatch):
    async def fake_validate(_scenario_yaml):
        return {
            "valid": True,
            "scenario_sha256": "a" * 64,
            "output": "Scenario is valid",
            "synthetic_only": True,
        }

    monkeypatch.setattr(
        "app.api.routes.simulation.synthetic_evidence.validate_scenario",
        fake_validate,
    )
    response = await client.post(
        "/api/simulation/synthetic/validate",
        json={"scenario_yaml": "name: training-only"},
    )
    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()["synthetic_only"] is True


@pytest.mark.asyncio
async def test_synthetic_evidence_generation_records_quality_and_provenance(client, monkeypatch):
    async def fake_generate(scenario_yaml, *, target, formats):
        assert scenario_yaml == "name: deterministic-training"
        assert target == "splunk"
        assert formats == ["windows", "zeek"]
        return {
            "run_id": "synthetic-11111111-1111-4111-8111-111111111111",
            "synthetic_only": True,
            "engine": "EvidenceForge",
            "engine_version": "1.13.0",
            "engine_ref": "a68836bc10ea55971e2ce984b9e47eb4d01b7246",
            "scenario_sha256": "b" * 64,
            "target": "splunk",
            "artifact_count": 3,
            "artifacts": [],
            "quality": {"available": True, "acceptance_passed": True, "total_records": 120},
        }

    monkeypatch.setattr(
        "app.api.routes.simulation.synthetic_evidence.generate",
        fake_generate,
    )
    response = await client.post(
        "/api/simulation/synthetic/runs",
        json={
            "scenario_name": "Detection exercise",
            "scenario_yaml": "name: deterministic-training",
            "target": "splunk",
            "formats": ["windows", "zeek"],
            "technique_ids": ["T1059.001"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["quality_passed"] is True
    assert body["validation_ready"] is True
    assert body["synthetic_only"] is True
    assert "not observed production telemetry" in body["evidence_boundary"]

    async def fake_download(run_id):
        assert run_id == body["run_id"]
        return b"PK synthetic zip"

    monkeypatch.setattr(
        "app.api.routes.simulation.synthetic_evidence.download_bundle",
        fake_download,
    )
    bundle = await client.get(f"/api/simulation/synthetic/runs/{body['run_id']}/bundle")
    assert bundle.status_code == 200
    assert bundle.headers["content-type"] == "application/zip"
    assert bundle.content == b"PK synthetic zip"


@pytest.mark.asyncio
async def test_simulation_forward_logs_rejects_query_string_credentials(client):
    response = await client.post(
        "/api/simulation/forward-logs",
        json={
            "source": "web",
            "destination_url": "https://siem.example.test/collector?access_token=secret",
            "limit": 10,
        },
    )
    assert response.status_code == 400
    assert "query parameters" in response.json()["detail"]


@pytest.mark.asyncio
async def test_completed_ai_delivery_reports_destination_persistence_warning(client, monkeypatch):
    async def fake_run_ai_assistant_telemetry_simulation(**kwargs):
        result = _ai_attack_flow_result()
        # Simulate an upstream sender returning a URL that is unsafe to store
        # after the delivery has already completed.
        result["delivery"]["destination_url"] = (
            "http://127.0.0.1:30304/logeye/api/logger.jsp?token=must-not-be-stored"
        )
        return result

    monkeypatch.setattr(
        "app.api.routes.simulation.external_simulation.run_ai_assistant_telemetry_simulation",
        fake_run_ai_assistant_telemetry_simulation,
    )

    response = await client.post(
        "/api/simulation/ai-assistant/telemetry",
        json={
            "mode": "challenge",
            "ai_provider": "local",
            "destination_url": "http://127.0.0.1:30304/logeye/api/logger.jsp?source=request",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["delivery"]["ok"] is True
    assert body["delivery"]["destination_url"] == ""
    assert body["destination_persistence"]["saved"] is False
    assert "Delivery completed" in body["destination_persistence"]["warning"]
    flows = (await client.get("/api/simulation/attack-flows")).json()
    assert flows[0]["delivery"]["destination_url"] == ""


@pytest.mark.asyncio
async def test_ai_assistant_attack_flow_is_saved_and_listed(client, monkeypatch):
    async def fake_run_ai_assistant_telemetry_simulation(**kwargs):
        result = _ai_attack_flow_result()
        result["mode"] = kwargs["mode"]
        result["ai_provider"] = kwargs["ai_provider"]
        result["complicated_attack"] = kwargs["complicated_attack"]
        result["delivery"]["destination_url"] = kwargs["destination_url"]
        return result

    monkeypatch.setattr(
        "app.api.routes.simulation.external_simulation.run_ai_assistant_telemetry_simulation",
        fake_run_ai_assistant_telemetry_simulation,
    )

    response = await client.post(
        "/api/simulation/ai-assistant/telemetry",
        json={
            "mode": "actor",
            "ai_provider": "local",
            "complicated_attack": True,
            "actor_profile": "apt29",
            "destination_url": "http://127.0.0.1:30304/logeye/api/logger.jsp?source=test",
            "payload_format": "per_event",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["run_id"] == "run-test-flow"
    assert payload["delivery"]["sent_event_count"] == 2

    listed = await client.get("/api/simulation/attack-flows")
    assert listed.status_code == 200
    flows = listed.json()
    assert len(flows) == 1
    flow = flows[0]
    assert flow["run_id"] == "run-test-flow"
    assert flow["scenario_name"] == "APT29-style identity chain"
    assert flow["summary"] == "Password spray to valid-account foothold."
    assert flow["technique_ids"] == ["T1589.002", "T1110.001", "T1078"]
    assert flow["event_count"] == 2
    assert flow["events"][1]["event_id"] == "4625"


@pytest.mark.asyncio
async def test_saved_attack_flow_can_be_resent(client, monkeypatch):
    async def fake_run_ai_assistant_telemetry_simulation(**kwargs):
        result = _ai_attack_flow_result()
        result["delivery"]["destination_url"] = kwargs["destination_url"]
        return result

    captured = {}

    def fake_resend_ai_assistant_telemetry_events(**kwargs):
        captured["stored_result"] = kwargs["stored_result"]
        captured["destination_url"] = kwargs["destination_url"]
        return {
            "ok": True,
            "status": 202,
            "error": "",
            "destination_url": kwargs["destination_url"],
            "event_count": len(kwargs["stored_result"]["events"]),
            "sent_event_count": len(kwargs["stored_result"]["events"]),
            "duration_ms": 4,
        }

    monkeypatch.setattr(
        "app.api.routes.simulation.external_simulation.run_ai_assistant_telemetry_simulation",
        fake_run_ai_assistant_telemetry_simulation,
    )
    monkeypatch.setattr(
        "app.api.routes.simulation.external_simulation.resend_ai_assistant_telemetry_events",
        fake_resend_ai_assistant_telemetry_events,
    )

    created = await client.post(
        "/api/simulation/ai-assistant/telemetry",
        json={
            "mode": "challenge",
            "ai_provider": "local",
            "destination_url": "http://127.0.0.1:30304/logeye/api/logger.jsp?source=first",
        },
    )
    assert created.status_code == 200
    flows = (await client.get("/api/simulation/attack-flows")).json()
    flow_id = flows[0]["id"]

    resent = await client.post(
        f"/api/simulation/attack-flows/{flow_id}/resend",
        json={
            "destination_url": "http://127.0.0.1:30304/logeye/api/logger.jsp?source=second",
            "payload_format": "per_event",
        },
    )
    assert resent.status_code == 200
    payload = resent.json()
    assert payload["delivery"]["status"] == 202
    assert payload["delivery"]["sent_event_count"] == 2
    assert payload["flow"]["last_delivery_ok"] is True
    assert payload["flow"]["last_delivery_status"] == 202
    assert captured["stored_result"]["run_id"] == "run-test-flow"
    assert captured["stored_result"]["events"][0]["technique_id"] == "T1589.002"
