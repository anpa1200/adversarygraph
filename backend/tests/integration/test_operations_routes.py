import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_operations_lists_return_arrays(client: AsyncClient):
    for path in ("investigations", "intake", "detections", "tracked-actors"):
        response = await client.get(f"/api/operations/{path}")
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    invalid = await client.get("/api/operations/investigations", params={"limit": 0})
    oversized = await client.get("/api/operations/intake", params={"limit": 501})
    assert invalid.status_code == 422
    assert oversized.status_code == 422


@pytest.mark.asyncio
async def test_investigation_validation(client: AsyncClient):
    response = await client.post("/api/operations/investigations", json={"name": ""})
    assert response.status_code == 422

    oversized = await client.post(
        "/api/operations/investigations",
        json={"name": "valid", "description": "x" * 100_001},
    )
    assert oversized.status_code == 422


@pytest.mark.asyncio
async def test_detection_validation(client: AsyncClient):
    response = await client.post("/api/operations/detections", json={"title": "Candidate"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_invalid_operational_id(client: AsyncClient):
    response = await client.delete("/api/operations/investigations/not-a-uuid")
    assert response.status_code == 400


# ── Investigations CRUD ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_investigation_create_update_delete(client: AsyncClient):
    payload = {
        "name": "Test investigation",
        "description": "Created by route test",
        "status": "active",
        "domain": "enterprise-attack",
        "actor_ids": ["G0007"],
        "technique_ids": ["T1059"],
        "report_ids": [],
    }
    create = await client.post("/api/operations/investigations", json=payload)
    assert create.status_code == 201
    item_id = create.json()["id"]
    assert create.json()["name"] == "Test investigation"

    update = await client.put(
        f"/api/operations/investigations/{item_id}",
        json={**payload, "name": "Updated investigation", "status": "closed"},
    )
    assert update.status_code == 200
    assert update.json()["name"] == "Updated investigation"
    assert update.json()["status"] == "closed"

    delete = await client.delete(f"/api/operations/investigations/{item_id}")
    assert delete.status_code == 204

    gone = await client.delete(f"/api/operations/investigations/{item_id}")
    assert gone.status_code == 404


# ── Intake CRUD ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_intake_create_update_delete(client: AsyncClient):
    payload = {
        "title": "Test intake report",
        "url": "https://example.com/report",
        "publisher": "Test publisher",
        "status": "pending",
    }
    create = await client.post("/api/operations/intake", json=payload)
    assert create.status_code == 201
    item_id = create.json()["id"]
    assert create.json()["title"] == "Test intake report"

    update = await client.put(
        f"/api/operations/intake/{item_id}",
        json={**payload, "status": "reviewed", "analyst_notes": "Reviewed and filed"},
    )
    assert update.status_code == 200
    assert update.json()["status"] == "reviewed"

    delete = await client.delete(f"/api/operations/intake/{item_id}")
    assert delete.status_code == 204

    gone = await client.delete(f"/api/operations/intake/{item_id}")
    assert gone.status_code == 404


# ── Detection Candidates CRUD ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detection_create_update_delete(client: AsyncClient):
    payload = {
        "title": "Suspicious PowerShell execution",
        "technique_id": "T1059.001",
        "status": "idea",
        "query_language": "sigma",
        "query": "selection:\n  CommandLine|contains: powershell",
    }
    create = await client.post("/api/operations/detections", json=payload)
    assert create.status_code == 201
    item_id = create.json()["id"]
    assert create.json()["title"] == "Suspicious PowerShell execution"

    update = await client.put(
        f"/api/operations/detections/{item_id}",
        json={**payload, "status": "candidate", "owner": "analyst@example.com"},
    )
    assert update.status_code == 200
    assert update.json()["status"] == "candidate"

    delete = await client.delete(f"/api/operations/detections/{item_id}")
    assert delete.status_code == 204


# ── Tracked Actors CRUD ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tracked_actor_create_and_delete(client: AsyncClient):
    payload = {
        "actor_id": "G0007",
        "actor_name": "APT28",
        "snapshot": {"technique_ids": ["T1059", "T1078"]},
    }
    create = await client.post("/api/operations/tracked-actors", json=payload)
    assert create.status_code == 201
    item_id = create.json()["id"]
    assert create.json()["actor_id"] == "G0007"

    delete = await client.delete(f"/api/operations/tracked-actors/{item_id}")
    assert delete.status_code == 204
