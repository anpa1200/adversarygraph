from __future__ import annotations

from collections import Counter

import pytest


HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put"}


def _operations(schema):
    for path, path_item in schema["paths"].items():
        for method, operation in path_item.items():
            if method.lower() in HTTP_METHODS:
                yield path, method.upper(), operation


def test_every_api_operation_has_a_complete_openapi_contract(app):
    schema = app.openapi()
    items = list(_operations(schema))
    operation_ids = [operation["operationId"] for _, _, operation in items]

    assert len(items) >= 300
    assert len(operation_ids) == len(set(operation_ids))
    assert all(path.startswith("/api/") for path, _, _ in items)
    assert all(operation.get("tags") for _, _, operation in items)
    assert all(operation.get("summary") for _, _, operation in items)

    for path, method, operation in items:
        success_responses = {
            str(code): response
            for code, response in operation["responses"].items()
            if str(code).startswith("2")
        }
        assert success_responses, f"{method} {path} has no successful response"
        for code, response in success_responses.items():
            if code != "204":
                assert response.get("content"), (
                    f"{method} {path} {code} has no response media type/schema"
                )


def test_every_supported_module_is_exposed_in_openapi(app):
    schema = app.openapi()
    module_counts = Counter(
        tag
        for _, _, operation in _operations(schema)
        for tag in operation["tags"]
    )
    documented_tags = {
        tag["name"]: tag.get("description", "")
        for tag in schema.get("tags", [])
    }

    assert len(module_counts) >= 28
    assert set(module_counts) == set(documented_tags)
    assert all(documented_tags.values())
    assert module_counts["ATT&CK"] >= 1
    assert module_counts["Analysis"] >= 1
    assert module_counts["Attack Simulation"] >= 1
    assert module_counts["CVE Intelligence"] >= 1
    assert module_counts["IOC Intelligence"] >= 1
    assert module_counts["Threat Hunting"] >= 1
    assert module_counts["Unified Intelligence RAG"] >= 1
    assert module_counts["System"] >= 1


@pytest.mark.asyncio
async def test_capabilities_endpoint_matches_the_active_contract(client, app):
    response = await client.get("/api/system/capabilities")
    assert response.status_code == 200

    payload = response.json()
    expected = list(_operations(app.openapi()))
    assert payload["name"] == "AdversaryGraph API"
    assert payload["version"] == app.version
    assert payload["operation_count"] == len(expected)
    assert payload["path_count"] == len(app.openapi()["paths"])
    assert payload["module_count"] == len(payload["modules"])
    assert payload["openapi_url"] == "/openapi.json"
    assert payload["docs_url"] == "/docs"

    advertised = {
        (operation["method"], operation["path"], operation["operation_id"])
        for module in payload["modules"]
        for operation in module["operations"]
    }
    contracted = {
        (method, path, operation["operationId"])
        for path, method, operation in expected
    }
    assert advertised == contracted


def test_binary_exports_publish_their_real_media_types(app):
    paths = app.openapi()["paths"]

    assert "application/pdf" in paths["/api/export/analysis/{session_id}"]["get"]["responses"]["200"]["content"]
    assert "application/pdf" in paths["/api/export/analysis/{session_id}"]["post"]["responses"]["200"]["content"]
    assert "application/stix+json" in paths["/api/export/analysis/{session_id}/stix"]["get"]["responses"]["200"]["content"]
    assert "application/pdf" in paths["/api/export/layer"]["post"]["responses"]["200"]["content"]
