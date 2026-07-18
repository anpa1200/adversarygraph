from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.services.auth import TeamUser, current_user


@pytest.mark.asyncio
async def test_file_endpoints_require_upload_permission(
    app,
    client: AsyncClient,
    monkeypatch,
):
    async def analyst_without_upload():
        return TeamUser(
            name="no-upload-analyst",
            roles=["analyst", "viewer"],
            permissions=["read", "run_analysis", "manage_intel"],
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    app.dependency_overrides[current_user] = analyst_without_upload
    upload = {"file": ("sample.txt", b"sample content", "text/plain")}
    try:
        file_only_requests = (
            ("/api/malwaregraph/analyses", {}),
            ("/api/malwaregraph/analyses/job-1/inject-file", {}),
            ("/api/ioc/report", {}),
        )
        for path, data in file_only_requests:
            response = await client.post(path, data=data, files=upload)
            assert response.status_code == 403, path
            assert response.json()["detail"] == "Permission required: upload_files"

        optional_file_requests = (
            "/api/analyze",
            "/api/analyze/stream",
            "/api/analyze/log-pcap",
            "/api/analyze/sessions/research",
            "/api/asset-surface/analyze",
        )
        for path in optional_file_requests:
            response = await client.post(path, files=upload)
            assert response.status_code == 403, path
            assert response.json()["detail"] == "Permission required: upload_files"

        # The permission gates file transfer, not text-based analysis/storage.
        text_analysis = await client.post(
            "/api/analyze",
            data={"provider": "invalid-provider", "text": "text-only report"},
        )
        assert text_analysis.status_code == 400

        text_research = await client.post(
            "/api/analyze/sessions/research",
            data={"text": "text-only research", "name": "No upload"},
        )
        assert text_research.status_code == 200

        text_assets = await client.post(
            "/api/asset-surface/analyze",
            data={
                "use_ai": "false",
                "text": "vpn.example.com 198.51.100.20 ports 443 public vpn",
            },
        )
        assert text_assets.status_code == 200
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous
