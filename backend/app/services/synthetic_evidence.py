from __future__ import annotations

from typing import Any

import httpx

from app.core.config import get_settings


class SyntheticEvidenceError(RuntimeError):
    pass


async def _request(method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    settings = get_settings()
    if not settings.evidenceforge_enabled:
        raise SyntheticEvidenceError("EvidenceForge synthetic evidence service is disabled")
    try:
        async with httpx.AsyncClient(
            timeout=settings.evidenceforge_timeout_seconds,
            follow_redirects=False,
        ) as client:
            response = await client.request(
                method,
                f"{settings.evidenceforge_url.rstrip('/')}{path}",
                json=payload,
            )
    except httpx.HTTPError as exc:
        raise SyntheticEvidenceError(f"EvidenceForge service is unavailable: {exc}") from exc
    if response.status_code >= 400:
        raise SyntheticEvidenceError(
            f"EvidenceForge returned HTTP {response.status_code}: {response.text[:4000]}"
        )
    return response.json()


async def status() -> dict[str, Any]:
    return await _request("GET", "/health")


async def templates() -> list[dict[str, Any]]:
    result = await _request("GET", "/templates")
    return result if isinstance(result, list) else []


async def validate_scenario(scenario_yaml: str) -> dict[str, Any]:
    return await _request("POST", "/validate", {"scenario_yaml": scenario_yaml})


async def generate(scenario_yaml: str, *, target: str, formats: list[str]) -> dict[str, Any]:
    return await _request(
        "POST",
        "/generate",
        {"scenario_yaml": scenario_yaml, "target": target, "formats": formats},
    )


async def download_bundle(run_id: str) -> bytes:
    result = await _request_bytes("GET", f"/runs/{run_id}/bundle")
    return result


async def _request_bytes(method: str, path: str) -> bytes:
    settings = get_settings()
    if not settings.evidenceforge_enabled:
        raise SyntheticEvidenceError("EvidenceForge synthetic evidence service is disabled")
    try:
        async with httpx.AsyncClient(timeout=settings.evidenceforge_timeout_seconds) as client:
            response = await client.request(method, f"{settings.evidenceforge_url.rstrip('/')}{path}")
    except httpx.HTTPError as exc:
        raise SyntheticEvidenceError(f"EvidenceForge service is unavailable: {exc}") from exc
    if response.status_code >= 400:
        raise SyntheticEvidenceError(f"EvidenceForge returned HTTP {response.status_code}")
    if len(response.content) > 268_435_456:
        raise SyntheticEvidenceError("Synthetic evidence bundle exceeds the 256 MiB API limit")
    return response.content
