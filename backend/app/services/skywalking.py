"""Read-only Apache SkyWalking OAP query client.

SkyWalking observations are runtime telemetry, not threat-intelligence facts.
This adapter intentionally returns a small, provenance-rich graph and never
retrieves span bodies, logs, request payloads, or configured credentials.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import settings


class SkyWalkingError(RuntimeError):
    """A safe error suitable for an operator-facing API response."""


_HEALTH_QUERY = """
query AdversaryGraphSkyWalkingHealth {
  version
  checkHealth { score details }
}
"""

_GLOBAL_TOPOLOGY_QUERY = """
query AdversaryGraphGlobalTopology($duration: Duration!, $layer: String) {
  topology: getGlobalTopology(duration: $duration, layer: $layer) {
    nodes { id name type isReal layers }
    calls {
      id source target sourceComponents targetComponents detectPoints
    }
  }
}
"""

_SEARCH_SERVICES_QUERY = """
query AdversaryGraphSearchServices($duration: Duration!, $keyword: String!) {
  services: searchServices(duration: $duration, keyword: $keyword) {
    id name
  }
}
"""

_SERVICE_TOPOLOGY_QUERY = """
query AdversaryGraphServiceTopology($duration: Duration!, $serviceId: ID!) {
  topology: getServiceTopology(serviceId: $serviceId, duration: $duration) {
    nodes { id name type isReal layers }
    calls {
      id source target sourceComponents targetComponents detectPoints
    }
  }
}
"""


def _validated_endpoint() -> str:
    endpoint = settings.skywalking_graphql_url.strip()
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SkyWalkingError("SkyWalking GraphQL URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise SkyWalkingError("SkyWalking GraphQL URL must not contain credentials.")
    if parsed.query or parsed.fragment:
        raise SkyWalkingError("SkyWalking GraphQL URL must not contain a query or fragment.")
    return endpoint


def _duration(minutes: int) -> dict[str, str]:
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = end - timedelta(minutes=minutes)
    return {
        "start": start.strftime("%Y-%m-%d %H%M"),
        "end": end.strftime("%Y-%m-%d %H%M"),
        "step": "MINUTE",
    }


async def _graphql(
    query: str,
    variables: dict[str, Any] | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    if not settings.skywalking_enabled:
        raise SkyWalkingError("SkyWalking integration is disabled.")

    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if settings.skywalking_auth_token:
        headers["Authorization"] = f"Bearer {settings.skywalking_auth_token}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.skywalking_timeout_seconds),
            verify=settings.skywalking_verify_tls,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            response = await client.post(
                _validated_endpoint(),
                json={"query": query, "variables": variables or {}},
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.TimeoutException as exc:
        raise SkyWalkingError("SkyWalking OAP query timed out.") from exc
    except httpx.HTTPStatusError as exc:
        raise SkyWalkingError(f"SkyWalking OAP returned HTTP {exc.response.status_code}.") from exc
    except (httpx.RequestError, ValueError) as exc:
        raise SkyWalkingError("SkyWalking OAP connection or response validation failed.") from exc

    if not isinstance(payload, dict):
        raise SkyWalkingError("SkyWalking OAP returned an invalid GraphQL response.")
    errors = payload.get("errors")
    if errors:
        messages = [
            str(item.get("message", "GraphQL query failed"))[:240]
            for item in errors[:3]
            if isinstance(item, dict)
        ]
        raise SkyWalkingError("SkyWalking GraphQL error: " + "; ".join(messages or ["query failed"]))
    data = payload.get("data")
    if not isinstance(data, dict):
        raise SkyWalkingError("SkyWalking GraphQL response did not contain data.")
    return data


async def health(*, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    if not settings.skywalking_enabled:
        return {
            "enabled": False,
            "connected": False,
            "status": "disabled",
            "message": "Optional SkyWalking integration is disabled.",
        }
    try:
        data = await _graphql(_HEALTH_QUERY, transport=transport)
    except SkyWalkingError as exc:
        return {
            "enabled": True,
            "connected": False,
            "status": "unavailable",
            "message": str(exc),
        }
    health_status = data.get("checkHealth") if isinstance(data.get("checkHealth"), dict) else {}
    score = health_status.get("score")
    connected = isinstance(score, int) and score == 0
    return {
        "enabled": True,
        "connected": connected,
        "status": "ok" if connected else "degraded",
        "version": str(data.get("version") or "unknown")[:120],
        "health_score": score,
        "message": str(health_status.get("details") or ("Connected." if connected else "OAP reported an unhealthy state."))[:500],
    }


async def _service_id(
    keyword: str,
    duration: dict[str, str],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
) -> str | None:
    data = await _graphql(
        _SEARCH_SERVICES_QUERY,
        {"duration": duration, "keyword": keyword},
        transport=transport,
    )
    services = data.get("services") if isinstance(data.get("services"), list) else []
    normalized = keyword.casefold().strip()
    ranked = sorted(
        (item for item in services if isinstance(item, dict) and item.get("id")),
        key=lambda item: (
            str(item.get("name", "")).casefold() != normalized,
            normalized not in str(item.get("name", "")).casefold(),
            str(item.get("name", "")).casefold(),
        ),
    )
    return str(ranked[0]["id"]) if ranked else None


def _normalize_topology(
    topology: Any,
    *,
    minutes: int,
    scope: str,
    query: str = "",
) -> dict[str, Any]:
    raw = topology if isinstance(topology, dict) else {}
    raw_nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    raw_edges = raw.get("calls") if isinstance(raw.get("calls"), list) else []
    node_limit = settings.skywalking_max_topology_nodes

    nodes: list[dict[str, Any]] = []
    allowed_ids: set[str] = set()
    for item in raw_nodes[:node_limit]:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        node_id = str(item["id"])
        allowed_ids.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "label": str(item.get("name") or node_id)[:500],
                "node_type": "runtime_service",
                "technology": str(item.get("type") or "unknown")[:120],
                "layers": [str(value)[:80] for value in (item.get("layers") or [])[:20]],
                "observed": bool(item.get("isReal", False)),
                "source": "apache_skywalking",
                "evidence_kind": "runtime_observation",
            }
        )

    edges: list[dict[str, Any]] = []
    for item in raw_edges[: node_limit * 4]:
        if not isinstance(item, dict):
            continue
        source, target = str(item.get("source") or ""), str(item.get("target") or "")
        if source not in allowed_ids or target not in allowed_ids:
            continue
        edges.append(
            {
                "id": str(item.get("id") or f"{source}->{target}")[:500],
                "source": source,
                "target": target,
                "edge_type": "runtime_call",
                "source_components": [str(value)[:120] for value in (item.get("sourceComponents") or [])[:30]],
                "target_components": [str(value)[:120] for value in (item.get("targetComponents") or [])[:30]],
                "detect_points": [str(value)[:40] for value in (item.get("detectPoints") or [])[:10]],
                "source_system": "apache_skywalking",
                "evidence_kind": "runtime_observation",
            }
        )

    if query.strip():
        needle = query.casefold().strip()
        matched = {node["id"] for node in nodes if needle in node["label"].casefold() or needle in node["technology"].casefold()}
        adjacent = {
            endpoint
            for edge in edges
            if edge["source"] in matched or edge["target"] in matched
            for endpoint in (edge["source"], edge["target"])
        }
        retained = matched | adjacent
        nodes = [node for node in nodes if node["id"] in retained]
        edges = [edge for edge in edges if edge["source"] in retained and edge["target"] in retained]

    return {
        "source": "apache_skywalking",
        "scope": scope,
        "query": query,
        "window_minutes": minutes,
        "nodes": nodes,
        "edges": edges,
        "counts": {"nodes": len(nodes), "edges": len(edges)},
        "truncated": len(raw_nodes) > node_limit,
        "provenance": {
            "classification": "runtime_observation",
            "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "statement": "Observed service calls are telemetry, not proof of malicious activity or attribution.",
        },
    }


async def topology(
    *,
    minutes: int = 60,
    service: str = "",
    layer: str = "",
    query: str = "",
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    duration = _duration(minutes)
    if service.strip():
        service_id = await _service_id(service.strip(), duration, transport=transport)
        if service_id is None:
            return _normalize_topology({}, minutes=minutes, scope=f"service:{service.strip()}", query=query)
        data = await _graphql(
            _SERVICE_TOPOLOGY_QUERY,
            {"duration": duration, "serviceId": service_id},
            transport=transport,
        )
        scope = f"service:{service.strip()}"
    else:
        data = await _graphql(
            _GLOBAL_TOPOLOGY_QUERY,
            {"duration": duration, "layer": layer.strip() or None},
            transport=transport,
        )
        scope = f"layer:{layer.strip()}" if layer.strip() else "global"
    return _normalize_topology(data.get("topology"), minutes=minutes, scope=scope, query=query)
