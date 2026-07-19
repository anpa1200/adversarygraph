"""Local, advisory-only MCP facade for AdversaryGraph unified intelligence.

The server intentionally exposes only four fixed RAG API operations over the
MCP stdio transport.  It is a separate process from the FastAPI application;
all authorization, TLP policy, retrieval, citation binding, and audit controls
remain enforced by the AdversaryGraph API.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import sys
from enum import Enum
from typing import Annotated, Any, Literal, TypeAlias
from urllib.parse import quote, urlsplit

import httpx
from pydantic import Field
from pydantic_settings import BaseSettings

try:  # Keep diagnostics importable when the optional process dependency is absent.
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations
except ImportError as exc:  # pragma: no cover - exercised only in incomplete installs
    FastMCP = None  # type: ignore[assignment,misc]
    ToolAnnotations = None  # type: ignore[assignment,misc]
    _MCP_IMPORT_ERROR: ImportError | None = exc
else:
    _MCP_IMPORT_ERROR = None


logger = logging.getLogger(__name__)


class MCPSettings(BaseSettings):
    """Minimal subprocess configuration; MCP never needs database credentials."""

    mcp_transport: Literal["stdio"] = "stdio"
    # The supported default is a host-side stdio process talking through the
    # loopback-only Compose proxy. A separately containerized MCP process must
    # opt into the internal http://api:8000 origin explicitly.
    mcp_api_base_url: str = "http://127.0.0.1:3000"
    mcp_api_token: str = ""
    auth_enabled: bool = False

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = MCPSettings()

SourceType: TypeAlias = Literal[
    "attack_technique",
    "attack_group",
    "attack_campaign",
    "actor_intel",
    "ioc",
    "cve",
    "analysis_report",
    "knowledge",
    "threat_signal",
    "threat_hunt",
    "evidence_node",
    "asset",
]
AttackDomain: TypeAlias = Literal[
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
    "atlas",
]
Query: TypeAlias = Annotated[str, Field(min_length=1, max_length=2_000)]
SourceId: TypeAlias = Annotated[str, Field(min_length=1, max_length=255)]
SearchLimit: TypeAlias = Annotated[int, Field(ge=1, le=25)]
ProfileId: TypeAlias = Annotated[int | None, Field(ge=1, le=2_147_483_647)]
SourceFilters: TypeAlias = Annotated[list[SourceType] | None, Field(max_length=12)]

SUPPORTED_SOURCE_TYPES = frozenset(SourceType.__args__)
SUPPORTED_DOMAINS = frozenset(AttackDomain.__args__)
_MAX_API_BASE_URL = 2_048
_MAX_API_TOKEN = 4_096
_MAX_JSON_DEPTH = 4
_MAX_JSON_KEYS = 100
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_TECHNIQUE_ID = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|AML\.[A-Z0-9][A-Z0-9._:-]{0,31})$")


class MCPConfigurationError(RuntimeError):
    """The MCP process is not configured to start safely."""


class MCPInputError(ValueError):
    """A tool argument failed the local MCP trust-boundary validation."""


class MCPAPIError(RuntimeError):
    """A sanitized AdversaryGraph API failure safe to return to an MCP client."""


class _Endpoint(Enum):
    SEARCH = ("POST", "/api/rag/search", 30.0, 2 * 1024 * 1024)
    ASSIST = ("POST", "/api/rag/assist", 70.0, _MAX_RESPONSE_BYTES)
    ENTITY = ("GET", "/api/rag/entity", 30.0, _MAX_RESPONSE_BYTES)

    @property
    def method(self) -> str:
        return self.value[0]

    @property
    def path(self) -> str:
        return self.value[1]

    @property
    def timeout_seconds(self) -> float:
        return self.value[2]

    @property
    def max_response_bytes(self) -> int:
        return self.value[3]


def _validated_base_url(value: str | None = None) -> str:
    raw = str(settings.mcp_api_base_url if value is None else value).strip()
    if not raw or len(raw) > _MAX_API_BASE_URL or any(ord(char) < 32 for char in raw):
        raise MCPConfigurationError("MCP_API_BASE_URL is missing or invalid")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise MCPConfigurationError("MCP_API_BASE_URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise MCPConfigurationError("MCP_API_BASE_URL must be an HTTP(S) origin")
    if parsed.username is not None or parsed.password is not None:
        raise MCPConfigurationError("MCP_API_BASE_URL must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise MCPConfigurationError("MCP_API_BASE_URL must be an origin without a path, query, or fragment")
    if port is not None and not 1 <= port <= 65_535:
        raise MCPConfigurationError("MCP_API_BASE_URL has an invalid port")
    if parsed.scheme.lower() == "http" and not _is_private_api_host(parsed.hostname):
        raise MCPConfigurationError(
            "Plain HTTP is allowed only for loopback, private IP, or private service DNS origins"
        )
    return f"{parsed.scheme.lower()}://{parsed.netloc}".rstrip("/")


def _is_private_api_host(value: str | None) -> bool:
    host = str(value or "").casefold().rstrip(".")
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return (
            "." not in host
            or host == "host.docker.internal"
            or host.endswith((".localhost", ".internal", ".local", ".svc", ".test"))
        )
    return bool(address.is_private or address.is_loopback or address.is_link_local)


def _validated_api_token() -> str:
    token = str(settings.mcp_api_token or "").strip()
    if len(token) > _MAX_API_TOKEN or any(ord(char) <= 32 or ord(char) == 127 for char in token):
        raise MCPConfigurationError("MCP_API_TOKEN is invalid")
    if settings.auth_enabled and not token:
        raise MCPConfigurationError(
            "MCP_API_TOKEN is required because AUTH_ENABLED=true; use a dedicated analyst session token"
        )
    return token


def _build_url(
    endpoint: _Endpoint,
    *,
    source_type: str | None = None,
    source_id: str | None = None,
) -> str:
    if not isinstance(endpoint, _Endpoint):
        raise MCPConfigurationError("The requested API operation is not allowlisted")
    path = endpoint.path
    if endpoint is _Endpoint.ENTITY:
        normalized_type = _validated_source_type(source_type)
        normalized_id = _bounded_text(source_id, "source_id", 255)
        path = f"{path}/{quote(normalized_type, safe='')}/{quote(normalized_id, safe='')}"
    elif source_type is not None or source_id is not None:
        raise MCPConfigurationError("Dynamic path values are allowed only for indexed entity lookup")
    return f"{_validated_base_url()}{path}"


def _new_http_client(timeout_seconds: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_seconds, connect=min(10.0, timeout_seconds)),
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=5, max_keepalive_connections=2),
    )


async def _request_json(
    endpoint: _Endpoint,
    *,
    body: dict[str, Any] | None = None,
    source_type: str | None = None,
    source_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(endpoint, _Endpoint):
        raise MCPConfigurationError("The requested API operation is not allowlisted")
    if endpoint.method == "GET" and body is not None:
        raise MCPConfigurationError("GET operations cannot include a request body")
    if endpoint.method == "POST" and not isinstance(body, dict):
        raise MCPConfigurationError("POST operations require a bounded JSON object")

    token = _validated_api_token()
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "AdversaryGraph-MCP/1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = _build_url(endpoint, source_type=source_type, source_id=source_id)
    try:
        async with _new_http_client(endpoint.timeout_seconds) as client:
            async with client.stream(
                endpoint.method,
                url,
                headers=headers,
                json=body if endpoint.method == "POST" else None,
            ) as response:
                if response.status_code >= 400:
                    raise _sanitized_http_error(endpoint, response.status_code)
                declared_size = response.headers.get("content-length", "")
                try:
                    if declared_size and int(declared_size) > endpoint.max_response_bytes:
                        raise MCPAPIError("AdversaryGraph API response exceeded the MCP safety limit")
                except ValueError:
                    pass
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > endpoint.max_response_bytes:
                        raise MCPAPIError("AdversaryGraph API response exceeded the MCP safety limit")
                    content.extend(chunk)
    except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as exc:
        logger.warning("MCP API request failed endpoint=%s error=%s", endpoint.name, type(exc).__name__)
        raise MCPAPIError("Unable to reach the AdversaryGraph API") from exc
    except httpx.HTTPError as exc:
        logger.warning("MCP API request failed endpoint=%s error=%s", endpoint.name, type(exc).__name__)
        raise MCPAPIError("AdversaryGraph API request failed safely") from exc

    try:
        payload = json.loads(content)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise MCPAPIError("AdversaryGraph API returned an invalid JSON response") from exc
    if not isinstance(payload, dict):
        raise MCPAPIError("AdversaryGraph API returned an unexpected response shape")
    return payload


def _sanitized_http_error(endpoint: _Endpoint, status_code: int) -> MCPAPIError:
    logger.warning("MCP API rejected request endpoint=%s status=%s", endpoint.name, status_code)
    if status_code in {401, 403}:
        return MCPAPIError("AdversaryGraph API rejected the MCP credentials or permissions")
    if status_code == 404 and endpoint is _Endpoint.ENTITY:
        return MCPAPIError("The requested indexed entity was not found")
    if status_code == 409:
        return MCPAPIError("Indexed evidence is unavailable or changed; refresh the RAG index and retry")
    if status_code == 422:
        return MCPAPIError("AdversaryGraph rejected the validated MCP request")
    if status_code == 429:
        return MCPAPIError("AdversaryGraph rate-limited the MCP request; retry later")
    if status_code >= 500:
        return MCPAPIError("AdversaryGraph API is temporarily unavailable")
    return MCPAPIError("AdversaryGraph API rejected the MCP request")


async def search_intelligence(
    query: Query,
    source_types: SourceFilters = None,
    domain: AttackDomain = "enterprise-attack",
    client_profile_id: ProfileId = None,
    limit: SearchLimit = 12,
) -> dict[str, Any]:
    """Search the governed IOC, CVE, ATT&CK, report, and related RAG corpus."""

    normalized_query = _bounded_text(query, "query", 2_000)
    normalized_sources = _validated_source_types(source_types)
    normalized_domain = _validated_domain(domain)
    normalized_profile = _validated_profile_id(client_profile_id)
    normalized_limit = _bounded_int(limit, "limit", 1, 25)
    payload = await _request_json(
        _Endpoint.SEARCH,
        body={
            "query": normalized_query,
            "source_types": normalized_sources,
            "domain": normalized_domain,
            "client_profile_id": normalized_profile,
            "limit": normalized_limit,
        },
    )
    return _search_output(payload, normalized_query, normalized_limit)


async def ask_intelligence(
    question: Query,
    source_types: SourceFilters = None,
    domain: AttackDomain = "enterprise-attack",
    client_profile_id: ProfileId = None,
    limit: SearchLimit = 12,
) -> dict[str, Any]:
    """Ask the local governed AI for a citation-bound answer over retrieved evidence."""

    normalized_question = _bounded_text(question, "question", 2_000)
    normalized_sources = _validated_source_types(source_types)
    normalized_domain = _validated_domain(domain)
    normalized_profile = _validated_profile_id(client_profile_id)
    normalized_limit = _bounded_int(limit, "limit", 1, 25)
    payload = await _request_json(
        _Endpoint.ASSIST,
        body={
            "query": normalized_question,
            "source_types": normalized_sources,
            "domain": normalized_domain,
            "client_profile_id": normalized_profile,
            "limit": normalized_limit,
            # MCP deliberately cannot acknowledge cloud processing on a user's behalf.
            "provider": "local",
            "cloud_processing_acknowledged": False,
        },
    )
    return _assistance_output(payload)


async def get_indexed_entity(
    source_type: SourceType,
    source_id: SourceId,
) -> dict[str, Any]:
    """Read one sanitized indexed entity and its source/chunk provenance."""

    normalized_type = _validated_source_type(source_type)
    normalized_id = _bounded_text(source_id, "source_id", 255)
    payload = await _request_json(
        _Endpoint.ENTITY,
        source_type=normalized_type,
        source_id=normalized_id,
    )
    return _entity_output(payload)


async def propose_navigator_layer(
    objective: Query,
    domain: AttackDomain = "enterprise-attack",
    client_profile_id: ProfileId = None,
) -> dict[str, Any]:
    """Request an evidence-backed Navigator suggestion without confirming or applying it."""

    normalized_objective = _bounded_text(objective, "objective", 2_000)
    normalized_domain = _validated_domain(domain)
    normalized_profile = _validated_profile_id(client_profile_id)
    question = (
        f"{normalized_objective}\n\n"
        "Map and preview a reviewed ATT&CK Navigator layer from only the retrieved evidence. "
        "Return a proposal only; do not claim that it was confirmed, applied, or saved."
    )
    payload = await _request_json(
        _Endpoint.ASSIST,
        body={
            "query": question[:4_000],
            "source_types": [],
            "domain": normalized_domain,
            "client_profile_id": normalized_profile,
            "limit": 25,
            "provider": "local",
            "cloud_processing_acknowledged": False,
        },
    )
    assistance = _assistance_output(payload)
    return {
        "answer": assistance["answer"],
        "citations": assistance["citations"],
        "cautions": assistance["cautions"],
        "warnings": assistance["warnings"],
        "navigator_proposal": assistance["navigator_proposal"],
        "retrieval_mode": assistance["retrieval_mode"],
        "effective_tlp": assistance["effective_tlp"],
        "requires_human_review": True,
        "confirmation_performed": False,
        "navigator_state_changed": False,
        "saved_layer_created": False,
        "execution_boundary": assistance["execution_boundary"],
    }


def _bounded_text(value: Any, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise MCPInputError(f"{label} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise MCPInputError(f"{label} must contain between 1 and {maximum} characters")
    if "\x00" in normalized or any(ord(char) < 32 and char not in "\n\r\t" for char in normalized):
        raise MCPInputError(f"{label} contains unsupported control characters")
    return normalized


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise MCPInputError(f"{label} must be an integer between {minimum} and {maximum}")
    return value


def _validated_profile_id(value: Any) -> int | None:
    if value is None:
        return None
    return _bounded_int(value, "client_profile_id", 1, 2_147_483_647)


def _validated_domain(value: Any) -> str:
    if not isinstance(value, str) or value not in SUPPORTED_DOMAINS:
        raise MCPInputError(f"domain must be one of: {', '.join(sorted(SUPPORTED_DOMAINS))}")
    return value


def _validated_source_type(value: Any) -> str:
    if not isinstance(value, str) or value not in SUPPORTED_SOURCE_TYPES:
        raise MCPInputError("source_type is not supported by the unified intelligence index")
    return value


def _validated_source_types(values: Any) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list) or len(values) > len(SUPPORTED_SOURCE_TYPES):
        raise MCPInputError("source_types must be a list with no more than 12 entries")
    normalized: list[str] = []
    for value in values:
        source_type = _validated_source_type(value)
        if source_type not in normalized:
            normalized.append(source_type)
    return normalized


def _search_output(payload: dict[str, Any], query: str, limit: int) -> dict[str, Any]:
    raw_items = payload.get("items")
    items = [_search_item(item) for item in raw_items[:limit] if isinstance(item, dict)] if isinstance(raw_items, list) else []
    return {
        "query": query,
        "retrieval_mode": _safe_string(payload.get("retrieval_mode"), 80),
        "items": items,
        "warnings": _safe_string_list(payload.get("warnings"), 30, 1_000),
        "corpus_indexed_at": _safe_string(payload.get("corpus_indexed_at"), 80),
        "provenance_preserved": True,
    }


def _search_item(item: dict[str, Any]) -> dict[str, Any]:
    source_type = _safe_string(item.get("source_type"), 40)
    source_id = _safe_string(item.get("source_id"), 255)
    content_hash = _safe_string(item.get("content_hash"), 128)
    return {
        "chunk_id": _safe_string(item.get("chunk_id"), 80),
        "document_id": _safe_string(item.get("document_id"), 80),
        "source_type": source_type,
        "source_id": source_id,
        "title": _safe_string(item.get("title"), 700),
        "excerpt": _safe_string(item.get("excerpt"), 10_000),
        "route": _safe_string(item.get("route") or item.get("canonical_route"), 1_000),
        "domain": _safe_string(item.get("domain"), 80),
        "tlp": _safe_string(item.get("tlp"), 32),
        "legal_sensitive": bool(item.get("legal_sensitive", False)),
        "score": _safe_number(item.get("score")),
        "lexical_score": _safe_number(item.get("lexical_score")),
        "vector_score": _safe_number(item.get("vector_score")),
        "exact_match": bool(item.get("exact_match", False)),
        "retrieval_signals": _safe_string_list(item.get("retrieval_signals"), 10, 40),
        "content_hash": content_hash,
        "indexed_at": _safe_string(item.get("indexed_at") or item.get("source_updated_at"), 80),
        "metadata": _safe_json(item.get("metadata")),
        "provenance": {
            "source_type": source_type,
            "source_id": source_id,
            "content_hash": content_hash,
        },
    }


def _assistance_output(payload: dict[str, Any]) -> dict[str, Any]:
    citations = payload.get("citations")
    normalized_citations = (
        [_citation(item) for item in citations[:30] if isinstance(item, dict)]
        if isinstance(citations, list)
        else []
    )
    return {
        "assistance_id": _safe_string(payload.get("assistance_id"), 80),
        "provider": _safe_string(payload.get("provider"), 40),
        "model": _safe_string(payload.get("model"), 160),
        "retrieval_mode": _safe_string(payload.get("retrieval_mode"), 80),
        "effective_tlp": _safe_string(payload.get("effective_tlp"), 32),
        "answer": _safe_string(payload.get("answer"), 12_000),
        "citations": normalized_citations,
        "entities": _safe_json_list(payload.get("entities"), 100),
        "cautions": _safe_string_list(payload.get("cautions"), 20, 2_000),
        "warnings": _safe_string_list(payload.get("warnings"), 30, 2_000),
        "navigator_proposal": _proposal(payload.get("navigator_proposal")),
        "requires_human_review": True,
        "execution_boundary": _safe_string(payload.get("execution_boundary"), 1_000)
        or (
            "Advisory output only. No Navigator state, saved layer, hunt, indicator, "
            "vulnerability, or response action was changed."
        ),
        "provenance_preserved": bool(normalized_citations),
    }


def _citation(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_ref": _safe_string(item.get("source_ref"), 8),
        "source_type": _safe_string(item.get("source_type"), 40),
        "source_id": _safe_string(item.get("source_id"), 255),
        "title": _safe_string(item.get("title"), 700),
        "excerpt": _safe_string(item.get("excerpt"), 4_000),
        "route": _safe_string(item.get("route"), 1_000),
        "tlp": _safe_string(item.get("tlp"), 32),
        "legal_sensitive": bool(item.get("legal_sensitive", False)),
        "score": _safe_number(item.get("score")),
        "verified": item.get("verified") is True,
    }


def _proposal(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    technique_values = value.get("technique_ids")
    technique_ids: list[str] = []
    if isinstance(technique_values, list):
        for raw in technique_values[:100]:
            candidate = _safe_string(raw, 40).upper()
            if candidate and _TECHNIQUE_ID.fullmatch(candidate) and candidate not in technique_ids:
                technique_ids.append(candidate)
    return {
        "id": _safe_string(value.get("id"), 80),
        "name": _safe_string(value.get("name"), 255),
        "domain": _safe_string(value.get("domain"), 80),
        "attack_version": _safe_string(value.get("attack_version"), 80),
        "technique_ids": technique_ids,
        "rationale": _safe_string(value.get("rationale"), 5_000),
        "proposal_checksum": _safe_string(value.get("proposal_checksum"), 64),
        "expires_at": _safe_string(value.get("expires_at"), 80),
        "requires_confirmation": True,
    }


def _entity_output(payload: dict[str, Any]) -> dict[str, Any]:
    chunks = payload.get("chunks")
    normalized_chunks: list[dict[str, Any]] = []
    remaining_chars = 160_000
    if isinstance(chunks, list):
        for raw in chunks[:100]:
            if not isinstance(raw, dict) or remaining_chars <= 0:
                continue
            content = _safe_string(raw.get("content"), min(10_000, remaining_chars))
            remaining_chars -= len(content)
            normalized_chunks.append({
                "id": _safe_string(raw.get("id"), 80),
                "ordinal": _safe_integer(raw.get("ordinal"), 0, 100_000),
                "content": content,
                "content_hash": _safe_string(raw.get("content_hash"), 128),
                "token_count": _safe_integer(raw.get("token_count"), 0, 10_000_000),
                "embedding_status": _safe_string(raw.get("embedding_status"), 40),
            })
    source_type = _safe_string(payload.get("source_type"), 40)
    source_id = _safe_string(payload.get("source_id"), 255)
    content_hash = _safe_string(payload.get("content_hash"), 128)
    return {
        "document_id": _safe_string(payload.get("document_id"), 80),
        "source_type": source_type,
        "source_id": source_id,
        "source_version": _safe_string(payload.get("source_version"), 120),
        "logical_key": _safe_string(payload.get("logical_key"), 500),
        "title": _safe_string(payload.get("title"), 700),
        "canonical_route": _safe_string(payload.get("canonical_route"), 1_000),
        "domain": _safe_string(payload.get("domain"), 80),
        "tlp": _safe_string(payload.get("tlp"), 32),
        "legal_sensitive": bool(payload.get("legal_sensitive", False)),
        "content_hash": content_hash,
        "source_updated_at": _safe_string(payload.get("source_updated_at"), 80),
        "indexed_at": _safe_string(payload.get("indexed_at"), 80),
        "metadata": _safe_json(payload.get("metadata")),
        "chunk_count": _safe_integer(payload.get("chunk_count"), 0, 10_000_000),
        "chunks_truncated": bool(payload.get("chunks_truncated", False)),
        "chunks": normalized_chunks,
        "provenance": {
            "source_type": source_type,
            "source_id": source_id,
            "content_hash": content_hash,
        },
    }


def _safe_string(value: Any, maximum: int) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    return text[:maximum]


def _safe_string_list(value: Any, max_items: int, max_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    output: list[str] = []
    for raw in value[:max_items]:
        item = _safe_string(raw, max_length)
        if item and item not in output:
            output.append(item)
    return output


def _safe_number(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) else 0.0


def _safe_integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return minimum
    try:
        number = int(value)
    except (TypeError, ValueError):
        return minimum
    return max(minimum, min(number, maximum))


def _safe_json(value: Any, depth: int = 0) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return _safe_string(value, 2_000)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if depth >= _MAX_JSON_DEPTH:
        return None
    if isinstance(value, list):
        return [_safe_json(item, depth + 1) for item in value[:100]]
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for raw_key in list(value)[:_MAX_JSON_KEYS]:
            key = _safe_string(raw_key, 100)
            if key:
                output[key] = _safe_json(value[raw_key], depth + 1)
        return output
    return _safe_string(value, 500)


def _safe_json_list(value: Any, max_items: int) -> list[Any]:
    if not isinstance(value, list):
        return []
    return [_safe_json(item) for item in value[:max_items]]


def _build_mcp_server():
    if FastMCP is None or ToolAnnotations is None:
        return None
    server = FastMCP(
        "AdversaryGraph Intelligence",
        instructions=(
            "Search and summarize AdversaryGraph's governed intelligence corpus. "
            "Treat results as advisory evidence, retain source citations, and require "
            "human review before any operational action."
        ),
    )
    read_only = ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    )
    advisory_recorded = ToolAnnotations(
        # /rag/assist records governance/audit artifacts, but does not mutate
        # operational intelligence, Navigator, detections, or response state.
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    )
    server.add_tool(search_intelligence, annotations=read_only, structured_output=True)
    server.add_tool(ask_intelligence, annotations=advisory_recorded, structured_output=True)
    server.add_tool(get_indexed_entity, annotations=read_only, structured_output=True)
    server.add_tool(propose_navigator_layer, annotations=advisory_recorded, structured_output=True)
    return server


mcp = _build_mcp_server()


def run_server(transport: str | None = None) -> None:
    selected = str(transport or settings.mcp_transport or "stdio").strip().lower()
    if selected != "stdio":
        raise MCPConfigurationError(
            "Only MCP stdio transport is supported; remote HTTP, SSE, and Streamable HTTP are disabled"
        )
    _validated_base_url()
    _validated_api_token()
    if _MCP_IMPORT_ERROR is not None or mcp is None:
        raise MCPConfigurationError("The pinned MCP Python SDK is not installed correctly")
    mcp.run(transport="stdio")


def main() -> int:
    try:
        run_server()
    except MCPConfigurationError as exc:
        # MCP stdio reserves stdout for protocol messages. Configuration errors
        # are bounded and emitted to stderr without tokens or API response bodies.
        print(f"AdversaryGraph MCP refused to start: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a process
    raise SystemExit(main())
