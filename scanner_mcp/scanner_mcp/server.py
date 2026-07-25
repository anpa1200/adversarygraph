"""Authenticated Streamable-HTTP MCP server for isolated assessment tools."""

from __future__ import annotations

import contextlib
import hmac
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import AnyHttpUrl, Field
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .config import settings
from .models import normalize_target
from .scanners import (
    ADDITIONAL_SCANNERS,
    resolve_target,
    run_assessment_plan,
    run_dns,
    run_nmap,
    run_nuclei,
    run_tls,
    run_web,
    scanner_catalog,
)


class StaticServiceTokenVerifier(TokenVerifier):
    """Validate the private API-to-scanner capability token in constant time."""

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(str(token or ""), settings.scanner_mcp_token):
            return None
        return AccessToken(
            token=token,
            client_id="adversarygraph-api",
            scopes=["asset:assess"],
            resource=settings.scanner_mcp_public_url,
        )


_configured_service_host = urlsplit(settings.scanner_mcp_public_url).netloc
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=list(
        dict.fromkeys(
            [
                _configured_service_host,
                f"scanner-mcp:{settings.scanner_mcp_port}",
                f"127.0.0.1:{settings.scanner_mcp_port}",
                f"localhost:{settings.scanner_mcp_port}",
            ]
        )
    ),
    allowed_origins=[],
)
mcp = FastMCP(
    "AdversaryGraph Vulnerability Assessment",
    instructions=(
        "Bounded defensive assessment tools. Every executing tool requires an "
        "authorization decision already recorded by AdversaryGraph. Tools accept "
        "no shell arguments, exploit payloads, credentials, or arbitrary templates."
    ),
    token_verifier=StaticServiceTokenVerifier(),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(settings.scanner_mcp_public_url),
        resource_server_url=AnyHttpUrl(settings.scanner_mcp_public_url),
        required_scopes=["asset:assess"],
    ),
    host=settings.scanner_mcp_host,
    port=settings.scanner_mcp_port,
    streamable_http_path="/mcp",
    stateless_http=True,
    json_response=True,
    transport_security=_transport_security,
)

_READ_ONLY_NETWORK = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)


def _require_authorization(authorization_confirmed: bool) -> None:
    if authorization_confirmed is not True:
        raise ValueError(
            "An audited authorization decision is required before scanning"
        )


@mcp.tool(
    annotations=ToolAnnotations(
        readOnlyHint=True, destructiveHint=False, openWorldHint=False
    )
)
def list_assessment_tools() -> dict[str, Any]:
    """List fixed scanner profiles, readiness, bounds, and engine provenance."""

    return scanner_catalog()


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def resolve_asset_target(
    target: str = Field(min_length=1, max_length=2_048),
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Resolve one normalized inventory target with a fixed address limit."""

    _require_authorization(authorization_confirmed)
    normalized = normalize_target(target)
    return {
        "target": {
            "value": normalized.value,
            "host": normalized.host,
            "target_type": normalized.target_type,
        },
        "resolved_ips": await resolve_target(normalized),
    }


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def run_safe_service_discovery(
    target: str = Field(min_length=1, max_length=2_048),
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Run the fixed unprivileged Nmap TCP-connect discovery profile."""

    _require_authorization(authorization_confirmed)
    return await run_nmap(normalize_target(target))


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def run_safe_web_posture(
    target: str = Field(min_length=1, max_length=2_048),
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Inspect root HTTP(S) response posture without crawling or payloads."""

    _require_authorization(authorization_confirmed)
    return await run_web(normalize_target(target))


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def run_verified_tls_assessment(
    target: str = Field(min_length=1, max_length=2_048),
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Perform one verified TLS handshake against the exact target."""

    _require_authorization(authorization_confirmed)
    return await run_tls(normalize_target(target))


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def run_read_only_dns_posture(
    target: str = Field(min_length=1, max_length=2_048),
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Query a fixed A/AAAA/CAA/TXT/DNSKEY/DMARC record set."""

    _require_authorization(authorization_confirmed)
    return await run_dns(normalize_target(target))


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def run_bounded_nuclei_assessment(
    target: str = Field(min_length=1, max_length=2_048),
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Run pinned signed HTTP/TLS/DNS templates under fixed exclusions and limits."""

    _require_authorization(authorization_confirmed)
    return await run_nuclei(normalize_target(target))


@mcp.tool(annotations=_READ_ONLY_NETWORK)
async def run_authorized_asset_assessment(
    target: str = Field(min_length=1, max_length=2_048),
    run_nmap_requested: bool = False,
    run_web_requested: bool = False,
    additional_scanners: Annotated[
        list[Literal["tls", "dns", "nuclei"]],
        Field(max_length=3),
    ]
    | None = None,
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    """Execute one explicit bounded tool plan and return an AI-reviewable trace."""

    _require_authorization(authorization_confirmed)
    selected_scanners = list(additional_scanners or [])
    unknown = sorted(set(selected_scanners) - set(ADDITIONAL_SCANNERS))
    if unknown:
        raise ValueError(f"Unsupported scanner(s): {', '.join(unknown)}")
    return await run_assessment_plan(
        target,
        run_nmap_requested=run_nmap_requested,
        run_web_requested=run_web_requested,
        additional_scanners=selected_scanners,
    )


async def health(_request: Request) -> JSONResponse:
    catalog = scanner_catalog()
    tools = catalog["tools"]
    unavailable = [
        row["id"]
        for row in tools
        if row.get("configured", True) and not row.get("enabled", False)
    ]
    return JSONResponse(
        {
            "status": "ready" if not unavailable else "degraded",
            "service": catalog["service"],
            "version": catalog["version"],
            "transport": catalog["transport"],
            "tool_count": len(tools),
            "unavailable_tools": unavailable,
        },
        status_code=200 if not unavailable else 503,
    )


@contextlib.asynccontextmanager
async def lifespan(_app: Starlette):
    async with mcp.session_manager.run():
        yield


app = Starlette(
    routes=[
        Route("/health", endpoint=health, methods=["GET"]),
        Mount("/", app=mcp.streamable_http_app()),
    ],
    lifespan=lifespan,
)
