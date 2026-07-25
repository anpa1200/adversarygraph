"""Private MCP client for the isolated vulnerability-assessment container."""

from __future__ import annotations

import ipaddress
import json
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent

from app.core.config import settings


_MAX_MCP_RESPONSE_BYTES = 8 * 1024 * 1024
_ASSESSMENT_TOOL = "run_authorized_asset_assessment"


class ScannerMCPError(RuntimeError):
    """A sanitized scanner-service failure safe to expose through the API."""


def validated_mcp_url(value: str | None = None) -> str:
    raw = str(settings.asset_scanner_mcp_url if value is None else value).strip()
    if not raw or len(raw) > 2_048 or any(ord(char) < 32 for char in raw):
        raise ScannerMCPError("Scanner MCP URL is missing or invalid")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ScannerMCPError("Scanner MCP URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ScannerMCPError("Scanner MCP URL must be HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise ScannerMCPError("Scanner MCP URL must not contain credentials")
    if parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/mcp":
        raise ScannerMCPError("Scanner MCP URL must use the fixed /mcp endpoint")
    if port is not None and not 1 <= port <= 65_535:
        raise ScannerMCPError("Scanner MCP URL has an invalid port")
    if parsed.scheme.lower() == "http" and not _private_service_host(parsed.hostname):
        raise ScannerMCPError("Plain HTTP scanner MCP is allowed only on a private service origin")
    return raw.rstrip("/")


def validated_service_token() -> str:
    token = str(settings.asset_scanner_mcp_token or "").strip()
    if (
        len(token) < 24
        or len(token) > 4_096
        or any(ord(char) <= 32 or ord(char) == 127 for char in token)
    ):
        raise ScannerMCPError("Scanner MCP service token is missing or invalid")
    return token


async def run_assessment(
    *,
    target: str,
    run_nmap: bool,
    run_web_probe: bool,
    additional_scanners: list[str],
) -> dict[str, Any]:
    """Execute one audited fixed tool plan over the MCP protocol."""

    result = await _call_tool(
        _ASSESSMENT_TOOL,
        {
            "target": target,
            "run_nmap_requested": bool(run_nmap),
            "run_web_requested": bool(run_web_probe),
            "additional_scanners": list(dict.fromkeys(additional_scanners)),
            "authorization_confirmed": True,
        },
    )
    required = {
        "service",
        "target",
        "resolved_ips",
        "nmap_result",
        "web_probe_result",
        "scanner_results",
        "tool_trace",
    }
    if not required.issubset(result):
        raise ScannerMCPError("Scanner MCP returned an incomplete assessment")
    if result.get("service") != "adversarygraph-scanner-mcp":
        raise ScannerMCPError("Scanner MCP returned an unexpected service identity")
    return result


async def list_tools() -> dict[str, Any]:
    return await _call_tool("list_assessment_tools", {})


async def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name not in {_ASSESSMENT_TOOL, "list_assessment_tools"}:
        raise ScannerMCPError("Scanner MCP tool is not allowlisted")
    timeout = min(max(float(settings.asset_scanner_mcp_timeout_seconds), 30.0), 1_000.0)
    headers = {
        "Authorization": f"Bearer {validated_service_token()}",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "AdversaryGraph-Scanner-MCP-Client/1",
    }
    try:
        async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout, connect=min(timeout, 10.0)),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
        ) as http_client:
            async with streamable_http_client(
                validated_mcp_url(),
                http_client=http_client,
            ) as (read_stream, write_stream, _):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    response = await session.call_tool(name, arguments)
    except ScannerMCPError:
        raise
    except Exception as exc:
        raise ScannerMCPError("Scanner MCP is unavailable or rejected the tool request") from exc

    if response.isError:
        raise ScannerMCPError("Scanner MCP tool failed safely")
    payload = response.structuredContent
    if payload is None:
        text_blocks = [block.text for block in response.content if isinstance(block, TextContent)]
        try:
            payload = json.loads("\n".join(text_blocks))
        except (json.JSONDecodeError, TypeError) as exc:
            raise ScannerMCPError("Scanner MCP returned invalid structured output") from exc
    if not isinstance(payload, dict):
        raise ScannerMCPError("Scanner MCP returned a non-object result")
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str)
    if len(encoded.encode("utf-8")) > _MAX_MCP_RESPONSE_BYTES:
        raise ScannerMCPError("Scanner MCP response exceeded the safety limit")
    return payload


def _private_service_host(host: str) -> bool:
    normalized = str(host or "").casefold().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return (
            "." not in normalized
            or normalized == "host.docker.internal"
            or normalized.endswith((".internal", ".local", ".svc", ".test", ".localhost"))
        )
    return bool(address.is_private or address.is_loopback or address.is_link_local)
