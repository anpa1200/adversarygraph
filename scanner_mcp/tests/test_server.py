from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from scanner_mcp import server


@pytest.mark.asyncio
async def test_mcp_exposes_only_bounded_scanner_tools():
    tools = {tool.name: tool for tool in await server.mcp.list_tools()}
    assert set(tools) == {
        "list_assessment_tools",
        "resolve_asset_target",
        "run_safe_service_discovery",
        "run_safe_web_posture",
        "run_verified_tls_assessment",
        "run_read_only_dns_posture",
        "run_bounded_nuclei_assessment",
        "run_authorized_asset_assessment",
    }
    assert "shell" not in tools
    assert "execute_command" not in tools
    for name, tool in tools.items():
        assert tool.annotations.destructiveHint is False
        if name.startswith("run_"):
            assert tool.annotations.openWorldHint is True


@pytest.mark.asyncio
async def test_executing_tool_rejects_missing_authorization():
    with pytest.raises(ValueError, match="authorization"):
        await server.run_safe_service_discovery(
            target="192.0.2.10",
            authorization_confirmed=False,
        )
    with pytest.raises(ValueError, match="authorization"):
        await server.resolve_asset_target(
            target="192.0.2.10",
            authorization_confirmed=False,
        )


@pytest.mark.asyncio
async def test_static_service_token_verifier_is_fail_closed():
    verifier = server.StaticServiceTokenVerifier()
    assert await verifier.verify_token("wrong-token-value-that-is-long-enough") is None
    accepted = await verifier.verify_token(server.settings.scanner_mcp_token)
    assert accepted is not None
    assert accepted.scopes == ["asset:assess"]


def test_dns_rebinding_policy_allows_configured_service_origin():
    configured_host = urlsplit(server.settings.scanner_mcp_public_url).netloc
    assert server._transport_security.enable_dns_rebinding_protection is True
    assert configured_host in server._transport_security.allowed_hosts
    assert server._transport_security.allowed_origins == []
