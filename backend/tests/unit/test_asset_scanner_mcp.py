from __future__ import annotations

import pytest

from app.services import asset_scanner_mcp


def test_scanner_mcp_url_is_fixed_to_private_mcp_endpoint():
    assert (
        asset_scanner_mcp.validated_mcp_url("http://scanner-mcp:8200/mcp")
        == "http://scanner-mcp:8200/mcp"
    )
    for value in (
        "http://public.example.com/mcp",
        "http://scanner-mcp:8200/admin",
        "http://scanner-mcp:8200/mcp?tool=shell",
        "file:///tmp/scanner",
        "http://user:secret@scanner-mcp:8200/mcp",
    ):
        with pytest.raises(asset_scanner_mcp.ScannerMCPError):
            asset_scanner_mcp.validated_mcp_url(value)


@pytest.mark.asyncio
async def test_assessment_calls_only_fixed_composite_tool(monkeypatch):
    calls = []

    async def fake_call(name, arguments):
        calls.append((name, arguments))
        return {
            "service": "adversarygraph-scanner-mcp",
            "target": {"host": "example.com", "target_type": "domain"},
            "resolved_ips": ["203.0.113.10"],
            "nmap_result": {"status": "ok"},
            "web_probe_result": {"status": "ok"},
            "scanner_results": {"tls": {"status": "ok"}},
            "tool_trace": [{"tool": "scanner.tls", "status": "ok"}],
        }

    monkeypatch.setattr(asset_scanner_mcp, "_call_tool", fake_call)
    result = await asset_scanner_mcp.run_assessment(
        target="example.com",
        run_nmap=True,
        run_web_probe=True,
        additional_scanners=["tls", "tls"],
    )

    assert result["service"] == "adversarygraph-scanner-mcp"
    assert calls == [
        (
            "run_authorized_asset_assessment",
            {
                "target": "example.com",
                "run_nmap_requested": True,
                "run_web_requested": True,
                "additional_scanners": ["tls"],
                "authorization_confirmed": True,
            },
        )
    ]


@pytest.mark.asyncio
async def test_assessment_rejects_wrong_service_identity(monkeypatch):
    async def fake_call(_name, _arguments):
        return {
            "service": "unexpected",
            "target": {},
            "resolved_ips": [],
            "nmap_result": {},
            "web_probe_result": {},
            "scanner_results": {},
            "tool_trace": [],
        }

    monkeypatch.setattr(asset_scanner_mcp, "_call_tool", fake_call)
    with pytest.raises(asset_scanner_mcp.ScannerMCPError, match="service identity"):
        await asset_scanner_mcp.run_assessment(
            target="example.com",
            run_nmap=False,
            run_web_probe=False,
            additional_scanners=[],
        )
