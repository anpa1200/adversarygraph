from __future__ import annotations

import json

import pytest
from scanner_mcp.models import normalize_target

from scanner_mcp import scanners


def test_target_normalization_removes_query_credentials_and_rejects_unsafe_schemes():
    target = normalize_target("https://Example.COM/path?token=secret#fragment")
    assert target.value == "https://example.com/path"
    assert target.host == "example.com"
    assert target.target_type == "url"

    with pytest.raises(ValueError):
        normalize_target("file:///etc/passwd")
    with pytest.raises(ValueError):
        normalize_target("https://user:password@example.com/")


def test_nmap_parser_accepts_only_open_services():
    parsed = scanners.parse_nmap_xml(
        b"""<?xml version="1.0"?>
        <nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22"><state state="closed"/></port>
          <port protocol="tcp" portid="443"><state state="open"/>
            <service name="https" product="nginx" version="1.24">
              <cpe>cpe:/a:nginx:nginx:1.24</cpe>
            </service>
          </port>
        </ports></host></nmaprun>"""
    )
    assert parsed["open_port_count"] == 1
    assert parsed["services"][0]["port"] == 443
    assert parsed["services"][0]["product"] == "nginx"


def test_nuclei_parser_bounds_and_normalizes_findings():
    raw = json.dumps(
        {
            "template-id": "example-check",
            "matched-at": "https://example.com/",
            "type": "http",
            "info": {
                "name": "Example observation",
                "severity": "medium",
                "reference": ["https://example.com/advisory"],
            },
        }
    ).encode()
    findings, rejected = scanners.parse_nuclei_jsonl(raw + b"\nnot-json\n")
    assert rejected == 1
    assert findings[0]["template_id"] == "example-check"
    assert findings[0]["verification_required"] is True


@pytest.mark.asyncio
async def test_composite_plan_returns_mcp_tool_trace(monkeypatch):
    async def fake_resolve(_target):
        return ["192.0.2.10"]

    async def fake_nmap(_target):
        return {"status": "ok", "profile": "safe-service-discovery", "findings": []}

    async def fake_tls(_target):
        return {"status": "ok", "profile": "verified-tls-handshake", "findings": []}

    monkeypatch.setattr(scanners, "resolve_target", fake_resolve)
    monkeypatch.setattr(scanners, "run_nmap", fake_nmap)
    monkeypatch.setattr(scanners, "run_tls", fake_tls)

    result = await scanners.run_assessment_plan(
        "192.0.2.10",
        run_nmap_requested=True,
        run_web_requested=False,
        additional_scanners=["tls"],
    )

    assert result["service"] == "adversarygraph-scanner-mcp"
    assert result["resolved_ips"] == ["192.0.2.10"]
    assert [row["tool"] for row in result["tool_trace"]] == [
        "scanner.nmap",
        "scanner.tls",
    ]
    assert result["web_probe_result"]["status"] == "not_requested"
