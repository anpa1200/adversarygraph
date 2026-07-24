from uuid import uuid4

from app.models.asset_surface import AssetRegistryItem
import json

import pytest

from app.services import emb3d
from app.services.emb3d import (
    Emb3dDataUnavailable,
    assess_asset_with_emb3d,
    infer_emb3d_properties,
    parse_emb3d_bundle,
)


def test_parse_emb3d_bundle_maps_properties_threats_and_mitigations():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-emb3d-property",
                "id": "x-mitre-emb3d-property--p1",
                "name": "Device includes a bootloader",
                "category": "System Software",
                "is_subproperty": False,
                "x_mitre_emb3d_property_id": "PID-21",
            },
            {
                "type": "vulnerability",
                "id": "vulnerability--t1",
                "name": "Inadequate Bootloader Protection and Verification",
                "description": "Bootloader modification risk.",
                "x_mitre_emb3d_threat_id": "TID-201",
                "x_mitre_emb3d_threat_category": "system-software",
                "x_mitre_emb3d_threat_CWEs": "- CWE-494",
                "x_mitre_emb3d_threat_CVEs": "- CVE-2024-0001",
            },
            {
                "type": "course-of-action",
                "id": "course-of-action--m1",
                "name": "Software Only Bootloader Authentication",
                "description": "Authenticate bootloader before execution.",
                "x_mitre_emb3d_mitigation_id": "MID-001",
                "x_mitre_emb3d_mitigation_maturity": "foundational",
            },
            {
                "type": "relationship",
                "relationship_type": "relates-to",
                "source_ref": "x-mitre-emb3d-property--p1",
                "target_ref": "vulnerability--t1",
            },
            {
                "type": "relationship",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--m1",
                "target_ref": "vulnerability--t1",
            },
        ],
    }

    kb = parse_emb3d_bundle(bundle)

    assert kb.properties["PID-21"]["name"] == "Device includes a bootloader"
    assert kb.property_to_threats["PID-21"] == ["TID-201"]
    assert kb.threat_to_mitigations["TID-201"] == ["MID-001"]
    assert kb.threats["TID-201"]["cwes"] == ["CWE-494"]
    assert kb.threats["TID-201"]["cves"] == ["CVE-2024-0001"]


def test_infer_emb3d_properties_from_embedded_bmc_asset():
    asset = AssetRegistryItem(
        id=uuid4(),
        fingerprint="domain:bmc.lab.local",
        inventory_asset_id="asset-fw-1",
        name="bmc-redfish-controller",
        asset_type="bmc_management",
        environment="production",
        exposure="internal",
        criticality="critical",
        ip_addresses=["10.1.1.10"],
        domains=["bmc.lab.local"],
        ports=[443, 623],
        technologies=["redfish", "bmc", "firmware", "ipmi", "secure_boot"],
        products=["Firmware Management Controller"],
        suppliers=["internal"],
        dependencies=["openssl", "lighttpd"],
        technique_ids=[],
        tags=["management_plane", "firmware"],
        labels={},
        risk_score=80,
        risk_level="high",
        raw={},
    )

    property_ids = {match.property_id for match in infer_emb3d_properties(asset)}

    assert {"PID-11", "PID-21", "PID-23", "PID-27", "PID-311", "PID-41", "PID-411", "PID-4113"}.issubset(property_ids)


def test_assess_asset_links_inferred_properties_to_threats():
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-emb3d-property",
                "id": "x-mitre-emb3d-property--p1",
                "name": "Device exposes remote network services",
                "category": "Networking",
                "x_mitre_emb3d_property_id": "PID-41",
            },
            {
                "type": "vulnerability",
                "id": "vulnerability--t1",
                "name": "Exploitable System Network Stack Component",
                "description": "Network stack risk.",
                "x_mitre_emb3d_threat_id": "TID-210",
            },
            {
                "type": "relationship",
                "relationship_type": "relates-to",
                "source_ref": "x-mitre-emb3d-property--p1",
                "target_ref": "vulnerability--t1",
            },
        ],
    }
    kb = parse_emb3d_bundle(bundle)
    asset = AssetRegistryItem(
        id=uuid4(),
        fingerprint="domain:portal.example.com",
        inventory_asset_id="asset-1",
        name="portal",
        asset_type="web-app",
        environment="prod",
        exposure="internet",
        criticality="high",
        ip_addresses=["203.0.113.10"],
        domains=["portal.example.com"],
        ports=[443],
        technologies=["nginx"],
        products=["portal"],
        suppliers=[],
        dependencies=[],
        technique_ids=[],
        tags=[],
        labels={},
        risk_score=70,
        risk_level="high",
        raw={},
    )

    report = assess_asset_with_emb3d(asset, kb)

    assert any(prop["id"] == "PID-41" for prop in report["properties"])
    assert [threat["id"] for threat in report["threats"]] == ["TID-210"]


def test_emb3d_bundle_loader_uses_valid_cache_without_network(tmp_path, monkeypatch):
    cache = tmp_path / "emb3d.json"
    cache.write_text(json.dumps({"type": "bundle", "objects": []}), encoding="utf-8")

    def unexpected_network(*args, **kwargs):
        raise AssertionError("network should not be called when a valid cache exists")

    monkeypatch.setattr(emb3d, "safe_get", unexpected_network)

    assert emb3d._load_bundle(source_url="https://example.test/emb3d.json", cache_path=cache) == {
        "type": "bundle",
        "objects": [],
    }


def test_emb3d_bundle_loader_reports_controlled_error_when_upstream_is_unavailable(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        raise ValueError("DNS unavailable")

    monkeypatch.setattr(emb3d, "safe_get", unavailable)

    with pytest.raises(Emb3dDataUnavailable, match="reference data is unavailable"):
        emb3d._load_bundle(
            source_url="https://example.test/emb3d.json",
            cache_path=tmp_path / "missing.json",
        )
