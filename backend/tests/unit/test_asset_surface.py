from uuid import uuid4

from app.models.asset_surface import AssetIntelMatch, AssetRegistryItem
from app.models.cve import CVERecord
from app.services.asset_intel import _collect_match, _match_cve, asset_fingerprint
from app.services.asset_surface import build_baseline_matrix, parse_inventory


def test_parse_csv_inventory_and_score_internet_assets():
    content = b"""asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,products,suppliers,dependencies,exposure,criticality,tags
asset-0001,customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,"80;443;8443","nginx;nodejs","customer portal","internal","npm",internet,critical,"customer-data"
asset-0002,ad-dc-01,identity,prod,IT,10.10.1.10,ad01.corp.local,"53;88;389;445","active-directory","active directory","microsoft","kerberos;ldap",internal,critical,"identity"
"""

    records, _ = parse_inventory(content, "assets.csv")
    matrix = build_baseline_matrix(records)

    assert len(records) == 2
    assert matrix["exposure_counts"]["internet"] == 1
    assert matrix["assets"][0]["risk_level"] in {"high", "critical"}
    assert matrix["assets"][0]["products"] == ["customer-portal"]
    assert matrix["assets"][1]["suppliers"] == ["microsoft"]
    assert matrix["assets"][0]["labels"]["risk"] == "critical"
    assert "tag:customer-data" in matrix["assets"][0]["labels"]["tags"]
    assert any(ttp["attack_id"] == "T1190" for ttp in matrix["assets"][0]["ttp_candidates"])


def test_parse_plain_text_inventory():
    records, _ = parse_inventory(b"vpn.example.com 198.51.100.20 ports 443 3389 public vpn", "assets.txt")
    matrix = build_baseline_matrix(records)

    assert records[0].domains == ["vpn.example.com"]
    assert records[0].exposure == "internet"
    assert records[0].ports == [443, 3389]
    assert 3389 in records[0].ports
    assert any(ttp["attack_id"] == "T1021" for ttp in matrix["assets"][0]["ttp_candidates"])
    assert any(ttp["attack_id"] == "T1133" for ttp in matrix["assets"][0]["ttp_candidates"])


def test_attack_surface_matrix_includes_detection_and_validation_guidance():
    content = b"""asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,products,suppliers,dependencies,exposure,criticality,tags
asset-ci-1,ci-runner,ci-cd,prod,Platform,10.4.5.6,ci.corp.local,"22;443","gitlab;runner;legacy","gitlab runner","gitlab","docker;ssh",internal,high,"pipeline"
"""

    records, _ = parse_inventory(content, "assets.csv")
    matrix = build_baseline_matrix(records)
    row = matrix["assets"][0]

    assert any(ttp["attack_id"] == "T1195" for ttp in row["ttp_candidates"])
    assert any(ttp["attack_id"] == "T1068" for ttp in row["ttp_candidates"])
    assert row["control_gaps"]
    assert row["validation_steps"]
    assert row["detection_ideas"]


def test_product_security_inventory_maps_richer_ttp_profile():
    content = b"""asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,products,suppliers,dependencies,exposure,criticality,tags
asset-fw-1,bmc-redfish-controller,bmc_management,production,PSIRT,10.1.1.10,bmc.lab.local,"443;623","redfish;bmc;firmware;ipmi","Firmware Management Controller","internal","openssl;lighttpd",internal,critical,"secure_boot;management_plane"
asset-k8s-1,ngc-container-runtime,container_orchestrator,production,Platform,10.2.2.20,,"443","kubernetes;containerd;docker;ngc","NGC Container Runtime","internal","container-image;oci",internal,high,"runtime"
dep-oss-1,openssl,open_source_dependency,unknown,Product Security,,,,openssl,"GPU Driver","openssl","purl;sbom;cpe",third-party,critical,"dependency"
"""

    records, _ = parse_inventory(content, "product-security.csv")
    matrix = build_baseline_matrix(records)
    ttps = {ttp["attack_id"] for row in matrix["assets"] for ttp in row["ttp_candidates"]}

    assert {"T1068", "T1542", "T1562", "T1611", "T1610", "T1525", "T1195", "T1608"}.issubset(ttps)
    assert len(ttps) >= 12


def test_asset_registry_fingerprint_prefers_domain_then_ip():
    assert asset_fingerprint({"domains": ["Portal.Example.com"], "ip_addresses": ["203.0.113.10"]}) == "domain:portal.example.com"
    assert asset_fingerprint({"domains": [], "ip_addresses": ["203.0.113.10"]}) == "ip:203.0.113.10"


def test_asset_cve_retrohunt_matches_product_tokens_and_ttp_context():
    asset = AssetRegistryItem(
        id=uuid4(),
        fingerprint="domain:portal.example.com",
        inventory_asset_id="customer-portal",
        name="customer-portal",
        asset_type="web-app",
        environment="prod",
        exposure="internet",
        criticality="critical",
        technologies=["nginx", "nodejs"],
        products=["nginx", "nodejs"],
        suppliers=[],
        dependencies=["nginx"],
        technique_ids=["T1190"],
        tags=["tech:nginx", "ttp:T1190"],
        labels={},
        risk_score=90,
        risk_level="critical",
        raw={},
    )
    cve = CVERecord(
        cve_id="CVE-2026-0001",
        source_id="unit-test",
        description="Nginx path traversal vulnerability in exposed web gateway",
        cvss_severity="CRITICAL",
        cpe_matches=["cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"],
        cwe_ids=["CWE-22"],
        tags=["kev"],
        known_exploited=True,
    )

    match = _match_cve(asset, cve, {"T1190"})

    assert match is not None
    assert match.source_id == "CVE-2026-0001"
    assert match.relevance_score >= 75
    assert any("nginx" in item.lower() for item in match.evidence)


def test_asset_retrohunt_collects_duplicate_actor_matches_as_one_relationship():
    asset_id = uuid4()
    matches = {}

    _collect_match(
        matches,
        AssetIntelMatch(
            asset_id=asset_id,
            source_type="actor",
            source_id="G0007",
            relationship="actor-reported-with-relevant-cve",
            title="APT28",
            relevance_score=62,
            confidence=70,
            evidence=["Relevant CVE: CVE-2026-0001"],
            tags=["actor:G0007", "cve:CVE-2026-0001"],
        ),
    )
    _collect_match(
        matches,
        AssetIntelMatch(
            asset_id=asset_id,
            source_type="actor",
            source_id="G0007",
            relationship="actor-reported-with-relevant-cve",
            title="APT28",
            relevance_score=75,
            confidence=85,
            evidence=["Relevant CVE: CVE-2026-0002"],
            tags=["actor:G0007", "cve:CVE-2026-0002"],
        ),
    )

    assert len(matches) == 1
    match = next(iter(matches.values()))
    assert match.relevance_score == 75
    assert match.confidence == 85
    assert match.evidence == ["Relevant CVE: CVE-2026-0001", "Relevant CVE: CVE-2026-0002"]
    assert "cve:CVE-2026-0002" in match.tags
