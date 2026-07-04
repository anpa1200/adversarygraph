from app.services.taxonomy import asset_labels, canonical_tag, canonical_tags, canonical_value, labels_to_tags, normalize_freeform_tags


def test_canonical_tags_use_strict_namespaces():
    assert canonical_tag("technique", "t1190") == "ttp:T1190"
    assert canonical_tag("group", "g0069") == "actor:G0069"
    assert canonical_tag("cve", "cve-2024-3400") == "cve:CVE-2024-3400"
    assert canonical_tag("technology", "Palo Alto PAN-OS") == "technology:palo-alto-pan-os"
    assert canonical_tag("criticality", "P0") == "risk:critical"


def test_asset_labels_and_flat_tags_share_one_convention():
    labels = asset_labels(
        asset_type="Web App",
        environment="Production",
        exposure="Public",
        criticality="P0",
        technologies=["NGINX", "Node.js"],
        products=["Customer Portal"],
        suppliers=["Palo Alto Networks"],
        dependencies=["OpenSSL"],
        sectors=["Financial Services"],
        ttps=["t1190"],
        cves=["cve-2024-3400"],
        extra_tags=["customer data", "pci"],
    )

    assert labels["asset_type"] == "web-app"
    assert labels["environment"] == "production"
    assert labels["exposure"] == "internet"
    assert labels["risk"] == "critical"
    assert labels["technologies"] == ["nginx", "node.js"]
    assert labels["ttps"] == ["T1190"]
    assert labels["cves"] == ["CVE-2024-3400"]

    tags = labels_to_tags(labels)

    assert "asset_type:web-app" in tags
    assert "environment:production" in tags
    assert "exposure:internet" in tags
    assert "risk:critical" in tags
    assert "technology:nginx" in tags
    assert "product:customer-portal" in tags
    assert "supplier:palo-alto-networks" in tags
    assert "dependency:openssl" in tags
    assert "sector:financial-services" in tags
    assert "ttp:T1190" in tags
    assert "cve:CVE-2024-3400" in tags
    assert "tag:customer-data" in tags


def test_freeform_tags_preserve_known_structured_values():
    assert normalize_freeform_tags(["T1059.001", "G0069", "CVE-2026-12345", "Legal Sensitive"]) == [
        "ttp:T1059.001",
        "actor:G0069",
        "cve:CVE-2026-12345",
        "tag:legal-sensitive",
    ]
    assert canonical_tags("tag", ["tag:kev", "T1190", "CVE-2024-3400"]) == [
        "tag:kev",
        "ttp:T1190",
        "cve:CVE-2024-3400",
    ]


def test_canonical_value_maps_common_aliases():
    assert canonical_value("exposure", "DMZ") == "internet"
    assert canonical_value("exposure", "third party") == "third-party"
    assert canonical_value("risk", "sev2") == "high"


def test_canonical_value_is_idempotent_for_namespaced_values():
    assert canonical_value("technology", "technology:nginx") == "nginx"
    assert canonical_value("product", "product:globalprotect-vpn") == "globalprotect-vpn"
    assert canonical_value("risk", "risk:critical") == "critical"
    assert canonical_tag("technology", "technology:nginx") == "technology:nginx"
