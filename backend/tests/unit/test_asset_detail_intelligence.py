import uuid

from app.models.threat_radar import ThreatAlert, ThreatSpaceAsset
from app.services import asset_detail_intelligence as intelligence


def _asset() -> ThreatSpaceAsset:
    return ThreatSpaceAsset(
        id=uuid.uuid4(),
        space_id=uuid.uuid4(),
        asset_id="edge-prod-01",
        name="Production edge appliance",
        criticality="critical",
        exposure="internet",
        products=["EdgeShield", "Server"],
        components=["Management API"],
        technologies=["Linux", "nginx"],
        ip_addresses=["192.0.2.44"],
        domains=["https://edge.example.test/health"],
        tags=["T1190"],
        metadata_json={"ttp_candidates": ["T1059.001"]},
    )


def test_asset_identities_are_exact_and_strip_url_paths():
    values = intelligence._asset_identities(_asset())
    assert values == {
        "192.0.2.44",
        "edge.example.test",
        "https://edge.example.test/health",
    }


def test_alert_matching_requires_asset_identity_not_signal_text():
    asset = _asset()
    matching = ThreatAlert(
        matches=[{
            "asset_uuid": str(asset.id),
            "asset_id": asset.asset_id,
            "inventory_entity": asset.name,
        }],
    )
    unrelated = ThreatAlert(
        matches=[{
            "asset_uuid": str(uuid.uuid4()),
            "asset_id": "other",
            "inventory_entity": "Production edge appliance mention in signal text",
        }],
    )
    assert intelligence._alert_matches_asset(matching, asset) is True
    assert intelligence._alert_matches_asset(unrelated, asset) is False


def test_generic_product_terms_are_not_used_for_cve_candidates():
    assert intelligence._meaningful_product_terms(_asset()) == [
        "edgeshield",
        "management api",
        "nginx",
    ]


def test_metadata_ttps_are_normalized_and_deduplicated():
    assert intelligence._asset_metadata_ttps(_asset()) == ["T1059.001", "T1190"]


def test_cpe_term_matching_uses_token_boundaries():
    haystack = '[{"criteria":"cpe:2.3:a:vendor:edge_shield:4.2:*:*:*:*:*:*:*"}]'
    assert intelligence._term_in_cpe_text("edge shield", haystack) is True
    assert intelligence._term_in_cpe_text("shieldx", haystack) is False
