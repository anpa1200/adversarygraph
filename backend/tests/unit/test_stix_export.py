import uuid
from datetime import datetime, timezone

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.report_review import ReportPromotion
from app.services.stix_export import build_analysis_stix_bundle


def test_analysis_stix_export_models_ttp_report_not_iocs():
    session_id = uuid.uuid4()
    session = AnalysisSession(
        id=session_id,
        status="completed",
        name="DFIR report analysis",
        input_type="file",
        filename="report.pdf",
        llm_provider="local",
        model="llama3.1:8b",
        domain="enterprise-attack",
        created_at=datetime(2026, 6, 16, tzinfo=timezone.utc),
    )
    result = AnalysisResult(
        session_id=session_id,
        extracted_techniques=[
            {
                "attack_id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "initial-access",
                "confidence": 0.9,
                "evidence": "phishing email leading to loader",
                "review_status": "accepted",
            }
        ],
        apt_matches=[
            {
                "group_attack_id": "G0059",
                "group_name": "Magic Hound",
                "similarity": 0.31,
                "shared_count": 4,
                "shared_techniques": ["T1566.002"],
            }
        ],
        summary="Observed phishing-to-loader activity.",
        raw_response="{}",
    )
    promotion = ReportPromotion(
        id=uuid.uuid4(),
        review_id=uuid.uuid4(),
        session_id=session_id,
        review_revision=1,
        policy_version="report-review-policy-v1.0",
        source_checksum="a" * 64,
        analysis_checksum="b" * 64,
        targets=["canonical_intelligence", "exports"],
        manifest={
            "accepted_claims": [
                {
                    "claim_key": "procedure-1",
                    "claim_type": "procedure",
                    "object": "Spearphishing Link",
                    "statement": "The report documents delivery through a phishing link.",
                    "attack_id": "T1566.002",
                    "actor_id": "",
                    "evidence_refs": [{"excerpt": "phishing email leading to loader"}],
                    "metadata": {"tactic": "initial-access", "confidence": 0.9},
                },
                {
                    "claim_key": "actor-1",
                    "claim_type": "actor",
                    "subject": "Magic Hound",
                    "statement": "The source explicitly attributes the activity to Magic Hound.",
                    "attack_id": "",
                    "actor_id": "G0059",
                    "evidence_refs": [{"excerpt": "attributed to Magic Hound"}],
                    "metadata": {"attribution_basis": "explicit"},
                },
                {
                    "claim_key": "actor-2",
                    "claim_type": "actor",
                    "subject": "report",
                    "object": "Blue Lantern",
                    "statement": "The source explicitly attributes the activity to Blue Lantern.",
                    "attack_id": "",
                    "actor_id": "Blue Lantern",
                    "evidence_refs": [{"excerpt": "attributed to Blue Lantern"}],
                    "metadata": {"attribution_basis": "source_reported"},
                },
            ]
        },
        manifest_checksum="c" * 64,
        idempotency_key="d" * 64,
        promoted_by="reviewer",
        promoted_at=datetime(2026, 6, 17, tzinfo=timezone.utc),
    )

    bundle = build_analysis_stix_bundle(
        session,
        result,
        technique_lookup={
            "T1566.002": {
                "stix_id": "attack-pattern--11111111-1111-4111-8111-111111111111",
                "name": "Spearphishing Link",
                "description": "MITRE technique description",
                "url": "https://attack.mitre.org/techniques/T1566/002/",
            }
        },
        group_lookup={
            "G0059": {
                "stix_id": "intrusion-set--22222222-2222-4222-8222-222222222222",
                "name": "Magic Hound",
                "aliases": ["APT35"],
                "url": "https://attack.mitre.org/groups/G0059/",
            }
        },
        promotion=promotion,
    )

    assert bundle["type"] == "bundle"
    object_types = {item["type"] for item in bundle["objects"]}
    assert {"identity", "report", "attack-pattern", "intrusion-set"} <= object_types
    assert "indicator" not in object_types
    assert "observed-data" not in object_types

    report = next(item for item in bundle["objects"] if item["type"] == "report")
    assert report["name"] == "DFIR report analysis"
    assert report["x_adversarygraph_domain"] == "enterprise-attack"
    assert "not attribution claims" in report["x_adversarygraph_note"]

    attack_pattern = next(item for item in bundle["objects"] if item["type"] == "attack-pattern")
    assert attack_pattern["id"] == "attack-pattern--11111111-1111-4111-8111-111111111111"
    assert attack_pattern["x_mitre_id"] == "T1566.002"
    assert attack_pattern["x_adversarygraph_review_status"] == "accepted"

    intrusion_set = next(
        item
        for item in bundle["objects"]
        if item["type"] == "intrusion-set" and item.get("x_mitre_id") == "G0059"
    )
    assert intrusion_set["id"] == "intrusion-set--22222222-2222-4222-8222-222222222222"
    assert "x_adversarygraph_similarity" not in intrusion_set
    assert intrusion_set["x_adversarygraph_review_status"] == "accepted"

    source_reported = next(
        item
        for item in bundle["objects"]
        if item["type"] == "intrusion-set" and item.get("name") == "Blue Lantern"
    )
    assert "x_mitre_id" not in source_reported
    assert "external_references" not in source_reported
    assert source_reported["x_adversarygraph_source_reported_name"] is True
