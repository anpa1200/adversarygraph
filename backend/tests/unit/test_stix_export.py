import uuid
from datetime import datetime, timezone

from app.models.analysis import AnalysisResult, AnalysisSession
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
    )

    assert bundle["type"] == "bundle"
    object_types = {item["type"] for item in bundle["objects"]}
    assert {"identity", "report", "attack-pattern", "intrusion-set"} <= object_types
    assert "indicator" not in object_types
    assert "observed-data" not in object_types

    report = next(item for item in bundle["objects"] if item["type"] == "report")
    assert report["name"] == "DFIR report analysis"
    assert report["x_threatmapper_domain"] == "enterprise-attack"
    assert "not attribution claims" in report["x_threatmapper_note"]

    attack_pattern = next(item for item in bundle["objects"] if item["type"] == "attack-pattern")
    assert attack_pattern["id"] == "attack-pattern--11111111-1111-4111-8111-111111111111"
    assert attack_pattern["x_mitre_id"] == "T1566.002"
    assert attack_pattern["x_threatmapper_review_status"] == "accepted"

    intrusion_set = next(item for item in bundle["objects"] if item["type"] == "intrusion-set")
    assert intrusion_set["id"] == "intrusion-set--22222222-2222-4222-8222-222222222222"
    assert intrusion_set["x_threatmapper_similarity"] == 0.31
