from types import SimpleNamespace

from app.services.threat_hunting import HUNT_TEMPLATES, build_stats


def test_hunt_templates_are_complete_and_unique():
    ids = [template["id"] for template in HUNT_TEMPLATES]
    assert len(ids) >= 6
    assert len(ids) == len(set(ids))
    for template in HUNT_TEMPLATES:
        assert template["title"]
        assert template["hypothesis"]
        assert template["technique_ids"]
        assert template["telemetry_sources"]
        assert template["required_fields"]
        assert template["expected_evidence"]


def test_build_stats_preserves_status_priority_and_finding_counts():
    hunts = [
        SimpleNamespace(status="running", priority="P1 High"),
        SimpleNamespace(status="planned", priority="P3 Monitor"),
        SimpleNamespace(status="completed", priority="P1 High"),
    ]
    findings = [
        SimpleNamespace(severity="critical"),
        SimpleNamespace(severity="medium"),
    ]
    assert build_stats(hunts, findings) == {
        "total_hunts": 3,
        "active_hunts": 2,
        "completed_hunts": 1,
        "total_findings": 2,
        "high_priority_findings": 1,
        "by_status": {"running": 1, "planned": 1, "completed": 1},
        "by_priority": {"P1 High": 2, "P3 Monitor": 1},
    }
