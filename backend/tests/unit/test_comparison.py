"""Unit tests for the Jaccard similarity logic used in APT comparison."""

import pytest


# ── Pure Jaccard helper (extracted from the route for testability) ─────────────

def jaccard(set_a: set, set_b: set) -> float:
    """Reference implementation mirroring the route logic."""
    intersection = set_a & set_b
    union        = set_a | set_b
    return len(intersection) / len(union) if union else 0.0


# ── Basic Jaccard ──────────────────────────────────────────────────────────────

def test_identical_sets():
    a = {"T1566", "T1059", "T1003"}
    assert jaccard(a, a) == pytest.approx(1.0)


def test_disjoint_sets():
    a = {"T1566", "T1059"}
    b = {"T1003", "T1021"}
    assert jaccard(a, b) == pytest.approx(0.0)


def test_partial_overlap():
    a = {"T1566", "T1059", "T1003"}
    b = {"T1059", "T1003", "T1021"}
    # intersection = {T1059, T1003} = 2
    # union        = {T1566, T1059, T1003, T1021} = 4
    assert jaccard(a, b) == pytest.approx(2 / 4)


def test_empty_both_sets():
    assert jaccard(set(), set()) == pytest.approx(0.0)


def test_empty_one_set():
    a = {"T1566"}
    assert jaccard(a, set()) == pytest.approx(0.0)
    assert jaccard(set(), a) == pytest.approx(0.0)


def test_single_element_match():
    a = {"T1566"}
    b = {"T1566"}
    assert jaccard(a, b) == pytest.approx(1.0)


def test_large_sets_performance():
    """Should complete in well under a second."""
    import time
    a = {f"T{i:04d}" for i in range(500)}
    b = {f"T{i:04d}" for i in range(250, 750)}
    t0 = time.monotonic()
    result = jaccard(a, b)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.1
    # intersection = 250, union = 750
    assert result == pytest.approx(250 / 750, rel=1e-6)


# ── Ranking logic ──────────────────────────────────────────────────────────────

def test_ranking_sorts_by_similarity():
    user = {"T1566", "T1059", "T1003"}
    groups = {
        "G0001": {"techs": {"T1566", "T1059"}, "name": "Alpha"},   # 2/4 = 0.5
        "G0002": {"techs": {"T1003"},           "name": "Beta"},    # 1/3 ≈ 0.33
        "G0003": {"techs": {"T1566", "T1059", "T1003", "T1021"}, "name": "Gamma"},  # 3/4 = 0.75
    }
    results = []
    for g_id, info in groups.items():
        shared = user & info["techs"]
        union  = user | info["techs"]
        sim = len(shared) / len(union)
        results.append((g_id, sim))

    results.sort(key=lambda r: r[1], reverse=True)
    assert results[0][0] == "G0003"
    assert results[1][0] == "G0001"
    assert results[2][0] == "G0002"


def test_top_n_truncation():
    user = {"T1566"}
    groups = {f"G{i:04d}": {"techs": {f"T{i:04d}"}} for i in range(20)}
    # Add one match
    groups["G0000"] = {"techs": {"T1566"}}

    results = [
        {"group_attack_id": g_id,
         "similarity": jaccard(user, info["techs"])}
        for g_id, info in groups.items()
    ]
    results.sort(key=lambda r: r["similarity"], reverse=True)
    top5 = results[:5]
    assert len(top5) == 5
    assert top5[0]["group_attack_id"] == "G0000"
    assert top5[0]["similarity"] == pytest.approx(1.0)


# ── Auditable overlap explanation ─────────────────────────────────────────────

def test_overlap_explanation_uses_required_sections_and_caveats():
    from app.services.comparison_explainer import Subject, TechniqueContext, explain_overlap

    text = explain_overlap(
        subject_a=Subject(name="Incident report", type="report"),
        subject_b=Subject(name="APT Example", type="actor"),
        shared_techniques=["T1059.001", "T1021.001"],
        unique_to_a=["T1486"],
        unique_to_b=["T1078"],
        tactic_distribution={
            "execution": {"subject_a": 1, "subject_b": 1, "shared": 1},
            "lateral-movement": {"subject_a": 1, "subject_b": 1, "shared": 1},
        },
        overlap_score=0.5,
        technique_context={
            "T1059.001": TechniqueContext(
                attack_id="T1059.001",
                name="PowerShell",
                tactics=("execution",),
                is_subtechnique=True,
                parent_attack_id="T1059",
            ),
            "T1021.001": TechniqueContext(
                attack_id="T1021.001",
                name="Remote Desktop Protocol",
                tactics=("lateral-movement",),
            ),
        },
    )

    for heading in [
        "### Overlap Summary",
        "### Scoring Method",
        "### What the Score Means",
        "### Shared Techniques (Evidence Table)",
        "### Tactic Coverage Comparison",
        "### Limitations and Caveats",
        "### Recommended Next Steps",
    ]:
        assert heading in text
    assert "50.0%" in text
    assert "High-frequency; carries less distinguishing weight." in text
    assert "Overlap is not attribution" in text
    assert "T1059.001 is a sub-technique under T1059" in text


def test_overlap_explanation_avoids_forbidden_overclaiming_words():
    from app.services.comparison_explainer import Subject, explain_overlap

    text = explain_overlap(
        subject_a=Subject(name="A", type="report"),
        subject_b=Subject(name="B", type="campaign"),
        shared_techniques=["T1059"],
        unique_to_a=[],
        unique_to_b=[],
        tactic_distribution={},
        overlap_score=1.0,
    ).lower()

    for forbidden in ["proves", "confirms", "attributes", "matches"]:
        assert forbidden not in text
