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
