from __future__ import annotations

from dataclasses import dataclass
from typing import Any


HIGH_FREQUENCY_TECHNIQUES = {
    "T1059",
    "T1078",
    "T1486",
    "T1566",
}


@dataclass(frozen=True)
class Subject:
    name: str
    type: str


@dataclass(frozen=True)
class TechniqueContext:
    attack_id: str
    name: str = "Unknown technique"
    tactics: tuple[str, ...] = ()
    is_subtechnique: bool = False
    parent_attack_id: str | None = None


def explain_overlap(
    *,
    subject_a: Subject,
    subject_b: Subject,
    shared_techniques: list[str],
    unique_to_a: list[str],
    unique_to_b: list[str],
    tactic_distribution: dict[str, dict[str, int]],
    overlap_score: float,
    technique_context: dict[str, TechniqueContext] | None = None,
) -> str:
    """Build an auditable ATT&CK overlap explanation without attribution wording."""
    context = technique_context or {}
    shared = sorted({_normalize_id(item) for item in shared_techniques if item})
    only_a = sorted({_normalize_id(item) for item in unique_to_a if item})
    only_b = sorted({_normalize_id(item) for item in unique_to_b if item})
    union_count = len(set(shared) | set(only_a) | set(only_b))
    percentage = _score_to_percentage(overlap_score)
    range_label, range_action = _score_range(percentage)
    subtech_notes = _subtechnique_notes(shared, context)

    sections = [
        "### Overlap Summary",
        (
            f"The overlap score is {percentage:.1f}% between {subject_a.type} "
            f"\"{subject_a.name}\" and {subject_b.type} \"{subject_b.name}\"."
        ),
        "",
        "### Scoring Method",
        (
            f"- Numerator: {len(shared)} shared technique ID(s), using exact ATT&CK ID equality "
            "and preserving sub-technique IDs."
        ),
        f"- Denominator: {union_count} technique ID(s) in the union across both subjects.",
        f"- Result: Jaccard similarity coefficient ({len(shared)} / {union_count or 1}), expressed as {percentage:.1f}%.",
        (
            "- Sub-technique handling: parent and sub-technique IDs are treated as distinct IDs. "
            + (subtech_notes if subtech_notes else "No parent/sub-technique relationship was present in the shared set.")
        ),
        "",
        "### What the Score Means",
        (
            "0-15% indicates low overlap and weak signal; 15-35% indicates moderate overlap "
            "worth investigation; 35-60% indicates significant overlap and a strong hypothesis "
            "lead; 60%+ indicates high overlap and should be prioritized for investigation."
        ),
        f"This result falls in the {range_label} range, so the recommended action is to {range_action}.",
        "",
        "### Shared Techniques (Evidence Table)",
        _shared_table(shared, subject_a, subject_b, context),
        "",
        "### Tactic Coverage Comparison",
        _tactic_table(tactic_distribution),
        "",
        "### Limitations and Caveats",
        "1. Overlap is not attribution. Shared techniques may reflect common tooling, not common authorship.",
        "2. ATT&CK technique granularity affects score. Two actors using the same sub-technique may reflect shared tooling, not shared campaign.",
        "3. High-frequency techniques inflate scores. Discount T1059, T1078, T1566, T1486 when assessing distinctiveness.",
        "4. Missing data deflates scores. If subject_b has few documented techniques, low overlap may reflect gaps in ATT&CK coverage, not actual divergence.",
        "5. This result is a hypothesis-generation input, not a conclusion.",
        "",
        "### Recommended Next Steps",
        _recommendation(percentage, shared, context),
    ]
    return "\n".join(sections)


def _normalize_id(value: str) -> str:
    return str(value).strip().upper()


def _score_to_percentage(score: float) -> float:
    if score <= 1:
        return round(score * 100, 1)
    return round(score, 1)


def _score_range(percentage: float) -> tuple[str, str]:
    if percentage < 15:
        return "0-15% low overlap", "monitor only if new evidence appears"
    if percentage < 35:
        return "15-35% moderate overlap", "investigate the shared low-frequency techniques and evidence sources"
    if percentage < 60:
        return "35-60% significant overlap", "investigate further and prioritize evidence review"
    return "60%+ high overlap", "prioritize this comparison for investigation"


def _subtechnique_notes(shared: list[str], context: dict[str, TechniqueContext]) -> str:
    notes = []
    for attack_id in shared:
        item = context.get(attack_id)
        if item and item.is_subtechnique and item.parent_attack_id:
            notes.append(f"{attack_id} is a sub-technique under {item.parent_attack_id}.")
    return " ".join(notes)


def _shared_table(
    shared: list[str],
    subject_a: Subject,
    subject_b: Subject,
    context: dict[str, TechniqueContext],
) -> str:
    if not shared:
        return "No shared techniques were present in the supplied overlap result."

    rows = [
        "| Technique | Tactic | Frequency signal | Evidence in subject_a | Evidence in subject_b |",
        "|---|---|---|---|---|",
    ]
    for attack_id in shared:
        item = context.get(attack_id, TechniqueContext(attack_id=attack_id))
        parent_id = attack_id.split(".", 1)[0]
        is_high_frequency = parent_id in HIGH_FREQUENCY_TECHNIQUES
        frequency = (
            "High-frequency; carries less distinguishing weight."
            if is_high_frequency
            else "Lower-frequency or context-dependent; review source evidence for distinctiveness."
        )
        rows.append(
            "| "
            + " | ".join([
                f"{attack_id} {item.name}",
                ", ".join(item.tactics) or "unknown",
                frequency,
                _evidence_source(subject_a),
                _evidence_source(subject_b),
            ])
            + " |"
        )
    return "\n".join(rows)


def _evidence_source(subject: Subject) -> str:
    if subject.type == "report":
        return "Report excerpt or extracted report evidence"
    if subject.type == "actor":
        return "ATT&CK reference, report, or feed-backed actor profile"
    if subject.type == "campaign":
        return "ATT&CK campaign reference, report, or feed"
    return "Supplied overlap input"


def _tactic_table(distribution: dict[str, dict[str, int]]) -> str:
    if not distribution:
        return "No tactic distribution was supplied."

    rows = [
        "| Tactic | Subject A techniques | Subject B techniques | Shared | Pattern |",
        "|---|---:|---:|---:|---|",
    ]
    for tactic in sorted(distribution):
        item = distribution[tactic] or {}
        shared = _int_value(item, "shared")
        total_a = _int_value(item, "subject_a")
        total_b = _int_value(item, "subject_b")
        if total_a == 0 and total_b == 0:
            pattern = "No coverage"
        elif shared > 0 and abs(total_a - total_b) <= max(1, shared):
            pattern = "Consistent"
        else:
            pattern = "Divergent"
        rows.append(f"| {tactic} | {total_a} | {total_b} | {shared} | {pattern} |")
    return "\n".join(rows)


def _int_value(item: dict[str, Any], key: str) -> int:
    try:
        return int(item.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _recommendation(
    percentage: float,
    shared: list[str],
    context: dict[str, TechniqueContext],
) -> str:
    distinctive = [
        attack_id for attack_id in shared
        if attack_id.split(".", 1)[0] not in HIGH_FREQUENCY_TECHNIQUES
    ]
    high_frequency = [
        attack_id for attack_id in shared
        if attack_id.split(".", 1)[0] in HIGH_FREQUENCY_TECHNIQUES
    ]

    if percentage < 15:
        return (
            "Monitor: the overlap is low. Revisit this comparison if new report evidence, "
            "new actor coverage, or additional low-frequency techniques appear."
        )
    if not distinctive and high_frequency:
        return (
            "Investigate further: focus on evidence quality because the shared set is dominated "
            f"by high-frequency techniques ({', '.join(high_frequency)})."
        )
    if distinctive:
        named = []
        for attack_id in distinctive[:6]:
            item = context.get(attack_id)
            named.append(f"{attack_id} {item.name}" if item else attack_id)
        return (
            "Investigate further: review source evidence for "
            f"{', '.join(named)} and compare timing, tooling, infrastructure, and procedure detail."
        )
    return "Dismiss: no meaningful shared technique signal was present in the supplied data."
