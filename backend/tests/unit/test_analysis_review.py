import pytest

from app.api.routes.analyze import (
    _validate_technique_ids,
    update_extracted_technique_review,
)
from app.services.ai.base import ExtractionResult, ExtractedTechnique


class _ScalarResult:
    def __init__(self, value=None, rows=None):
        self.value = value
        self.rows = rows or []

    def scalar_one_or_none(self):
        return self.value

    def __iter__(self):
        return iter(self.rows)


class _TechniqueValidationSession:
    def __init__(self, version_id=None, known_ids=()):
        self.version_id = version_id
        self.known_ids = known_ids
        self.calls = 0

    async def execute(self, _statement):
        self.calls += 1
        if self.calls == 1:
            return _ScalarResult(self.version_id)
        return _ScalarResult(rows=[(attack_id,) for attack_id in self.known_ids])


def _extraction(*attack_ids: str) -> ExtractionResult:
    return ExtractionResult(
        techniques=[
            ExtractedTechnique(
                attack_id=attack_id,
                name="candidate",
                tactic="execution",
                confidence=0.8,
                evidence="PowerShell launched encoded commands",
                llm_verified=True,
            )
            for attack_id in attack_ids
        ]
    )


@pytest.mark.asyncio
async def test_validate_technique_ids_fails_closed_without_local_catalog():
    result = _extraction("T1059.001", "T9999")
    session = _TechniqueValidationSession(version_id=None)

    await _validate_technique_ids(result, "enterprise-attack", session)

    assert [item.llm_verified for item in result.techniques] == [False, False]
    assert session.calls == 1


@pytest.mark.asyncio
async def test_validate_technique_ids_marks_only_catalog_matches_verified():
    result = _extraction("T1059.001", "T9999")
    session = _TechniqueValidationSession(
        version_id="catalog-version",
        known_ids=("T1059.001",),
    )

    await _validate_technique_ids(result, "enterprise-attack", session)

    assert [item.llm_verified for item in result.techniques] == [True, False]


def test_update_extracted_technique_review_sets_status_and_note():
    techniques = [
        {
            "attack_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "execution",
            "confidence": 0.7,
            "evidence": "PowerShell launched encoded commands",
            "review_status": "suggested",
            "evidence_source": "source-text",
        }
    ]

    updated = update_extracted_technique_review(
        techniques,
        "t1059",
        review_status="accepted",
        review_note="Confirmed in source paragraph 4.",
        reviewer="analyst@example.test",
    )

    assert updated is techniques[0]
    assert techniques[0]["review_status"] == "accepted"
    assert techniques[0]["review_note"] == "Confirmed in source paragraph 4."
    assert techniques[0]["reviewer"] == "analyst@example.test"


def test_update_extracted_technique_review_overrides_evidence_as_analyst_source():
    techniques = [
        {
            "attack_id": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "credential-access",
            "confidence": 0.8,
            "evidence": "dumping was mentioned",
            "review_status": "needs-evidence",
            "evidence_start": 10,
            "evidence_end": 31,
            "evidence_source": "llm",
        }
    ]

    updated = update_extracted_technique_review(
        techniques,
        "T1003",
        review_status="accepted",
        evidence="The report states LSASS memory was dumped.",
    )

    assert updated["evidence"] == "The report states LSASS memory was dumped."
    assert updated["evidence_source"] == "analyst"
    assert updated["evidence_start"] is None
    assert updated["evidence_end"] is None


def test_update_extracted_technique_review_returns_none_for_missing_id():
    techniques = [{"attack_id": "T1059", "review_status": "suggested"}]

    assert update_extracted_technique_review(
        techniques,
        "T9999",
        review_status="rejected",
    ) is None
