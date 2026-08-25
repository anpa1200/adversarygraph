from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.ioc import IOCIndicator
from app.models.operations import ReportIntake
from app.services import opencti_sync, taxonomy_migration
from app.services.report_review_preflight import evaluate_report_preflight


class _Rows:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def scalars(self):
        return self

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class _TaxonomySession:
    def __init__(self, results, reviewed_session_ids):
        self.results = results
        self.reviewed_session_ids = reviewed_session_ids

    async def execute(self, statement):
        sql = str(statement)
        if "FROM analysis_results" in sql:
            return _Rows(self.results)
        if "FROM report_reviews" in sql:
            return _Rows(self.reviewed_session_ids)
        if "FROM report_promotions" in sql:
            return _Rows([])
        if "FROM analysis_sessions" in sql:
            return _Rows([])
        raise AssertionError(f"Unexpected statement: {sql}")


class _IOCTaxonomySession:
    def __init__(self, indicators):
        self.indicators = indicators

    async def execute(self, statement):
        sql = str(statement)
        if "FROM ioc_indicators" in sql:
            return _Rows(self.indicators)
        raise AssertionError(f"Unexpected statement: {sql}")


class _OpenCTISession:
    def __init__(
        self,
        existing=None,
        result=None,
        *,
        intake=None,
        review_id=None,
        promotion_id=None,
    ):
        self.existing = existing
        self.result = result
        self.intake = intake
        self.review_id = review_id
        self.promotion_id = promotion_id
        self.added = []
        self.flushes = 0

    async def execute(self, statement):
        sql = str(statement)
        if "FROM analysis_sessions" in sql:
            return _Rows([self.existing] if self.existing is not None else [])
        if "FROM analysis_results" in sql:
            return _Rows([self.result] if self.result is not None else [])
        if "FROM report_intake" in sql:
            return _Rows([self.intake] if self.intake is not None else [])
        raise AssertionError(f"Unexpected statement: {sql}")

    async def scalar(self, statement):
        sql = str(statement)
        if "FROM report_reviews" in sql:
            return self.review_id
        if "FROM report_promotions" in sql:
            return self.promotion_id
        raise AssertionError(f"Unexpected scalar statement: {sql}")

    def add(self, value):
        self.added.append(value)

    async def flush(self):
        self.flushes += 1
        for value in self.added:
            if isinstance(value, AnalysisSession) and value.id is None:
                value.id = uuid4()
            elif isinstance(value, ReportIntake) and value.id is None:
                value.id = uuid4()
            elif isinstance(value, AnalysisResult) and value.id is None:
                value.id = 1


def _analysis_result(session_id, *, review_status="suggested"):
    return AnalysisResult(
        id=1,
        session_id=session_id,
        extracted_techniques=[
            {
                "attack_id": "ttp:T1059.001",
                "review_status": review_status,
            }
        ],
        apt_matches=[
            {
                "group_attack_id": "actor:G0016",
                "shared_techniques": ["ttp:T1059.001"],
            }
        ],
        summary="summary",
        raw_response="{}",
    )


@pytest.mark.asyncio
async def test_taxonomy_normalization_skips_review_and_legacy_analyst_results():
    reviewed_id = uuid4()
    legacy_id = uuid4()
    mutable_id = uuid4()
    reviewed = _analysis_result(reviewed_id)
    legacy = _analysis_result(legacy_id, review_status="accepted")
    mutable = _analysis_result(mutable_id)
    db = _TaxonomySession([reviewed, legacy, mutable], [reviewed_id])
    stats = {"tables": {}, "rows_changed": 0}

    await taxonomy_migration._normalize_analysis_results(db, stats)

    assert reviewed.extracted_techniques[0]["attack_id"] == "ttp:T1059.001"
    assert legacy.extracted_techniques[0]["attack_id"] == "ttp:T1059.001"
    assert mutable.extracted_techniques[0]["attack_id"] == "T1059.001"
    assert mutable.apt_matches[0]["group_attack_id"] == "G0016"
    assert stats["tables"]["analysis_results"] == {
        "scanned": 3,
        "changed": 1,
        "skipped_protected": 2,
    }
    assert stats["rows_changed"] == 1


@pytest.mark.asyncio
async def test_taxonomy_normalization_never_rewrites_promotion_ioc_projections():
    immutable = IOCIndicator(
        id=1,
        value="evil.example",
        indicator_type="domain",
        source_id="REPORT-PROMOTION-11111111-1111-4111-8111-111111111111",
        tags=["Raw Label"],
        technique_ids=["ttp:T1059.001"],
        raw={"manifest_checksum": "immutable"},
    )
    mutable = IOCIndicator(
        id=2,
        value="mutable.example",
        indicator_type="domain",
        source_id="opencti",
        tags=["Raw Label"],
        technique_ids=["ttp:T1059.001"],
        raw={},
    )
    db = _IOCTaxonomySession([immutable, mutable])
    stats = {"tables": {}, "rows_changed": 0}

    await taxonomy_migration._normalize_iocs(db, stats)

    assert immutable.tags == ["Raw Label"]
    assert immutable.technique_ids == ["ttp:T1059.001"]
    assert immutable.raw == {"manifest_checksum": "immutable"}
    assert mutable.tags == ["tag:raw-label"]
    assert mutable.technique_ids == ["T1059.001"]
    assert stats["tables"]["ioc_indicators"] == {
        "scanned": 2,
        "changed": 1,
        "skipped_protected": 1,
    }


@pytest.mark.asyncio
async def test_opencti_existing_reviewed_report_is_not_mutated():
    session_id = uuid4()
    existing = AnalysisSession(
        id=session_id,
        status="completed",
        name="Analyst-reviewed title",
        input_type="file",
        filename="opencti:report--protected",
        llm_provider="opencti",
        model="opencti-sync",
        domain="enterprise-attack",
        tlp="TLP:AMBER+STRICT",
        source_text="Immutable reviewed source",
    )
    result = _analysis_result(session_id)
    db = _OpenCTISession(existing, result, review_id=uuid4())

    outcome = await opencti_sync._upsert_opencti_report(
        db,
        {
            "standard_id": "report--protected",
            "name": "Replacement title",
            "description": "Replacement source T1059.001",
            "externalReferences": [{"url": "https://example.test/protected"}],
        },
        "enterprise-attack",
    )

    assert outcome == "protected"
    assert existing.name == "Analyst-reviewed title"
    assert existing.source_text == "Immutable reviewed source"
    assert result.summary == "summary"
    assert result.extracted_techniques[0]["attack_id"] == "ttp:T1059.001"
    assert db.added == []
    assert db.flushes == 0


@pytest.mark.asyncio
async def test_new_opencti_report_enters_review_and_deterministic_preflight(monkeypatch):
    db = _OpenCTISession()
    start = AsyncMock(return_value=SimpleNamespace(version=1))
    preflight = AsyncMock()
    monkeypatch.setattr(opencti_sync, "start_review", start)
    monkeypatch.setattr(opencti_sync, "run_preflight", preflight)
    report = {
        "id": "internal-report-1",
        "standard_id": "report--new",
        "name": "New OpenCTI report",
        "description": "The actor executed PowerShell and the record maps this behavior to T1059.001.",
        "published": "2026-08-20T10:15:00Z",
        "externalReferences": [{"url": "https://example.test/new-report"}],
    }

    outcome = await opencti_sync._upsert_opencti_report(
        db,
        report,
        "enterprise-attack",
    )

    assert outcome == "created"
    stored_session = next(value for value in db.added if isinstance(value, AnalysisSession))
    stored_result = next(value for value in db.added if isinstance(value, AnalysisResult))
    intake = next(value for value in db.added if isinstance(value, ReportIntake))
    evidence = stored_result.extracted_techniques[0]
    assert stored_session.source_text.startswith("OpenCTI report: New OpenCTI report")
    assert stored_session.source_provenance["source_kind"] == "file"
    assert stored_session.source_provenance["origin_kind"] == "opencti-report"
    assert stored_session.source_provenance["acquisition"]["superseded"] is False
    assert stored_session.source_text[evidence["evidence_start"]:evidence["evidence_end"]] == evidence["evidence"]
    assert evidence["review_status"] == "suggested"
    assert evidence["llm_verified"] is False
    assert intake.analysis_session_id == stored_session.id
    assert intake.url == ""
    assert intake.provenance["source_kind"] == "file"
    assert intake.provenance["origin_kind"] == "opencti-report"
    assert intake.provenance["external_reference_url"] == "https://example.test/new-report"
    assert intake.provenance["retrieval"]["publication_date_candidates"] == [
        {"value": "2026-08-20", "source": "opencti.report.published"}
    ]
    start.assert_awaited_once_with(
        db,
        stored_session.id,
        opencti_sync.OPENCTI_REVIEW_ACTOR,
        profile="external_cti",
    )
    preflight.assert_awaited_once_with(
        db,
        stored_session.id,
        opencti_sync.OPENCTI_REVIEW_ACTOR,
        expected_version=1,
    )

    source_metadata = opencti_sync._source_metadata(stored_session, intake)
    source_gate = evaluate_report_preflight(
        stored_session.source_text,
        source_metadata,
        [],
    )["source_provenance"]
    assert source_metadata["source_kind"] == "file"
    assert source_metadata["source_url"] == ""
    assert source_gate["machine_verdict"] == "pass"
    assert source_gate["details"]["summary"] == (
        "Uploaded-file provenance is bound to a complete point-in-time acquisition receipt."
    )


@pytest.mark.asyncio
async def test_legacy_opencti_report_is_updated_then_enters_required_review(monkeypatch):
    session_id = uuid4()
    existing = AnalysisSession(
        id=session_id,
        status="completed",
        name="Legacy OpenCTI title",
        input_type="file",
        filename="opencti:report--legacy",
        llm_provider="opencti",
        model="opencti-sync",
        domain="enterprise-attack",
        tlp="TLP:AMBER+STRICT",
        source_text="Legacy unreviewed source",
    )
    result = _analysis_result(session_id)
    db = _OpenCTISession(existing, result)
    start = AsyncMock(return_value=SimpleNamespace(version=4))
    preflight = AsyncMock()
    monkeypatch.setattr(opencti_sync, "start_review", start)
    monkeypatch.setattr(opencti_sync, "run_preflight", preflight)

    outcome = await opencti_sync._upsert_opencti_report(
        db,
        {
            "standard_id": "report--legacy",
            "name": "Updated OpenCTI title",
            "description": "Updated source references T1059.001.",
            "published": "2026-08-20T10:15:00Z",
        },
        "enterprise-attack",
    )

    assert outcome == "updated"
    assert existing.name == "Updated OpenCTI title"
    assert existing.source_provenance["origin_kind"] == "opencti-report"
    assert any(isinstance(value, ReportIntake) for value in db.added)
    start.assert_awaited_once_with(
        db,
        session_id,
        opencti_sync.OPENCTI_REVIEW_ACTOR,
        profile="external_cti",
    )
    preflight.assert_awaited_once_with(
        db,
        session_id,
        opencti_sync.OPENCTI_REVIEW_ACTOR,
        expected_version=4,
    )


@pytest.mark.asyncio
async def test_new_opencti_report_fails_closed_when_review_initialization_fails(monkeypatch):
    db = _OpenCTISession()
    monkeypatch.setattr(
        opencti_sync,
        "start_review",
        AsyncMock(side_effect=RuntimeError("review unavailable")),
    )

    with pytest.raises(
        opencti_sync.OpenCTISyncError,
        match="could not enter the required Review Gate",
    ):
        await opencti_sync._upsert_opencti_report(
            db,
            {
                "standard_id": "report--failed-review",
                "name": "Review required",
                "description": "Stored source text",
                "externalReferences": [{"url": "https://example.test/review-required"}],
            },
            "enterprise-attack",
        )
