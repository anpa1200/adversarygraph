from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from app.models.analysis import AnalysisSession
from app.models.operations import ReportIntake
from app.models.report_review import ReportReview
from app.services.report_intake import latest_report_intake_id_subquery
from app.services.report_review import _load_intake, collection_summaries


class _Rows:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def scalars(self):
        return self

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


def _postgres_sql(statement) -> str:
    return " ".join(
        str(
            statement.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        ).split()
    )


def test_latest_intake_subquery_is_correlated_and_deterministically_ordered():
    statement = (
        select(AnalysisSession.id, ReportIntake.id)
        .select_from(AnalysisSession)
        .outerjoin(
            ReportIntake,
            ReportIntake.id
            == latest_report_intake_id_subquery(AnalysisSession.id),
        )
    )

    sql = _postgres_sql(statement)

    assert (
        "report_intake.analysis_session_id = analysis_sessions.id"
        in sql
    )
    assert (
        "ORDER BY report_intake.updated_at DESC, report_intake.id DESC LIMIT 1"
        in sql
    )
    assert (
        "LEFT OUTER JOIN report_intake ON report_intake.id = (SELECT report_intake.id"
        in sql
    )


@pytest.mark.asyncio
async def test_review_intake_loader_uses_id_tie_break_for_direct_and_fallback():
    class _DB:
        def __init__(self):
            self.statements = []

        async def execute(self, statement):
            self.statements.append(statement)
            return _Rows()

    db = _DB()

    assert await _load_intake(db, uuid4()) is None

    assert len(db.statements) == 2
    for statement in db.statements:
        assert (
            "ORDER BY report_intake.updated_at DESC, report_intake.id DESC LIMIT 1"
            in _postgres_sql(statement)
        )


@pytest.mark.asyncio
async def test_collection_summary_bulk_intakes_use_id_tie_break():
    class _CapturedIntakeQuery(RuntimeError):
        pass

    class _DB:
        def __init__(self, review):
            self.review = review
            self.calls = 0
            self.intake_statement = None

        async def execute(self, statement):
            self.calls += 1
            if self.calls == 1:
                return _Rows([self.review])
            if self.calls < 6:
                return _Rows()
            self.intake_statement = statement
            raise _CapturedIntakeQuery

    session_id = uuid4()
    review = ReportReview(
        id=uuid4(),
        session_id=session_id,
        revision=1,
        policy_version="report-review-policy-v1.0",
        source_checksum="a" * 64,
        analysis_checksum="b" * 64,
        created_by="test",
    )
    db = _DB(review)

    with pytest.raises(_CapturedIntakeQuery):
        await collection_summaries(db, [session_id])

    sql = _postgres_sql(db.intake_statement)
    assert (
        "ORDER BY report_intake.analysis_session_id, "
        "report_intake.updated_at DESC, report_intake.id DESC"
        in sql
    )
