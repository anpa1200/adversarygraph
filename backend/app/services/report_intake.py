"""Shared deterministic selection helpers for analysis-linked report intake."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.sql.elements import ColumnElement
from sqlalchemy.sql.selectable import ScalarSelect

from app.models.operations import ReportIntake


def latest_report_intake_id_subquery(
    session_id_column: ColumnElement[Any],
) -> ScalarSelect[Any]:
    """Select one authoritative intake per outer analysis-session row.

    ``updated_at`` is the freshness authority and UUID ``id`` is the stable
    tie-breaker.  ``correlate_except`` keeps the inner intake table local while
    allowing the supplied outer session column to correlate naturally.
    """

    return (
        select(ReportIntake.id)
        .where(ReportIntake.analysis_session_id == session_id_column)
        .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
        .limit(1)
        .correlate_except(ReportIntake)
        .scalar_subquery()
    )
