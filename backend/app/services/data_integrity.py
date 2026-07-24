from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


_SAMPLE_LIMIT = 20
_integrity_snapshot: dict[str, Any] = {
    "status": "pending",
    "checked_at": None,
    "duplicate_groups": {},
    "samples": {},
    "policy": {},
}


def ioc_cve_integrity_snapshot() -> dict[str, Any]:
    """Return the latest completed/background scan state without querying the database."""
    return deepcopy(_integrity_snapshot)


def _publish_snapshot(result: dict[str, Any]) -> None:
    _integrity_snapshot.clear()
    _integrity_snapshot.update(deepcopy(result))


async def inspect_ioc_cve_integrity(session: AsyncSession, *, sample_limit: int = _SAMPLE_LIMIT) -> dict[str, Any]:
    """
    Inspect IOC/CVE deduplication integrity without mutating data.

    Exact IOC repeats across different sources are expected in threat-intel data
    and are reported as cross-source overlap, not as duplicate corruption. Error
    conditions are limited to rows that should be canonical inside this schema:
    one normalized IOC value/type per source and one normalized CVE ID globally.
    """
    _publish_snapshot(
        {
            "status": "running",
            "checked_at": None,
            "duplicate_groups": {},
            "samples": {},
            "policy": {},
        }
    )
    exact_ioc_duplicates = await _rows(
        session,
        """
        select value, indicator_type, source_id, count(*)::int as rows
        from ioc_indicators
        group by value, indicator_type, source_id
        having count(*) > 1
        order by rows desc, source_id, indicator_type, value
        limit :limit
        """,
        sample_limit,
    )
    normalized_ioc_duplicates = await _rows(
        session,
        """
        select
            lower(trim(value)) as normalized_value,
            lower(trim(indicator_type)) as normalized_type,
            source_id,
            count(*)::int as rows,
            array_agg(id order by id) as sample_ids
        from ioc_indicators
        group by lower(trim(value)), lower(trim(indicator_type)), source_id
        having count(*) > 1
        order by rows desc, source_id, normalized_type, normalized_value
        limit :limit
        """,
        sample_limit,
    )
    cve_duplicates = await _rows(
        session,
        """
        select
            upper(trim(cve_id)) as cve_id,
            count(*)::int as rows,
            array_agg(id order by id) as sample_ids
        from cve_records
        group by upper(trim(cve_id))
        having count(*) > 1
        order by rows desc, cve_id
        limit :limit
        """,
        sample_limit,
    )
    cross_source_ioc_overlap = await _rows(
        session,
        """
        select
            lower(trim(value)) as normalized_value,
            lower(trim(indicator_type)) as normalized_type,
            count(distinct source_id)::int as source_count,
            count(*)::int as rows,
            array_agg(distinct source_id order by source_id) as sample_sources
        from ioc_indicators
        group by lower(trim(value)), lower(trim(indicator_type))
        having count(distinct source_id) > 1
        order by source_count desc, rows desc, normalized_type, normalized_value
        limit :limit
        """,
        sample_limit,
    )
    totals_result = await session.execute(
        text(
            """
            select
                (select count(*)::int from ioc_indicators) as ioc_records,
                (select count(*)::int from cve_records) as cve_records,
                (select count(distinct lower(trim(value)) || '|' || lower(trim(indicator_type)) || '|' || source_id)::int from ioc_indicators) as normalized_ioc_keys,
                (select count(distinct upper(trim(cve_id)))::int from cve_records) as normalized_cve_keys
            """
        )
    )
    totals = dict(totals_result.one()._mapping)

    exact_ioc_duplicate_groups = len(exact_ioc_duplicates)
    normalized_ioc_duplicate_groups = len(normalized_ioc_duplicates)
    cve_duplicate_groups = len(cve_duplicates)
    cross_source_overlap_groups = len(cross_source_ioc_overlap)
    status = "error" if normalized_ioc_duplicate_groups or cve_duplicate_groups or exact_ioc_duplicate_groups else "ok"

    result = {
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "totals": totals,
        "duplicate_groups": {
            "exact_ioc_value_type_source": exact_ioc_duplicate_groups,
            "normalized_ioc_value_type_source": normalized_ioc_duplicate_groups,
            "normalized_cve_id": cve_duplicate_groups,
            "cross_source_ioc_overlap": cross_source_overlap_groups,
        },
        "samples": {
            "exact_ioc_duplicates": exact_ioc_duplicates,
            "normalized_ioc_duplicates": normalized_ioc_duplicates,
            "cve_duplicates": cve_duplicates,
            "cross_source_ioc_overlap": cross_source_ioc_overlap,
        },
        "policy": {
            "ioc_canonical_key": "lower(trim(value)) + lower(trim(indicator_type)) + source_id",
            "cve_canonical_key": "upper(trim(cve_id))",
            "cross_source_ioc_overlap": "reported for visibility; not treated as corruption",
        },
    }
    _publish_snapshot(result)
    return result


def mark_ioc_cve_integrity_unavailable(exc: Exception) -> dict[str, Any]:
    """Publish a safe failure state for self-test without exposing database details."""
    result = {
        "status": "unavailable",
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "duplicate_groups": {},
        "samples": {},
        "policy": {},
        "error_type": type(exc).__name__,
    }
    _publish_snapshot(result)
    return result


async def _rows(session: AsyncSession, sql: str, limit: int) -> list[dict[str, Any]]:
    result = await session.execute(text(sql), {"limit": max(1, min(limit, 100))})
    return [dict(row._mapping) for row in result.fetchall()]
