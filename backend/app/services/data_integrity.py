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
                (select count(distinct upper(trim(cve_id)))::int from cve_records) as normalized_cve_keys,
                (select count(*)::int from ioc_indicators where jsonb_array_length(coalesce(tags, '[]'::jsonb)) = 0) as untagged_iocs,
                (select count(*)::int from cve_records where jsonb_array_length(coalesce(tags, '[]'::jsonb)) = 0) as untagged_cves,
                (select count(*)::int from report_intake where jsonb_array_length(coalesce(tags, '[]'::jsonb)) = 0) as untagged_reports,
                (select count(*)::int from intelligence_tags where canonical <> namespace || ':' || value) as malformed_canonical_tags,
                (select count(*)::int
                   from intelligence_entity_tags entity_tag
                   left join intelligence_tags tag on tag.canonical = entity_tag.tag
                  where tag.canonical is null) as orphan_entity_tags
            """
        )
    )
    totals = dict(totals_result.one()._mapping)

    exact_ioc_duplicate_groups = len(exact_ioc_duplicates)
    normalized_ioc_duplicate_groups = len(normalized_ioc_duplicates)
    cve_duplicate_groups = len(cve_duplicates)
    cross_source_overlap_groups = len(cross_source_ioc_overlap)
    structural_errors = sum(
        int(totals.get(key) or 0)
        for key in (
            "untagged_iocs",
            "untagged_cves",
            "untagged_reports",
            "malformed_canonical_tags",
            "orphan_entity_tags",
        )
    )
    status = "error" if (
        normalized_ioc_duplicate_groups
        or cve_duplicate_groups
        or exact_ioc_duplicate_groups
        or structural_errors
    ) else "ok"

    result = {
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "totals": totals,
        "duplicate_groups": {
            "exact_ioc_value_type_source": exact_ioc_duplicate_groups,
            "normalized_ioc_value_type_source": normalized_ioc_duplicate_groups,
            "normalized_cve_id": cve_duplicate_groups,
            "cross_source_ioc_overlap": cross_source_overlap_groups,
            "structural_tag_errors": structural_errors,
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
            "canonical_tags": "every IOC, CVE, and report must have at least one normalized tag; tag links must resolve",
        },
    }
    _publish_snapshot(result)
    return result


async def database_inventory_snapshot(session: AsyncSession) -> dict[str, Any]:
    """
    Live counts across the core intelligence data model: IOCs, CVEs, ATT&CK
    techniques/tactics/groups, campaigns, tags, cross-entity correlations,
    assets, and reports. Read-only; safe to run on every self-test.
    """
    totals_result = await session.execute(
        text(
            """
            select
                (select count(*)::int from ioc_indicators) as ioc_total,
                (select count(*)::int from cve_records) as cve_total,
                (select count(*)::int from cve_records where known_exploited) as cve_known_exploited,
                (select count(*)::int from techniques) as technique_total,
                (select count(*)::int from tactics) as tactic_total,
                (select count(*)::int from apt_groups) as group_total,
                (select count(*)::int from campaigns) as campaign_total,
                (select count(*)::int from intelligence_tags) as tag_total,
                (select count(*)::int from intelligence_entity_tags) as tag_application_total,
                (select count(*)::int from ioc_actor_links) as ioc_actor_link_total,
                (select count(*)::int from cve_actor_links) as cve_actor_link_total,
                (select count(*)::int from cve_technique_links) as cve_technique_link_total,
                (select count(*)::int from asset_registry_items) as asset_total,
                (select count(*)::int from report_intake) as report_total
            """
        )
    )
    totals = dict(totals_result.one()._mapping)

    domain_rows = await session.execute(
        text(
            """
            select 'technique' as kind, domain, count(*)::int as rows from techniques group by domain
            union all
            select 'tactic' as kind, domain, count(*)::int as rows from tactics group by domain
            union all
            select 'group' as kind, domain, count(*)::int as rows from apt_groups group by domain
            order by kind, domain
            """
        )
    )
    by_domain: dict[str, dict[str, int]] = {"technique": {}, "tactic": {}, "group": {}}
    for row in domain_rows.mappings():
        by_domain[row["kind"]][row["domain"]] = row["rows"]

    tag_namespace_rows = await session.execute(
        text(
            """
            select namespace, count(*)::int as rows
            from intelligence_tags
            group by namespace
            order by rows desc
            limit 20
            """
        )
    )
    tags_by_namespace = {row["namespace"]: row["rows"] for row in tag_namespace_rows.mappings()}

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "totals": totals,
        "attack_by_domain": by_domain,
        "tags_by_namespace": tags_by_namespace,
    }


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
