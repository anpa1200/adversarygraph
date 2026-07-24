from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_session
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import (
    AptGroup,
    AptGroupTechnique,
    Campaign,
    CampaignTechnique,
    Tactic,
    Technique,
)
from app.models.cve import CVEActorLink, CVEIOCLink, CVERecord, CVETechniqueLink
from app.models.ioc import IOCActorLink, IOCIndicator, IOCSource
from app.models.sector_packs import SectorPack
from app.services.auth import TeamUser, current_user
from app.services.telemetry_readiness import infer_telemetry_source_tags

router = APIRouter(prefix="/statistics", tags=["Statistics"])

VALID_DATASETS = {
    "actors",
    "reports",
    "sectors",
    "ttps",
    "cves",
    "iocs",
}


class StatPoint(BaseModel):
    label: str
    value: float | int
    id: str = ""
    secondary: str = ""
    category: str = ""
    detail: str = ""


class StatWidget(BaseModel):
    id: str
    title: str
    description: str
    dataset: str
    kind: str = Field(pattern="^(bar|pie|table|score)$")
    points: list[StatPoint] = Field(default_factory=list)


class StatisticsOverview(BaseModel):
    generated_at: str
    domain: str
    included: list[str]
    totals: list[StatPoint]
    widgets: list[StatWidget]


async def _count(session: AsyncSession, statement: Any) -> int:
    try:
        value = await session.scalar(statement)
        return int(value or 0)
    except Exception:
        await session.rollback()
        return 0


async def _rows(session: AsyncSession, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        result = await session.execute(text(sql), params or {})
        return [dict(row) for row in result.mappings().all()]
    except Exception:
        await session.rollback()
        return []


def _point(row: dict[str, Any], label: str = "label", value: str = "value", **extra: str) -> StatPoint:
    return StatPoint(
        label=str(row.get(label) or "unknown"),
        value=int(row.get(value) or 0),
        id=str(row.get(extra.get("id", "id")) or ""),
        secondary=str(row.get(extra.get("secondary", "secondary")) or ""),
        category=str(row.get(extra.get("category", "category")) or ""),
        detail=str(row.get(extra.get("detail", "detail")) or ""),
    )


async def _technique_source_tag_rows(session: AsyncSession, domain: str, limit: int) -> list[dict[str, Any]]:
    try:
        result = await session.execute(
            select(Technique)
            .where(Technique.domain == domain, Technique.is_deprecated.is_(False))
            .options(selectinload(Technique.tactics))
        )
        techniques = result.scalars().all()
    except Exception:
        await session.rollback()
        return []

    counts: Counter[str] = Counter()
    for technique in techniques:
        tactics = [tactic.shortname for tactic in technique.tactics]
        tags = infer_telemetry_source_tags(
            technique.attack_id,
            tactics,
            technique.platforms or [],
            technique.data_sources or [],
            technique.detection or "",
            technique.description or "",
            technique.name,
        )
        for tag in tags:
            counts[tag.split(":", 1)[0]] += 1

    return [
        {"id": tag, "label": tag, "value": value}
        for tag, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    ]


@router.get("/overview", response_model=StatisticsOverview)
async def statistics_overview(
    domain: str = Query("enterprise-attack"),
    include: list[str] = Query(default_factory=lambda: sorted(VALID_DATASETS)),
    limit: int = Query(15, ge=5, le=50),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    selected = [item for item in include if item in VALID_DATASETS] or sorted(VALID_DATASETS)
    widgets: list[StatWidget] = []
    totals: list[StatPoint] = []

    if "ttps" in selected:
        technique_count = await _count(
            session,
            select(func.count()).select_from(Technique).where(Technique.domain == domain, Technique.is_deprecated.is_(False)),
        )
        subtechnique_count = await _count(
            session,
            select(func.count()).select_from(Technique).where(
                Technique.domain == domain,
                Technique.is_subtechnique.is_(True),
                Technique.is_deprecated.is_(False),
            ),
        )
        tactic_count = await _count(session, select(func.count()).select_from(Tactic).where(Tactic.domain == domain))
        totals.extend([
            StatPoint(label="Techniques", value=technique_count, detail="ATT&CK/ATLAS techniques in selected domain"),
            StatPoint(label="Sub-techniques", value=subtechnique_count, detail="Sub-techniques in selected domain"),
            StatPoint(label="Tactics", value=tactic_count, detail="Tactics in selected domain"),
        ])
        tactic_rows = await _rows(
            session,
            """
            SELECT ta.name AS label, COUNT(tt.technique_id)::int AS value, ta.shortname AS category
            FROM tactics ta
            LEFT JOIN technique_tactics tt ON tt.tactic_id = ta.id
            WHERE ta.domain = :domain
            GROUP BY ta.id, ta.name, ta.shortname
            ORDER BY value DESC, ta.name ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="tactic-distribution",
            title="Technique Distribution By Tactic",
            description="How the selected ATT&CK domain is distributed across tactics.",
            dataset="ttps",
            kind="bar",
            points=[_point(row, category="category") for row in tactic_rows],
        ))
        platform_rows = await _rows(
            session,
            """
            SELECT platform AS id, platform AS label, COUNT(*)::int AS value
            FROM techniques t,
                 LATERAL jsonb_array_elements_text(t.platforms) AS platform
            WHERE t.domain = :domain AND t.is_deprecated = false
            GROUP BY platform
            ORDER BY value DESC, platform ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="ttp-platform-tags",
            title="TTP Platform Tags",
            description="Technique tags by supported platform such as Windows, Linux, Network, Office, or cloud services.",
            dataset="ttps",
            kind="bar",
            points=[_point(row, id="id") for row in platform_rows],
        ))
        datasource_rows = await _technique_source_tag_rows(session, domain, limit)
        widgets.append(StatWidget(
            id="ttp-telemetry-source-tags",
            title="TTP Telemetry Source Tags",
            description="Technique tags by ATT&CK data-source family. Useful for telemetry-readiness planning.",
            dataset="ttps",
            kind="bar",
            points=[_point(row, id="id") for row in datasource_rows],
        ))
    if "actors" in selected:
        actor_count = await _count(session, select(func.count()).select_from(AptGroup).where(AptGroup.domain == domain))
        campaign_count = await _count(session, select(func.count()).select_from(Campaign).where(Campaign.domain == domain))
        actor_usage_count = await _count(session, select(func.count()).select_from(AptGroupTechnique))
        campaign_usage_count = await _count(session, select(func.count()).select_from(CampaignTechnique))
        totals.extend([
            StatPoint(label="Actors", value=actor_count, detail="ATT&CK groups in selected domain"),
            StatPoint(label="Campaigns", value=campaign_count, detail="ATT&CK campaigns in selected domain"),
            StatPoint(label="Actor TTP links", value=actor_usage_count, detail="Group-to-technique relationships"),
            StatPoint(label="Campaign TTP links", value=campaign_usage_count, detail="Campaign-to-technique relationships"),
        ])
        actor_rows = await _rows(
            session,
            """
            SELECT g.attack_id AS id, g.name AS label, COUNT(gt.technique_id)::int AS value,
                   g.domain AS category
            FROM apt_groups g
            JOIN apt_group_techniques gt ON gt.group_id = g.id
            WHERE g.domain = :domain
            GROUP BY g.id, g.attack_id, g.name, g.domain
            ORDER BY value DESC, g.name ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="actor-technique-coverage",
            title="Actors By Mapped Techniques",
            description="Actors with the largest ATT&CK technique coverage in the local knowledge base.",
            dataset="actors",
            kind="bar",
            points=[_point(row, id="id", category="category") for row in actor_rows],
        ))
        technique_usage_rows = await _rows(
            session,
            """
            SELECT t.attack_id AS id, t.name AS label, COUNT(gt.group_id)::int AS value,
                   string_agg(DISTINCT ta.shortname, ', ' ORDER BY ta.shortname) AS category
            FROM techniques t
            JOIN apt_group_techniques gt ON gt.technique_id = t.id
            LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
            LEFT JOIN tactics ta ON ta.id = tt.tactic_id
            WHERE t.domain = :domain AND t.is_deprecated = false
            GROUP BY t.id, t.attack_id, t.name
            ORDER BY value DESC, t.attack_id ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="top-techniques-by-actor-usage",
            title="Most Used TTPs By Actors",
            description="Techniques that appear across the most actor profiles.",
            dataset="actors",
            kind="table",
            points=[_point(row, id="id", category="category") for row in technique_usage_rows],
        ))
        actor_risk_rows = await _rows(
            session,
            """
            WITH actor_usage AS (
                SELECT g.id, COUNT(gt.technique_id) AS technique_count
                FROM apt_groups g
                LEFT JOIN apt_group_techniques gt ON gt.group_id = g.id
                WHERE g.domain = :domain
                GROUP BY g.id
            )
            SELECT CASE
                    WHEN technique_count >= 50 THEN 'high-coverage actor'
                    WHEN technique_count >= 20 THEN 'medium-coverage actor'
                    WHEN technique_count > 0 THEN 'low-coverage actor'
                    ELSE 'no mapped techniques'
                   END AS label,
                   COUNT(*)::int AS value
            FROM actor_usage
            GROUP BY label
            ORDER BY value DESC, label ASC
            """,
            {"domain": domain},
        )
        widgets.append(StatWidget(
            id="actor-risk-tags",
            title="Actor Risk / Coverage Tags",
            description="Actor tags derived from mapped technique breadth. This is coverage pressure, not attribution certainty.",
            dataset="actors",
            kind="pie",
            points=[_point(row) for row in actor_risk_rows],
        ))
        actor_region_rows = await _rows(
            session,
            """
            SELECT region AS label, COUNT(*)::int AS value
            FROM (
                SELECT CASE
                    WHEN description ILIKE ANY (ARRAY['%iran%', '%middle east%', '%israel%', '%gulf%', '%lebanon%', '%saudi%', '%uae%']) THEN 'Middle East'
                    WHEN description ILIKE ANY (ARRAY['%china%', '%korea%', '%japan%', '%taiwan%', '%vietnam%', '%india%', '%asia%']) THEN 'Asia-Pacific'
                    WHEN description ILIKE ANY (ARRAY['%russia%', '%ukraine%', '%europe%', '%belarus%']) THEN 'Europe / Eurasia'
                    WHEN description ILIKE ANY (ARRAY['%north america%', '%united states%', '%canada%', '%latin america%', '%mexico%', '%brazil%']) THEN 'Americas'
                    WHEN description ILIKE ANY (ARRAY['%africa%', '%egypt%', '%morocco%']) THEN 'Africa'
                    ELSE 'Unknown / global'
                END AS region
                FROM apt_groups
                WHERE domain = :domain
            ) tagged
            GROUP BY region
            ORDER BY value DESC, region ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="actor-region-tags",
            title="Actor Region Tags",
            description="Heuristic regional tags derived from ATT&CK group descriptions and aliases.",
            dataset="actors",
            kind="bar",
            points=[_point(row) for row in actor_region_rows],
        ))
        actor_sector_rows = await _rows(
            session,
            """
            SELECT sector AS label, COUNT(*)::int AS value
            FROM (
                SELECT unnest(ARRAY[
                    CASE WHEN description ILIKE ANY (ARRAY['%government%', '%ministry%', '%diplomatic%', '%embassy%']) THEN 'government' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%defense%', '%military%', '%aerospace%']) THEN 'defense' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%energy%', '%oil%', '%gas%', '%electric%']) THEN 'energy' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%telecom%', '%telecommunications%']) THEN 'telecom' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%financial%', '%bank%', '%cryptocurrency%', '%crypto%']) THEN 'finance' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%health%', '%hospital%', '%pharma%']) THEN 'healthcare' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%technology%', '%software%', '%cloud%', '%it service%']) THEN 'technology' END
                ]) AS sector
                FROM apt_groups
                WHERE domain = :domain
            ) tagged
            WHERE sector IS NOT NULL
            GROUP BY sector
            ORDER BY value DESC, sector ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="actor-sector-tags",
            title="Actor Target-Sector Tags",
            description="Heuristic sector tags derived from actor descriptions. Use as an exploration lead, not a source of truth.",
            dataset="actors",
            kind="bar",
            points=[_point(row) for row in actor_sector_rows],
        ))

    if "reports" in selected:
        report_count = await _count(session, select(func.count()).select_from(AnalysisSession))
        completed_reports = await _count(
            session,
            select(func.count()).select_from(AnalysisSession).where(AnalysisSession.status == "completed"),
        )
        totals.extend([
            StatPoint(label="Analysis reports", value=report_count, detail="Stored AI analysis sessions"),
            StatPoint(label="Completed reports", value=completed_reports, detail="Completed AI report analyses"),
        ])
        report_ttp_rows = await _rows(
            session,
            """
            SELECT COALESCE(item->>'attack_id', item->>'technique_id', item->>'id', 'unknown') AS id,
                   COALESCE(NULLIF(item->>'name', ''), COALESCE(item->>'attack_id', item->>'technique_id', 'unknown')) AS label,
                   COUNT(*)::int AS value,
                   ROUND(AVG(CASE
                       WHEN item->>'confidence' ~ '^[0-9]+(\\.[0-9]+)?$' THEN (item->>'confidence')::numeric
                       ELSE NULL
                   END), 1)::text AS secondary
            FROM analysis_results ar,
                 LATERAL jsonb_array_elements(ar.extracted_techniques) AS item
            GROUP BY id, label
            ORDER BY value DESC, id ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="report-technique-usage",
            title="TTPs Extracted From Reports",
            description="Techniques most often extracted from stored AI report analyses. Secondary value is average confidence when available.",
            dataset="reports",
            kind="table",
            points=[_point(row, id="id", secondary="secondary") for row in report_ttp_rows],
        ))
        report_provider_rows = await _rows(
            session,
            """
            SELECT COALESCE(NULLIF(llm_provider, ''), 'unknown') AS label, COUNT(*)::int AS value
            FROM analysis_sessions
            GROUP BY label
            ORDER BY value DESC, label ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="report-provider-tags",
            title="Report AI Provider Tags",
            description="Stored report-analysis sessions grouped by LLM/provider tag.",
            dataset="reports",
            kind="pie",
            points=[_point(row) for row in report_provider_rows],
        ))
        report_confidence_rows = await _rows(
            session,
            """
            SELECT CASE
                    WHEN confidence >= 80 THEN 'high-confidence TTP'
                    WHEN confidence >= 50 THEN 'medium-confidence TTP'
                    WHEN confidence >= 1 THEN 'low-confidence TTP'
                    ELSE 'missing confidence'
                   END AS label,
                   COUNT(*)::int AS value
            FROM (
                SELECT COALESCE(CASE
                    WHEN item->>'confidence' ~ '^[0-9]+(\\.[0-9]+)?$' THEN (item->>'confidence')::numeric
                    ELSE NULL
                END, 0) AS confidence
                FROM analysis_results ar,
                     LATERAL jsonb_array_elements(ar.extracted_techniques) AS item
            ) scored
            GROUP BY label
            ORDER BY value DESC, label ASC
            """,
        )
        widgets.append(StatWidget(
            id="report-confidence-tags",
            title="Report Extraction Confidence Tags",
            description="Confidence bands for TTPs extracted from reports by AI analysis.",
            dataset="reports",
            kind="bar",
            points=[_point(row) for row in report_confidence_rows],
        ))

    if "cves" in selected:
        cve_count = await _count(session, select(func.count()).select_from(CVERecord))
        kev_count = await _count(session, select(func.count()).select_from(CVERecord).where(CVERecord.known_exploited.is_(True)))
        cve_ttp_links = await _count(session, select(func.count()).select_from(CVETechniqueLink))
        cve_actor_links = await _count(session, select(func.count()).select_from(CVEActorLink))
        cve_ioc_links = await _count(session, select(func.count()).select_from(CVEIOCLink))
        totals.extend([
            StatPoint(label="CVEs", value=cve_count, detail="Stored CVE records"),
            StatPoint(label="CISA KEV", value=kev_count, detail="Known exploited CVEs"),
            StatPoint(label="CVE-TTP links", value=cve_ttp_links, detail="CVE to ATT&CK relationships"),
            StatPoint(label="CVE-actor links", value=cve_actor_links, detail="CVE to actor relationships"),
            StatPoint(label="CVE-IOC links", value=cve_ioc_links, detail="CVE to IOC relationships"),
        ])
        severity_rows = await _rows(
            session,
            """
            SELECT COALESCE(NULLIF(cvss_severity, ''), 'UNKNOWN') AS label, COUNT(*)::int AS value
            FROM cve_records
            GROUP BY label
            ORDER BY value DESC
            """,
        )
        widgets.append(StatWidget(
            id="cve-severity-distribution",
            title="CVE Severity Distribution",
            description="CVSS severity distribution across the local CVE Library.",
            dataset="cves",
            kind="pie",
            points=[_point(row) for row in severity_rows],
        ))
        cve_ttp_rows = await _rows(
            session,
            """
            SELECT l.attack_id AS id, COALESCE(t.name, l.attack_id) AS label, COUNT(*)::int AS value,
                   ROUND(AVG(l.confidence), 1)::text AS secondary
            FROM cve_technique_links l
            LEFT JOIN techniques t ON t.attack_id = l.attack_id AND t.domain = :domain
            GROUP BY l.attack_id, t.name
            ORDER BY value DESC, l.attack_id ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="cve-technique-usage",
            title="TTPs Most Linked To CVEs",
            description="Techniques most often connected to CVE exploitation context. Secondary value is average confidence.",
            dataset="cves",
            kind="table",
            points=[_point(row, id="id", secondary="secondary") for row in cve_ttp_rows],
        ))
        cwe_rows = await _rows(
            session,
            """
            SELECT cwe AS id, cwe AS label, COUNT(*)::int AS value
            FROM cve_records c,
                 LATERAL jsonb_array_elements_text(c.cwe_ids) AS cwe
            GROUP BY cwe
            ORDER BY value DESC, cwe ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="top-cwe",
            title="Most Common Weakness Classes",
            description="Top CWE IDs observed in the local CVE Library.",
            dataset="cves",
            kind="bar",
            points=[_point(row, id="id") for row in cwe_rows],
        ))
        cve_risk_rows = await _rows(
            session,
            """
            SELECT label, COUNT(*)::int AS value
            FROM (
                SELECT CASE
                    WHEN known_exploited THEN 'risk: cisa-kev'
                    WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric >= 9 THEN 'risk: critical'
                    WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric >= 7 THEN 'risk: high'
                    WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric >= 4 THEN 'risk: medium'
                    WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric > 0 THEN 'risk: low'
                    ELSE 'risk: unknown'
                END AS label
                FROM cve_records
            ) tagged
            GROUP BY label
            ORDER BY value DESC, label ASC
            """,
        )
        widgets.append(StatWidget(
            id="cve-risk-tags",
            title="CVE Risk Tags",
            description="CVE tags derived from CVSS score and CISA KEV status.",
            dataset="cves",
            kind="pie",
            points=[_point(row) for row in cve_risk_rows],
        ))
        cve_attack_vector_rows = await _rows(
            session,
            """
            SELECT CASE
                    WHEN cvss_vector LIKE '%/AV:N/%' OR cvss_vector LIKE 'CVSS:%/AV:N/%' THEN 'attack-vector: network'
                    WHEN cvss_vector LIKE '%/AV:A/%' OR cvss_vector LIKE 'CVSS:%/AV:A/%' THEN 'attack-vector: adjacent'
                    WHEN cvss_vector LIKE '%/AV:L/%' OR cvss_vector LIKE 'CVSS:%/AV:L/%' THEN 'attack-vector: local'
                    WHEN cvss_vector LIKE '%/AV:P/%' OR cvss_vector LIKE 'CVSS:%/AV:P/%' THEN 'attack-vector: physical'
                    ELSE 'attack-vector: unknown'
                   END AS label,
                   COUNT(*)::int AS value
            FROM cve_records
            GROUP BY label
            ORDER BY value DESC, label ASC
            """,
        )
        widgets.append(StatWidget(
            id="cve-attack-vector-tags",
            title="CVE Attack Vector Tags",
            description="CVSS vector tags that identify network, adjacent, local, physical, or unknown exposure.",
            dataset="cves",
            kind="bar",
            points=[_point(row) for row in cve_attack_vector_rows],
        ))
        cve_source_rows = await _rows(
            session,
            """
            SELECT COALESCE(s.label, c.source_id, 'unknown') AS label, COUNT(c.id)::int AS value,
                   COALESCE(c.source_id, '') AS id
            FROM cve_records c
            LEFT JOIN cve_sources s ON s.source_id = c.source_id
            GROUP BY c.source_id, s.label
            ORDER BY value DESC, label ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="cve-source-tags",
            title="CVE Source Tags",
            description="CVE Library coverage by source/feed tag.",
            dataset="cves",
            kind="bar",
            points=[_point(row, id="id") for row in cve_source_rows],
        ))
        cve_confidence_rows = await _rows(
            session,
            """
            SELECT label, COUNT(*)::int AS value
            FROM (
                SELECT CASE
                    WHEN confidence >= 85 THEN 'high-confidence CVE link'
                    WHEN confidence >= 60 THEN 'medium-confidence CVE link'
                    WHEN confidence > 0 THEN 'low-confidence CVE link'
                    ELSE 'missing confidence'
                END AS label
                FROM cve_technique_links
                UNION ALL
                SELECT CASE
                    WHEN confidence >= 85 THEN 'high-confidence actor link'
                    WHEN confidence >= 60 THEN 'medium-confidence actor link'
                    WHEN confidence > 0 THEN 'low-confidence actor link'
                    ELSE 'missing confidence'
                END AS label
                FROM cve_actor_links
                UNION ALL
                SELECT CASE
                    WHEN confidence >= 85 THEN 'high-confidence IOC link'
                    WHEN confidence >= 60 THEN 'medium-confidence IOC link'
                    WHEN confidence > 0 THEN 'low-confidence IOC link'
                    ELSE 'missing confidence'
                END AS label
                FROM cve_ioc_links
            ) tagged
            GROUP BY label
            ORDER BY value DESC, label ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="cve-relationship-confidence-tags",
            title="CVE Relationship Confidence Tags",
            description="Confidence bands across CVE-to-TTP, CVE-to-actor, and CVE-to-IOC links.",
            dataset="cves",
            kind="bar",
            points=[_point(row) for row in cve_confidence_rows],
        ))

    if "iocs" in selected:
        ioc_count = await _count(session, select(func.count()).select_from(IOCIndicator))
        ioc_sources = await _count(session, select(func.count()).select_from(IOCSource))
        ioc_actor_links = await _count(session, select(func.count()).select_from(IOCActorLink))
        totals.extend([
            StatPoint(label="IOCs", value=ioc_count, detail="Stored indicators"),
            StatPoint(label="IOC sources", value=ioc_sources, detail="Configured indicator sources"),
            StatPoint(label="IOC-actor links", value=ioc_actor_links, detail="Evidence-backed IOC actor links"),
        ])
        ioc_type_rows = await _rows(
            session,
            """
            SELECT indicator_type AS label, COUNT(*)::int AS value
            FROM ioc_indicators
            GROUP BY indicator_type
            ORDER BY value DESC, indicator_type ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="ioc-type-distribution",
            title="IOC Type Distribution",
            description="Indicator volume by observable type.",
            dataset="iocs",
            kind="pie",
            points=[_point(row) for row in ioc_type_rows],
        ))
        ioc_source_rows = await _rows(
            session,
            """
            SELECT COALESCE(s.label, i.source_id) AS label, COUNT(i.id)::int AS value, i.source_id AS id
            FROM ioc_indicators i
            LEFT JOIN ioc_sources s ON s.source_id = i.source_id
            GROUP BY i.source_id, s.label
            ORDER BY value DESC, label ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="ioc-source-distribution",
            title="IOC Volume By Source",
            description="Which feeds contribute the most indicators.",
            dataset="iocs",
            kind="bar",
            points=[_point(row, id="id") for row in ioc_source_rows],
        ))
        ioc_ttp_rows = await _rows(
            session,
            """
            SELECT tid AS id, COALESCE(t.name, tid) AS label, COUNT(*)::int AS value
            FROM ioc_indicators i,
                 LATERAL jsonb_array_elements_text(i.technique_ids) AS tid
            LEFT JOIN techniques t ON t.attack_id = tid AND t.domain = :domain
            GROUP BY tid, t.name
            ORDER BY value DESC, tid ASC
            LIMIT :limit
            """,
            {"domain": domain, "limit": limit},
        )
        widgets.append(StatWidget(
            id="ioc-technique-usage",
            title="TTPs Most Linked To IOCs",
            description="Techniques most frequently attached to collected indicators.",
            dataset="iocs",
            kind="table",
            points=[_point(row, id="id") for row in ioc_ttp_rows],
        ))
        ioc_confidence_rows = await _rows(
            session,
            """
            SELECT CASE
                    WHEN confidence >= 85 THEN 'confidence: high'
                    WHEN confidence >= 60 THEN 'confidence: medium'
                    WHEN confidence > 0 THEN 'confidence: low'
                    ELSE 'confidence: unknown'
                   END AS label,
                   COUNT(*)::int AS value
            FROM ioc_indicators
            GROUP BY label
            ORDER BY value DESC, label ASC
            """,
        )
        widgets.append(StatWidget(
            id="ioc-confidence-tags",
            title="IOC Confidence Tags",
            description="Indicator confidence bands from the normalized IOC Library.",
            dataset="iocs",
            kind="pie",
            points=[_point(row) for row in ioc_confidence_rows],
        ))
        ioc_tlp_rows = await _rows(
            session,
            """
            SELECT COALESCE(NULLIF(UPPER(tlp), ''), 'UNKNOWN') AS label, COUNT(*)::int AS value
            FROM ioc_indicators
            GROUP BY label
            ORDER BY value DESC, label ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="ioc-tlp-tags",
            title="IOC TLP Tags",
            description="Traffic Light Protocol tags attached to stored indicators.",
            dataset="iocs",
            kind="pie",
            points=[_point(row) for row in ioc_tlp_rows],
        ))
        ioc_malware_rows = await _rows(
            session,
            """
            SELECT malware_family AS label, COUNT(*)::int AS value
            FROM ioc_indicators
            WHERE COALESCE(NULLIF(malware_family, ''), '') <> ''
            GROUP BY malware_family
            ORDER BY value DESC, malware_family ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="ioc-malware-family-tags",
            title="IOC Malware Family Tags",
            description="Malware-family tags attached to collected indicators.",
            dataset="iocs",
            kind="bar",
            points=[_point(row) for row in ioc_malware_rows],
        ))
        ioc_tag_rows = await _rows(
            session,
            """
            SELECT tag AS id, tag AS label, COUNT(*)::int AS value
            FROM ioc_indicators i,
                 LATERAL jsonb_array_elements_text(i.tags) AS tag
            GROUP BY tag
            ORDER BY value DESC, tag ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="ioc-freeform-tags",
            title="IOC Freeform Tags",
            description="Source-provided and enrichment tags stored with IOC records.",
            dataset="iocs",
            kind="table",
            points=[_point(row, id="id") for row in ioc_tag_rows],
        ))

    if "sectors" in selected:
        sector_count = await _count(session, select(func.count()).select_from(SectorPack))
        totals.append(StatPoint(label="Sector packs", value=sector_count, detail="Stored sector intelligence packs"))
        sector_confidence_rows = await _rows(
            session,
            """
            SELECT COALESCE(NULLIF(confidence_level, ''), 'Unknown') AS label, COUNT(*)::int AS value
            FROM sector_packs
            GROUP BY label
            ORDER BY value DESC, label ASC
            """,
        )
        widgets.append(StatWidget(
            id="sector-confidence",
            title="Sector Pack Confidence",
            description="Confidence levels across sector intelligence packs.",
            dataset="sectors",
            kind="pie",
            points=[_point(row) for row in sector_confidence_rows],
        ))
        sector_actor_rows = await _rows(
            session,
            """
            SELECT actor AS label, COUNT(*)::int AS value
            FROM sector_packs s,
                 LATERAL jsonb_array_elements_text(s.likely_threat_actors) AS actor
            GROUP BY actor
            ORDER BY value DESC, actor ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="sector-actor-mentions",
            title="Actors Most Mentioned In Sector Packs",
            description="Threat actors recurring across sector intelligence contexts.",
            dataset="sectors",
            kind="bar",
            points=[_point(row) for row in sector_actor_rows],
        ))
        sector_ttp_rows = await _rows(
            session,
            """
            SELECT ttp AS label, COUNT(*)::int AS value
            FROM sector_packs s,
                 LATERAL jsonb_array_elements_text(s.relevant_ttp_categories) AS ttp
            GROUP BY ttp
            ORDER BY value DESC, ttp ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="sector-ttp-categories",
            title="Sector TTP Category Frequency",
            description="TTP categories most often selected as relevant to sectors.",
            dataset="sectors",
            kind="table",
            points=[_point(row) for row in sector_ttp_rows],
        ))
        sector_surface_rows = await _rows(
            session,
            """
            SELECT surface AS label, COUNT(*)::int AS value
            FROM sector_packs s,
                 LATERAL jsonb_array_elements_text(s.common_attack_surfaces) AS surface
            GROUP BY surface
            ORDER BY value DESC, surface ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="sector-attack-surface-tags",
            title="Sector Attack Surface Tags",
            description="Common attack-surface tags from sector intelligence packs.",
            dataset="sectors",
            kind="bar",
            points=[_point(row) for row in sector_surface_rows],
        ))
        sector_telemetry_rows = await _rows(
            session,
            """
            SELECT telemetry AS label, COUNT(*)::int AS value
            FROM sector_packs s,
                 LATERAL jsonb_array_elements_text(s.telemetry_requirements) AS telemetry
            GROUP BY telemetry
            ORDER BY value DESC, telemetry ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="sector-telemetry-tags",
            title="Sector Telemetry Requirement Tags",
            description="Telemetry tags required by sector intelligence and detection-engineering packs.",
            dataset="sectors",
            kind="table",
            points=[_point(row) for row in sector_telemetry_rows],
        ))
        sector_vuln_rows = await _rows(
            session,
            """
            SELECT vuln_focus AS label, COUNT(*)::int AS value
            FROM sector_packs s,
                 LATERAL jsonb_array_elements_text(s.vulnerability_intelligence_focus) AS vuln_focus
            GROUP BY vuln_focus
            ORDER BY value DESC, vuln_focus ASC
            LIMIT :limit
            """,
            {"limit": limit},
        )
        widgets.append(StatWidget(
            id="sector-vulnerability-tags",
            title="Sector Vulnerability Focus Tags",
            description="Vulnerability-intelligence tags that recur across sector packs.",
            dataset="sectors",
            kind="table",
            points=[_point(row) for row in sector_vuln_rows],
        ))

    cross_rows = await _rows(
        session,
        """
        WITH actor_counts AS (
            SELECT technique_id, COUNT(DISTINCT group_id)::int AS value
            FROM apt_group_techniques
            GROUP BY technique_id
        ),
        campaign_counts AS (
            SELECT technique_id, COUNT(DISTINCT campaign_id)::int AS value
            FROM campaign_techniques
            GROUP BY technique_id
        ),
        cve_counts AS (
            SELECT attack_id, COUNT(DISTINCT cve_id)::int AS value
            FROM cve_technique_links
            GROUP BY attack_id
        ),
        ioc_counts AS (
            SELECT tid AS attack_id, COUNT(DISTINCT i.id)::int AS value
            FROM ioc_indicators i,
                 LATERAL jsonb_array_elements_text(i.technique_ids) AS tid
            GROUP BY tid
        )
        SELECT t.attack_id AS id, t.name AS label,
               (COALESCE(ac.value, 0)
                + COALESCE(cc.value, 0)
                + COALESCE(vc.value, 0)
                + COALESCE(ic.value, 0))::int AS value,
               CONCAT('actors=', COALESCE(ac.value, 0),
                      ', cves=', COALESCE(vc.value, 0),
                      ', iocs=', COALESCE(ic.value, 0),
                      ', campaigns=', COALESCE(cc.value, 0)) AS secondary
        FROM techniques t
        LEFT JOIN actor_counts ac ON ac.technique_id = t.id
        LEFT JOIN campaign_counts cc ON cc.technique_id = t.id
        LEFT JOIN cve_counts vc ON vc.attack_id = t.attack_id
        LEFT JOIN ioc_counts ic ON ic.attack_id = t.attack_id
        WHERE t.domain = :domain AND t.is_deprecated = false
          AND (COALESCE(ac.value, 0)
               + COALESCE(cc.value, 0)
               + COALESCE(vc.value, 0)
               + COALESCE(ic.value, 0)) > 0
        ORDER BY value DESC, t.attack_id ASC
        LIMIT :limit
        """,
        {"domain": domain, "limit": limit},
    )
    widgets.append(StatWidget(
        id="cross-dataset-ttp-pressure",
        title="Cross-Dataset TTP Pressure",
        description="Techniques with the broadest combined presence across actors, campaigns, CVEs, and IOCs.",
        dataset="cross",
        kind="table",
        points=[_point(row, id="id", secondary="secondary") for row in cross_rows],
    ))
    entity_tag_rows = await _rows(
        session,
        """
        SELECT label, COUNT(*)::int AS value
        FROM (
            SELECT 'TTP tactic: ' || ta.shortname AS label
            FROM techniques t
            JOIN technique_tactics tt ON tt.technique_id = t.id
            JOIN tactics ta ON ta.id = tt.tactic_id
            WHERE t.domain = :domain AND t.is_deprecated = false

            UNION ALL
            SELECT 'TTP platform: ' || platform AS label
            FROM techniques t,
                 LATERAL jsonb_array_elements_text(t.platforms) AS platform
            WHERE t.domain = :domain AND t.is_deprecated = false

            UNION ALL
            SELECT 'TTP type: ' || CASE WHEN is_subtechnique THEN 'sub-technique' ELSE 'parent-technique' END AS label
            FROM techniques
            WHERE domain = :domain AND is_deprecated = false

            UNION ALL
            SELECT 'Actor region: ' || CASE
                WHEN description ILIKE ANY (ARRAY['%iran%', '%middle east%', '%israel%', '%gulf%', '%lebanon%', '%saudi%', '%uae%']) THEN 'Middle East'
                WHEN description ILIKE ANY (ARRAY['%china%', '%korea%', '%japan%', '%taiwan%', '%vietnam%', '%india%', '%asia%']) THEN 'Asia-Pacific'
                WHEN description ILIKE ANY (ARRAY['%russia%', '%ukraine%', '%europe%', '%belarus%']) THEN 'Europe / Eurasia'
                WHEN description ILIKE ANY (ARRAY['%north america%', '%united states%', '%canada%', '%latin america%', '%mexico%', '%brazil%']) THEN 'Americas'
                WHEN description ILIKE ANY (ARRAY['%africa%', '%egypt%', '%morocco%']) THEN 'Africa'
                ELSE 'Unknown / global'
            END AS label
            FROM apt_groups
            WHERE domain = :domain

            UNION ALL
            SELECT 'Actor sector: ' || sector AS label
            FROM (
                SELECT unnest(ARRAY[
                    CASE WHEN description ILIKE ANY (ARRAY['%government%', '%ministry%', '%diplomatic%', '%embassy%']) THEN 'government' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%defense%', '%military%', '%aerospace%']) THEN 'defense' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%energy%', '%oil%', '%gas%', '%electric%']) THEN 'energy' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%telecom%', '%telecommunications%']) THEN 'telecom' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%financial%', '%bank%', '%cryptocurrency%', '%crypto%']) THEN 'finance' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%health%', '%hospital%', '%pharma%']) THEN 'healthcare' END,
                    CASE WHEN description ILIKE ANY (ARRAY['%technology%', '%software%', '%cloud%', '%it service%']) THEN 'technology' END
                ]) AS sector
                FROM apt_groups
                WHERE domain = :domain
            ) actor_sector_tags
            WHERE sector IS NOT NULL

            UNION ALL
            SELECT 'CVE severity: ' || COALESCE(NULLIF(cvss_severity, ''), 'UNKNOWN') AS label
            FROM cve_records

            UNION ALL
            SELECT 'CVE risk: ' || CASE
                WHEN known_exploited THEN 'cisa-kev'
                WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric >= 9 THEN 'critical'
                WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric >= 7 THEN 'high'
                WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric >= 4 THEN 'medium'
                WHEN cvss_score ~ '^[0-9]+(\\.[0-9]+)?$' AND cvss_score::numeric > 0 THEN 'low'
                ELSE 'unknown'
            END AS label
            FROM cve_records

            UNION ALL
            SELECT 'CVE attack vector: ' || CASE
                WHEN cvss_vector LIKE '%/AV:N/%' OR cvss_vector LIKE 'CVSS:%/AV:N/%' THEN 'network'
                WHEN cvss_vector LIKE '%/AV:A/%' OR cvss_vector LIKE 'CVSS:%/AV:A/%' THEN 'adjacent'
                WHEN cvss_vector LIKE '%/AV:L/%' OR cvss_vector LIKE 'CVSS:%/AV:L/%' THEN 'local'
                WHEN cvss_vector LIKE '%/AV:P/%' OR cvss_vector LIKE 'CVSS:%/AV:P/%' THEN 'physical'
                ELSE 'unknown'
            END AS label
            FROM cve_records

            UNION ALL
            SELECT 'IOC type: ' || indicator_type AS label
            FROM ioc_indicators

            UNION ALL
            SELECT 'IOC TLP: ' || COALESCE(NULLIF(UPPER(tlp), ''), 'UNKNOWN') AS label
            FROM ioc_indicators

            UNION ALL
            SELECT 'IOC confidence: ' || CASE
                WHEN confidence >= 85 THEN 'high'
                WHEN confidence >= 60 THEN 'medium'
                WHEN confidence > 0 THEN 'low'
                ELSE 'unknown'
            END AS label
            FROM ioc_indicators

            UNION ALL
            SELECT 'IOC malware: ' || malware_family AS label
            FROM ioc_indicators
            WHERE COALESCE(NULLIF(malware_family, ''), '') <> ''
        ) tags
        GROUP BY label
        ORDER BY value DESC, label ASC
        LIMIT :limit
        """,
        {"domain": domain, "limit": limit},
    )
    widgets.append(StatWidget(
        id="global-entity-tag-cloud",
        title="Global Entity Tag Cloud",
        description="Unified tag frequency across TTPs, actors, CVEs, and IOCs: tactic, platform, type, region, sector, risk, confidence, TLP, source, and malware-family tags.",
        dataset="cross",
        kind="table",
        points=[_point(row) for row in entity_tag_rows],
    ))

    return StatisticsOverview(
        generated_at=datetime.now(timezone.utc).isoformat(),
        domain=domain,
        included=selected,
        totals=totals,
        widgets=widgets,
    )
