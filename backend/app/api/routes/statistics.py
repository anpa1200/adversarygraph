from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

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
        return 0


async def _rows(session: AsyncSession, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    try:
        result = await session.execute(text(sql), params or {})
        return [dict(row) for row in result.mappings().all()]
    except Exception:
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
                   ROUND(AVG(NULLIF(item->>'confidence', '')::numeric), 1)::text AS secondary
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

    cross_rows = await _rows(
        session,
        """
        SELECT t.attack_id AS id, t.name AS label,
               (COUNT(DISTINCT gt.group_id)
                + COUNT(DISTINCT ctl.cve_id)
                + COUNT(DISTINCT i.id)
                + COUNT(DISTINCT ct.campaign_id))::int AS value,
               CONCAT('actors=', COUNT(DISTINCT gt.group_id),
                      ', cves=', COUNT(DISTINCT ctl.cve_id),
                      ', iocs=', COUNT(DISTINCT i.id),
                      ', campaigns=', COUNT(DISTINCT ct.campaign_id)) AS secondary
        FROM techniques t
        LEFT JOIN apt_group_techniques gt ON gt.technique_id = t.id
        LEFT JOIN campaign_techniques ct ON ct.technique_id = t.id
        LEFT JOIN cve_technique_links ctl ON ctl.attack_id = t.attack_id
        LEFT JOIN ioc_indicators i ON i.technique_ids ? t.attack_id
        WHERE t.domain = :domain AND t.is_deprecated = false
        GROUP BY t.id, t.attack_id, t.name
        HAVING (COUNT(DISTINCT gt.group_id)
                + COUNT(DISTINCT ctl.cve_id)
                + COUNT(DISTINCT i.id)
                + COUNT(DISTINCT ct.campaign_id)) > 0
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

    return StatisticsOverview(
        generated_at=datetime.now(timezone.utc).isoformat(),
        domain=domain,
        included=selected,
        totals=totals,
        widgets=widgets,
    )
