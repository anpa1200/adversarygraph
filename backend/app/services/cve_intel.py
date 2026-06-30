from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.safe_http import safe_get
from app.core.version import APP_USER_AGENT
from app.models.attack import Technique
from app.models.cve import CVEActorLink, CVEIOCLink, CVERecord, CVESource, CVETechniqueLink
from app.models.ioc import IOCActorLink, IOCIndicator
from app.services.ioc_intel import _dedupe_attack_ids

NVD_SOURCE_ID = "nvd-cve-2.0"
CISA_KEV_SOURCE_ID = "cisa-kev"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass
class CVEImportItem:
    cve_id: str
    source_id: str
    description: str = ""
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str = ""
    cvss_version: str = ""
    cvss_score: str = ""
    cvss_severity: str = ""
    cvss_vector: str = ""
    cwe_ids: list[str] | None = None
    cpe_matches: list[str] | None = None
    references: list[dict[str, Any]] | None = None
    tags: list[str] | None = None
    known_exploited: bool = False
    kev_due_date: str = ""
    kev_required_action: str = ""
    raw: dict[str, Any] | None = None


async def ensure_cve_sources(session: AsyncSession) -> None:
    for source_id, label, kind, url in [
        (NVD_SOURCE_ID, "NVD CVE API 2.0", "api", NVD_API_URL),
        (CISA_KEV_SOURCE_ID, "CISA Known Exploited Vulnerabilities", "json", CISA_KEV_URL),
    ]:
        stmt = insert(CVESource).values(
            source_id=source_id,
            label=label,
            kind=kind,
            url=url,
            enabled=True,
            sync_status="configured",
        ).on_conflict_do_update(
            index_elements=["source_id"],
            set_={"label": label, "kind": kind, "url": url, "enabled": True},
        )
        await session.execute(stmt)
    await session.commit()


async def list_cve_sources(session: AsyncSession) -> list[CVESource]:
    await ensure_cve_sources(session)
    rows = await session.execute(select(CVESource).order_by(CVESource.label))
    return list(rows.scalars().all())


async def upsert_cves(session: AsyncSession, items: list[CVEImportItem]) -> dict[str, int]:
    await ensure_cve_sources(session)
    inserted = 0
    updated = 0
    for item in items:
        cve_id = item.cve_id.upper()
        existing = await session.scalar(select(CVERecord).where(CVERecord.cve_id == cve_id))
        values = {
            "cve_id": cve_id,
            "source_id": item.source_id,
            "description": item.description,
            "published": item.published,
            "last_modified": item.last_modified,
            "vuln_status": item.vuln_status,
            "cvss_version": item.cvss_version,
            "cvss_score": str(item.cvss_score or ""),
            "cvss_severity": item.cvss_severity,
            "cvss_vector": item.cvss_vector,
            "cwe_ids": sorted(set(item.cwe_ids or [])),
            "cpe_matches": sorted(set(item.cpe_matches or [])),
            "references": item.references or [],
            "tags": sorted(set(item.tags or [])),
            "known_exploited": item.known_exploited,
            "kev_due_date": item.kev_due_date,
            "kev_required_action": item.kev_required_action,
            "raw": item.raw or {},
        }
        if existing:
            for key, value in values.items():
                if key == "source_id" and existing.known_exploited and item.source_id == NVD_SOURCE_ID:
                    continue
                if key == "known_exploited":
                    value = bool(existing.known_exploited or value)
                if key in {"kev_due_date", "kev_required_action"} and not value and getattr(existing, key):
                    value = getattr(existing, key)
                if key in {"cvss_version", "cvss_score", "cvss_severity", "cvss_vector", "vuln_status"} and not value and getattr(existing, key):
                    value = getattr(existing, key)
                if key in {"cwe_ids", "cpe_matches"} and not value and getattr(existing, key):
                    value = getattr(existing, key)
                if key == "tags":
                    value = sorted(set([*(existing.tags or []), *value]))
                if key == "references":
                    value = _merge_references(existing.references or [], value)
                setattr(existing, key, value)
            updated += 1
        else:
            session.add(CVERecord(**values))
            inserted += 1
    await session.commit()
    return {"inserted": inserted, "updated": updated}


async def sync_nvd_recent(session: AsyncSession, *, days: int = 7, limit: int = 2000) -> dict[str, Any]:
    await ensure_cve_sources(session)
    days = max(1, min(days, 120))
    limit = max(1, min(limit, 2000))
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": str(limit),
        "startIndex": "0",
    }
    headers = {"User-Agent": APP_USER_AGENT}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    source = await session.get(CVESource, NVD_SOURCE_ID)
    try:
        response = safe_get(NVD_API_URL, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        payload = response.json()
        items = [_parse_nvd_vulnerability(item) for item in payload.get("vulnerabilities", []) if isinstance(item, dict)]
        result = await upsert_cves(session, [item for item in items if item is not None])
        if source:
            source.last_synced_at = datetime.now(timezone.utc)
            source.sync_status = "ok"
            source.sync_error = ""
        await session.commit()
        return {"source": NVD_SOURCE_ID, "days": days, "fetched": len(items), **result}
    except Exception as exc:
        if source:
            source.sync_status = "error"
            source.sync_error = str(exc)[:500]
            await session.commit()
        raise


async def sync_nvd_cve_ids(session: AsyncSession, cve_ids: list[str], *, limit: int = 100) -> dict[str, Any]:
    """Enrich specific CVE IDs from NVD, primarily to fill CVSS for KEV records."""
    await ensure_cve_sources(session)
    normalized = []
    seen = set()
    for cve_id in cve_ids:
        cve_id = cve_id.upper().strip()
        if CVE_ID_RE.fullmatch(cve_id) and cve_id not in seen:
            normalized.append(cve_id)
            seen.add(cve_id)
    normalized = normalized[: max(1, min(limit, 500))]
    source = await session.get(CVESource, NVD_SOURCE_ID)
    headers = {"User-Agent": APP_USER_AGENT}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    fetched = 0
    inserted = 0
    updated = 0
    errors: list[str] = []
    request_delay = 0.65 if settings.nvd_api_key else 6.2
    for index, cve_id in enumerate(normalized):
        if index:
            await asyncio.sleep(request_delay)
        try:
            response = safe_get(NVD_API_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
            response.raise_for_status()
            payload = response.json()
            items = [_parse_nvd_vulnerability(item) for item in payload.get("vulnerabilities", []) if isinstance(item, dict)]
            parsed = [item for item in items if item is not None]
            fetched += len(parsed)
            result = await upsert_cves(session, parsed)
            inserted += int(result.get("inserted", 0) or 0)
            updated += int(result.get("updated", 0) or 0)
        except Exception as exc:
            errors.append(f"{cve_id}: {exc}")

    if source:
        source.last_synced_at = datetime.now(timezone.utc)
        source.sync_status = "ok" if not errors else "degraded"
        source.sync_error = "; ".join(errors[:5])[:500]
    await session.commit()
    return {
        "source": NVD_SOURCE_ID,
        "mode": "cve-id-enrichment",
        "requested": len(normalized),
        "fetched": fetched,
        "inserted": inserted,
        "updated": updated,
        "errors": errors[:20],
    }


async def enrich_missing_cvss(session: AsyncSession, *, limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    rows = await session.execute(
        select(CVERecord.cve_id)
        .where(or_(CVERecord.cvss_score.is_(None), CVERecord.cvss_score == ""))
        .order_by(CVERecord.known_exploited.desc(), CVERecord.last_modified.desc().nulls_last())
        .limit(limit)
    )
    cve_ids = list(rows.scalars().all())
    result = await sync_nvd_cve_ids(session, cve_ids, limit=limit)
    result["missing_selected"] = len(cve_ids)
    return result


async def sync_cisa_kev(session: AsyncSession) -> dict[str, Any]:
    await ensure_cve_sources(session)
    source = await session.get(CVESource, CISA_KEV_SOURCE_ID)
    try:
        response = safe_get(CISA_KEV_URL, headers={"User-Agent": APP_USER_AGENT}, timeout=60)
        response.raise_for_status()
        payload = response.json()
        vulns = payload.get("vulnerabilities", [])
        items = [_parse_kev_vulnerability(item, payload) for item in vulns if isinstance(item, dict)]
        result = await upsert_cves(session, [item for item in items if item is not None])
        if source:
            source.last_synced_at = datetime.now(timezone.utc)
            source.sync_status = "ok"
            source.sync_error = ""
        await session.commit()
        return {"source": CISA_KEV_SOURCE_ID, "fetched": len(items), **result}
    except Exception as exc:
        if source:
            source.sync_status = "error"
            source.sync_error = str(exc)[:500]
            await session.commit()
        raise


async def sync_all_cve_sources(session: AsyncSession, *, days: int = 7) -> dict[str, Any]:
    results: dict[str, Any] = {"totals": {"inserted": 0, "updated": 0}, "sources": []}
    for syncer in (lambda: sync_nvd_recent(session, days=days), lambda: sync_cisa_kev(session)):
        try:
            item = await syncer()
        except Exception as exc:
            item = {"status": "error", "error": str(exc)}
        results["sources"].append(item)
        results["totals"]["inserted"] += int(item.get("inserted", 0) or 0)
        results["totals"]["updated"] += int(item.get("updated", 0) or 0)
    correlation = await correlate_cves(session)
    results["correlations"] = correlation
    return results


async def list_cve_library(
    session: AsyncSession,
    *,
    search: str = "",
    severity: str = "",
    known_exploited: bool | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    await ensure_cve_sources(session)
    limit = max(1, min(limit, 5000))
    offset = max(0, offset)
    stmt = select(CVERecord)
    count_stmt = select(func.count(CVERecord.id))
    filters = []
    if search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                CVERecord.cve_id.ilike(pattern),
                CVERecord.description.ilike(pattern),
                CVERecord.cvss_severity.ilike(pattern),
            )
        )
    if severity:
        filters.append(CVERecord.cvss_severity.ilike(severity))
    if known_exploited is not None:
        filters.append(CVERecord.known_exploited.is_(known_exploited))
    if filters:
        stmt = stmt.where(*filters)
        count_stmt = count_stmt.where(*filters)
    total = int((await session.execute(count_stmt)).scalar_one_or_none() or 0)
    rows = await session.execute(stmt.order_by(CVERecord.known_exploited.desc(), CVERecord.last_modified.desc().nulls_last()).offset(offset).limit(limit))
    return {"total": total, "limit": limit, "offset": offset, "items": [_cve_row(cve) for cve in rows.scalars().all()]}


async def get_cve_detail(session: AsyncSession, cve_id: str) -> dict[str, Any] | None:
    row = await session.execute(
        select(CVERecord)
        .options(
            selectinload(CVERecord.technique_links),
            selectinload(CVERecord.ioc_links),
            selectinload(CVERecord.actor_links),
        )
        .where(CVERecord.cve_id == cve_id.upper())
    )
    cve = row.scalar_one_or_none()
    if cve is None:
        return None

    techniques = []
    for link in cve.technique_links:
        technique = await session.scalar(select(Technique).where(Technique.attack_id == link.attack_id))
        techniques.append({
            "attack_id": link.attack_id,
            "name": technique.name if technique else "",
            "relationship": link.relationship_type,
            "confidence": link.confidence,
            "evidence": link.evidence,
            "source": link.source_id,
        })
    iocs = []
    for link in cve.ioc_links:
        indicator = await session.get(IOCIndicator, link.indicator_id)
        iocs.append({
            "indicator_id": link.indicator_id,
            "value": indicator.value if indicator else "",
            "type": indicator.indicator_type if indicator else "",
            "relationship": link.relationship_type,
            "confidence": link.confidence,
            "evidence": link.evidence,
            "source": link.source_id,
        })
    actors = [
        {
            "actor_attack_id": link.actor_attack_id,
            "actor_name": link.actor_name,
            "relationship": link.relationship_type,
            "confidence": link.confidence,
            "evidence": link.evidence,
            "source": link.source_id,
        }
        for link in cve.actor_links
    ]
    return {**_cve_row(cve), "techniques": techniques, "iocs": iocs, "actors": actors, "raw": cve.raw or {}}


async def correlate_cves(session: AsyncSession) -> dict[str, int]:
    """Create strict links where local source fields explicitly mention CVE/TTP/actor evidence."""
    await ensure_cve_sources(session)
    cves = (await session.execute(select(CVERecord))).scalars().all()
    existing_cve_ids = {cve.cve_id for cve in cves}
    technique_links = 0
    ioc_links = 0
    actor_links = 0

    for cve in cves:
        text = " ".join([
            cve.description or "",
            cve.kev_required_action or "",
            " ".join(str(ref.get("url", "")) + " " + str(ref.get("source", "")) for ref in (cve.references or [])),
        ])
        for attack_id in _dedupe_attack_ids(ATTACK_ID_RE.findall(text)):
            technique_links += await _upsert_cve_technique_link(
                session,
                cve.cve_id,
                attack_id,
                cve.source_id,
                "explicit ATT&CK technique ID appears in CVE source text/reference",
                confidence=85,
            )

    indicators = (await session.execute(select(IOCIndicator).options(selectinload(IOCIndicator.actor_links)))).scalars().all()
    for indicator in indicators:
        text = " ".join([
            indicator.value or "",
            indicator.description or "",
            indicator.source_url or "",
            indicator.malware_family or "",
            indicator.campaign or "",
            " ".join(indicator.tags or []),
            str(indicator.raw or {}),
        ])
        for cve_id in sorted({match.upper() for match in CVE_ID_RE.findall(text)} & existing_cve_ids):
            ioc_links += await _upsert_cve_ioc_link(
                session,
                cve_id,
                indicator.id,
                indicator.source_id,
                "CVE ID appears in IOC source fields/raw enrichment",
                confidence=80,
            )
            for actor_link in indicator.actor_links:
                actor_links += await _upsert_cve_actor_link(
                    session,
                    cve_id,
                    actor_link.actor_attack_id,
                    actor_link.actor_name,
                    actor_link.source_id,
                    f"Derived from CVE-tagged IOC {indicator.value!r} with actor evidence: {actor_link.evidence}",
                    confidence=min(actor_link.confidence, 75),
                )

    await session.commit()
    return {"technique_links": technique_links, "ioc_links": ioc_links, "actor_links": actor_links}


def _parse_nvd_vulnerability(item: dict[str, Any]) -> CVEImportItem | None:
    cve = item.get("cve") or {}
    cve_id = str(cve.get("id") or "").upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        return None
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    metrics = cve.get("metrics") or {}
    metric = _best_metric(metrics)
    weaknesses = cve.get("weaknesses") or []
    cwe_ids = []
    for weakness in weaknesses:
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "")
            if value.startswith("CWE-"):
                cwe_ids.append(value)
    refs = []
    raw_refs = cve.get("references", [])
    if isinstance(raw_refs, dict):
        raw_refs = raw_refs.get("referenceData", [])
    for ref in raw_refs or []:
        if not isinstance(ref, dict):
            continue
        refs.append({"url": ref.get("url", ""), "source": ref.get("source", ""), "tags": ref.get("tags", [])})
    cpes = _extract_cpes(cve.get("configurations") or [])
    return CVEImportItem(
        cve_id=cve_id,
        source_id=NVD_SOURCE_ID,
        description=description,
        published=cve.get("published"),
        last_modified=cve.get("lastModified"),
        vuln_status=cve.get("vulnStatus", ""),
        cvss_version=metric.get("version", ""),
        cvss_score=str(metric.get("baseScore", "")),
        cvss_severity=metric.get("baseSeverity", ""),
        cvss_vector=metric.get("vectorString", ""),
        cwe_ids=cwe_ids,
        cpe_matches=cpes,
        references=refs,
        tags=["nvd"],
        raw=item,
    )


def _parse_kev_vulnerability(item: dict[str, Any], payload: dict[str, Any]) -> CVEImportItem | None:
    cve_id = str(item.get("cveID") or "").upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        return None
    description = " ".join(
        part
        for part in [
            item.get("vendorProject", ""),
            item.get("product", ""),
            item.get("vulnerabilityName", ""),
            item.get("shortDescription", ""),
            item.get("requiredAction", ""),
        ]
        if part
    )
    return CVEImportItem(
        cve_id=cve_id,
        source_id=CISA_KEV_SOURCE_ID,
        description=description,
        published=item.get("dateAdded"),
        last_modified=payload.get("dateReleased") or item.get("dateAdded"),
        known_exploited=True,
        kev_due_date=item.get("dueDate", ""),
        kev_required_action=item.get("requiredAction", ""),
        references=[{"url": item.get("notes", ""), "source": "CISA KEV", "tags": ["known-exploited"]}] if item.get("notes") else [],
        tags=["cisa-kev", "known-exploited"],
        raw=item,
    )


def _best_metric(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            metric = values[0].get("cvssData") or {}
            return {
                "version": str(metric.get("version") or key.replace("cvssMetric", "")),
                "baseScore": metric.get("baseScore", ""),
                "baseSeverity": values[0].get("baseSeverity") or metric.get("baseSeverity", ""),
                "vectorString": metric.get("vectorString", ""),
            }
    return {}


def _extract_cpes(configurations: list[dict[str, Any]]) -> list[str]:
    cpes: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria")
                if criteria:
                    cpes.append(criteria)
    return cpes[:500]


def _merge_references(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen = set()
    for ref in [*existing, *incoming]:
        if not isinstance(ref, dict):
            continue
        key = (str(ref.get("url", "")), str(ref.get("source", "")))
        if key in seen:
            continue
        seen.add(key)
        merged.append(ref)
    return merged[:200]


async def _upsert_cve_technique_link(session: AsyncSession, cve_id: str, attack_id: str, source_id: str, evidence: str, confidence: int) -> int:
    stmt = insert(CVETechniqueLink).values(
        cve_id=cve_id,
        attack_id=attack_id.upper(),
        source_id=source_id,
        evidence=evidence[:2000],
        confidence=confidence,
    ).on_conflict_do_nothing(index_elements=["cve_id", "attack_id", "source_id"])
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


async def _upsert_cve_ioc_link(session: AsyncSession, cve_id: str, indicator_id: int, source_id: str, evidence: str, confidence: int) -> int:
    stmt = insert(CVEIOCLink).values(
        cve_id=cve_id,
        indicator_id=indicator_id,
        source_id=source_id,
        evidence=evidence[:2000],
        confidence=confidence,
    ).on_conflict_do_nothing(index_elements=["cve_id", "indicator_id", "source_id"])
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


async def _upsert_cve_actor_link(session: AsyncSession, cve_id: str, actor_attack_id: str, actor_name: str, source_id: str, evidence: str, confidence: int) -> int:
    stmt = insert(CVEActorLink).values(
        cve_id=cve_id,
        actor_attack_id=actor_attack_id,
        actor_name=actor_name,
        source_id=source_id,
        evidence=evidence[:2000],
        confidence=confidence,
    ).on_conflict_do_nothing(index_elements=["cve_id", "actor_attack_id", "source_id"])
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


def _cve_row(cve: CVERecord) -> dict[str, Any]:
    return {
        "id": cve.id,
        "cve_id": cve.cve_id,
        "source": cve.source_id,
        "description": cve.description,
        "published": cve.published,
        "last_modified": cve.last_modified,
        "vuln_status": cve.vuln_status,
        "cvss": {
            "version": cve.cvss_version,
            "score": cve.cvss_score,
            "severity": cve.cvss_severity,
            "vector": cve.cvss_vector,
        },
        "cwe_ids": cve.cwe_ids or [],
        "cpe_matches": cve.cpe_matches or [],
        "references": cve.references or [],
        "tags": cve.tags or [],
        "known_exploited": cve.known_exploited,
        "kev_due_date": cve.kev_due_date,
        "kev_required_action": cve.kev_required_action,
    }
