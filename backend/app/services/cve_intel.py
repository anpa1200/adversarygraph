from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.safe_http import safe_get, safe_post
from app.core.version import APP_USER_AGENT
from app.models.attack import Technique
from app.models.cve import CVEActorLink, CVEIOCLink, CVERecord, CVESource, CVETechniqueLink
from app.models.ioc import IOCActorLink, IOCIndicator
from app.services.ioc_intel import _dedupe_attack_ids
from app.services.taxonomy import canonical_tags

logger = logging.getLogger(__name__)

NVD_SOURCE_ID = "nvd-cve-2.0"
CISA_KEV_SOURCE_ID = "cisa-kev"
GHSA_SOURCE_ID = "github-advisory-database"
EPSS_SOURCE_ID = "first-epss"
OSV_SOURCE_ID = "osv-dev"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_API_URL = "https://api.github.com/advisories"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
PRODUCT_SECURITY_SOURCE_CATALOG: tuple[tuple[str, str, str, str], ...] = (
    (NVD_SOURCE_ID, "NVD CVE API 2.0", "api", NVD_API_URL),
    (CISA_KEV_SOURCE_ID, "CISA Known Exploited Vulnerabilities", "json", CISA_KEV_URL),
    (GHSA_SOURCE_ID, "GitHub Advisory Database", "api", GHSA_API_URL),
    (EPSS_SOURCE_ID, "FIRST EPSS", "api", EPSS_API_URL),
    (OSV_SOURCE_ID, "OSV.dev Vulnerability Database", "api", OSV_QUERY_BATCH_URL),
    ("deps-dev", "deps.dev Package Dependency API", "api", "https://api.deps.dev/v3"),
    ("gitlab-advisory-database", "GitLab Advisory Database", "git", "https://gitlab.com/gitlab-org/advisories-community"),
    ("pypa-advisory-database", "PyPA Advisory Database", "git", "https://github.com/pypa/advisory-database"),
    ("go-vuln-db", "Go Vulnerability Database", "json", "https://vuln.go.dev"),
    ("rustsec-advisory-db", "RustSec Advisory Database", "git", "https://github.com/RustSec/advisory-db"),
    ("msrc-security-updates", "Microsoft Security Update Guide", "api", "https://api.msrc.microsoft.com/cvrf/v3.0"),
    ("redhat-security-data", "Red Hat Security Data API", "api", "https://access.redhat.com/hydra/rest/securitydata"),
    ("ubuntu-security-notices", "Ubuntu Security Notices", "api", "https://ubuntu.com/security/notices.json"),
    ("debian-security-tracker", "Debian Security Tracker", "json", "https://security-tracker.debian.org/tracker/data/json"),
    ("alpine-secdb", "Alpine SecDB", "json", "https://secdb.alpinelinux.org"),
    ("cisa-ics-advisories", "CISA ICS Advisories", "rss", "https://www.cisa.gov/news-events/cybersecurity-advisories"),
    ("certcc-vulnerability-notes", "CERT/CC Vulnerability Notes", "html", "https://kb.cert.org/vuls"),
    ("exploit-db", "Exploit-DB Public Exploit Catalog", "csv", "https://gitlab.com/exploit-database/exploitdb"),
    ("metasploit-modules", "Metasploit Framework Modules", "git", "https://github.com/rapid7/metasploit-framework"),
    ("vulncheck", "VulnCheck Vulnerability and Exploit Intelligence", "api", "https://vulncheck.com"),
    ("snyk", "Snyk Vulnerability Database", "api", "https://api.snyk.io"),
    ("socket-dev", "Socket Package Supply-Chain Intelligence", "api", "https://api.socket.dev"),
    ("endoflife-date", "endoflife.date Product Lifecycle Data", "api", "https://endoflife.date/api"),
    ("hibp-domain-breaches", "Have I Been Pwned Domain Breach Monitoring", "api", "https://haveibeenpwned.com/API/v3"),
    ("leakix", "LeakIX Internet Exposure Intelligence", "api", "https://leakix.net"),
    ("spycloud", "SpyCloud Breach and Credential Exposure", "api", "https://spycloud.com"),
    ("flare", "Flare External Exposure and Dark Web Monitoring", "api", "https://flare.io"),
    ("darkowl", "DarkOwl Darknet Intelligence", "api", "https://darkowl.com"),
    ("intel471", "Intel 471 Cybercrime Intelligence", "api", "https://intel471.com"),
    ("kela", "KELA Cybercrime Intelligence", "api", "https://ke-la.com"),
    ("recorded-future", "Recorded Future Vulnerability and Threat Intelligence", "api", "https://api.recordedfuture.com"),
)

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
    for source_id, label, kind, url in PRODUCT_SECURITY_SOURCE_CATALOG:
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


async def upsert_cves(session: AsyncSession, items: list[CVEImportItem]) -> dict[str, Any]:
    await ensure_cve_sources(session)
    inserted = 0
    updated = 0
    for item in items:
        cve_id = item.cve_id.upper()
        existing = await session.scalar(select(CVERecord).where(CVERecord.cve_id == cve_id))
        values: dict[str, Any] = {
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
            "tags": canonical_tags("tag", item.tags or []),
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
                    value = canonical_tags("tag", [*(existing.tags or []), *value])
                if key == "references":
                    value = _merge_references(existing.references or [], value)
                setattr(existing, key, value)
            updated += 1
        else:
            session.add(CVERecord(**values))
            inserted += 1
    await session.commit()
    result: dict[str, Any] = {"inserted": inserted, "updated": updated}
    if inserted or updated:
        try:
            from app.services.asset_intel import retrohunt_assets

            result["asset_retrohunt"] = await retrohunt_assets(session)
            await session.commit()
        except Exception:
            logger.exception("Asset retrohunt failed after CVE upsert")
            result["asset_retrohunt_error"] = "Asset retrohunt failed. See server logs."
    return result


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
    except Exception:
        logger.exception("NVD recent CVE sync failed")
        if source:
            source.sync_status = "error"
            source.sync_error = "NVD sync failed. See server logs."
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
        except Exception:
            logger.exception("NVD CVE enrichment failed cve_id=%s", cve_id)
            errors.append(f"{cve_id}: enrichment failed. See server logs.")

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
    except Exception:
        logger.exception("CISA KEV sync failed")
        if source:
            source.sync_status = "error"
            source.sync_error = "CISA KEV sync failed. See server logs."
            await session.commit()
        raise


async def sync_github_advisories(session: AsyncSession, *, ecosystem: str = "", severity: str = "", limit: int = 100) -> dict[str, Any]:
    """Import recent reviewed GitHub Security Advisories that carry CVE aliases."""
    await ensure_cve_sources(session)
    limit = max(1, min(limit, 100))
    params: dict[str, str] = {
        "type": "reviewed",
        "per_page": str(limit),
        "sort": "updated",
        "direction": "desc",
    }
    if ecosystem:
        params["ecosystem"] = ecosystem
    if severity:
        params["severity"] = severity.lower()
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": APP_USER_AGENT,
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
    source = await session.get(CVESource, GHSA_SOURCE_ID)
    try:
        response = safe_get(GHSA_API_URL, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        payload = response.json()
        advisories = payload if isinstance(payload, list) else []
        parsed = [item for item in (_parse_ghsa_advisory(item) for item in advisories) if item is not None]
        result = await upsert_cves(session, parsed)
        if source:
            source.last_synced_at = datetime.now(timezone.utc)
            source.sync_status = "ok"
            source.sync_error = ""
        await session.commit()
        return {
            "source": GHSA_SOURCE_ID,
            "mode": "github-advisories",
            "ecosystem": ecosystem or "all",
            "severity": severity or "all",
            "fetched": len(advisories),
            "imported_cves": len(parsed),
            **result,
        }
    except Exception:
        logger.exception("GitHub advisory sync failed")
        if source:
            source.sync_status = "error"
            source.sync_error = "GitHub advisory sync failed. See server logs."
            await session.commit()
        raise


async def sync_epss_scores(session: AsyncSession, *, limit: int = 500) -> dict[str, Any]:
    """Enrich existing CVEs with FIRST EPSS probability and percentile metadata."""
    await ensure_cve_sources(session)
    limit = max(1, min(limit, 2000))
    rows = await session.execute(
        select(CVERecord.cve_id)
        .order_by(CVERecord.known_exploited.desc(), CVERecord.cvss_severity.desc().nulls_last(), CVERecord.last_modified.desc().nulls_last())
        .limit(limit)
    )
    cve_ids = [str(row).upper() for row in rows.scalars().all() if CVE_ID_RE.fullmatch(str(row).upper())]
    source = await session.get(CVESource, EPSS_SOURCE_ID)
    if not cve_ids:
        return {"source": EPSS_SOURCE_ID, "mode": "epss", "requested": 0, "fetched": 0, "updated": 0}

    headers = {"User-Agent": APP_USER_AGENT}
    updated = 0
    fetched = 0
    errors: list[str] = []
    for chunk in _chunks(cve_ids, 100):
        try:
            response = safe_get(EPSS_API_URL, params={"cve": ",".join(chunk)}, headers=headers, timeout=60)
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", []) if isinstance(payload, dict) else []
            fetched += len(data)
            for item in data:
                if not isinstance(item, dict):
                    continue
                cve_id = str(item.get("cve") or "").upper()
                cve = await session.scalar(select(CVERecord).where(CVERecord.cve_id == cve_id))
                if not cve:
                    continue
                epss = _float_or_none(item.get("epss"))
                percentile = _float_or_none(item.get("percentile"))
                raw = dict(cve.raw or {})
                raw["epss"] = {
                    "epss": epss,
                    "percentile": percentile,
                    "date": item.get("date", ""),
                    "source": EPSS_SOURCE_ID,
                }
                tags = [*(cve.tags or []), "epss"]
                if epss is not None and epss >= 0.5:
                    tags.append("epss-high-probability")
                if percentile is not None and percentile >= 0.95:
                    tags.append("epss-top-percentile")
                if (epss is not None and epss >= 0.1) or (percentile is not None and percentile >= 0.9):
                    tags.append("product-security-priority")
                cve.raw = raw
                cve.tags = canonical_tags("tag", tags)
                updated += 1
        except Exception:
            logger.exception("EPSS batch sync failed")
            errors.append("EPSS batch sync failed. See server logs.")

    if source:
        source.last_synced_at = datetime.now(timezone.utc)
        source.sync_status = "ok" if not errors else "degraded"
        source.sync_error = "; ".join(errors[:5])[:500]
    await session.commit()
    return {"source": EPSS_SOURCE_ID, "mode": "epss", "requested": len(cve_ids), "fetched": fetched, "updated": updated, "errors": errors[:20]}


async def sync_osv_packages(session: AsyncSession, packages: list[dict[str, Any]]) -> dict[str, Any]:
    """Query OSV for package/SBOM records and import CVE aliases into the CVE Library."""
    await ensure_cve_sources(session)
    queries = []
    normalized_packages: list[dict[str, str]] = []
    for package in packages[:200]:
        name = str(package.get("package_name") or package.get("name") or "").strip()
        ecosystem = _normalize_osv_ecosystem(str(package.get("ecosystem") or package.get("package_type") or "").strip())
        version = str(package.get("version") or package.get("package_version") or "").strip()
        if not name or not ecosystem:
            continue
        query: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            query["version"] = version
        queries.append(query)
        normalized_packages.append({"name": name, "ecosystem": ecosystem, "version": version})
    source = await session.get(CVESource, OSV_SOURCE_ID)
    if not queries:
        return {"source": OSV_SOURCE_ID, "mode": "osv-querybatch", "requested": 0, "fetched": 0, "inserted": 0, "updated": 0, "package_results": []}

    try:
        response = safe_post(OSV_QUERY_BATCH_URL, json={"queries": queries}, headers={"User-Agent": APP_USER_AGENT}, timeout=90)
        response.raise_for_status()
        payload = response.json()
        results = payload.get("results", []) if isinstance(payload, dict) else []
        items: list[CVEImportItem] = []
        package_results: list[dict[str, Any]] = []
        for package, result in zip(normalized_packages, results, strict=False):
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            package_results.append({**package, "vulnerability_count": len(vulns), "ids": [str(v.get("id", "")) for v in vulns[:20] if isinstance(v, dict)]})
            for vuln in vulns:
                if isinstance(vuln, dict):
                    parsed = _parse_osv_vuln(vuln, package)
                    if not parsed and vuln.get("id"):
                        try:
                            detail = _fetch_osv_vuln_detail(str(vuln["id"]))
                        except Exception:
                            logger.exception("OSV detail fetch failed advisory_id=%s", vuln.get("id"))
                            detail = None
                        if detail:
                            parsed = _parse_osv_vuln(detail, package)
                    items.extend(parsed)
        upsert = await upsert_cves(session, items)
        imported_cve_ids = sorted({item.cve_id for item in items})
        nvd_enrichment: dict[str, Any] | None = None
        if imported_cve_ids:
            try:
                nvd_enrichment = await sync_nvd_cve_ids(session, imported_cve_ids, limit=min(len(imported_cve_ids), 50))
            except Exception:
                logger.exception("NVD enrichment failed after OSV package sync")
                nvd_enrichment = {
                    "status": "error",
                    "error": "NVD enrichment failed. See server logs.",
                }
        if source:
            source.last_synced_at = datetime.now(timezone.utc)
            source.sync_status = "ok"
            source.sync_error = ""
        await session.commit()
        return {
            "source": OSV_SOURCE_ID,
            "mode": "osv-querybatch",
            "requested": len(queries),
            "fetched": sum(item["vulnerability_count"] for item in package_results),
            "imported_cves": len(items),
            "package_results": package_results,
            "nvd_enrichment": nvd_enrichment,
            **upsert,
        }
    except Exception:
        logger.exception("OSV package sync failed")
        if source:
            source.sync_status = "error"
            source.sync_error = "OSV package sync failed. See server logs."
            await session.commit()
        raise


async def sync_all_cve_sources(session: AsyncSession, *, days: int = 7) -> dict[str, Any]:
    results: dict[str, Any] = {"totals": {"inserted": 0, "updated": 0}, "sources": []}
    for syncer in (
        lambda: sync_nvd_recent(session, days=days),
        lambda: sync_cisa_kev(session),
        lambda: sync_github_advisories(session, limit=100),
        lambda: sync_epss_scores(session, limit=500),
    ):
        try:
            item = await syncer()
        except Exception:
            logger.exception("CVE source sync failed")
            item = {"status": "error", "error": "CVE source sync failed. See server logs."}
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
    for ioc_link in cve.ioc_links:
        indicator = await session.get(IOCIndicator, ioc_link.indicator_id)
        iocs.append({
            "indicator_id": ioc_link.indicator_id,
            "value": indicator.value if indicator else "",
            "type": indicator.indicator_type if indicator else "",
            "relationship": ioc_link.relationship_type,
            "confidence": ioc_link.confidence,
            "evidence": ioc_link.evidence,
            "source": ioc_link.source_id,
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


async def cves_for_technique(session: AsyncSession, attack_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    """Return direct and IOC-derived CVE links for a technique."""
    attack_id = attack_id.upper().strip()
    limit = max(1, min(limit, 500))
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    direct_rows = await session.execute(
        select(CVETechniqueLink, CVERecord)
        .join(CVERecord, CVERecord.cve_id == CVETechniqueLink.cve_id)
        .where(CVETechniqueLink.attack_id == attack_id)
        .order_by(CVERecord.known_exploited.desc(), CVERecord.cvss_score.desc().nulls_last(), CVERecord.cve_id)
        .limit(limit)
    )
    for link, cve in direct_rows.all():
        key = (cve.cve_id, "direct", link.source_id)
        seen.add(key)
        output.append(_correlation_row(
            cve,
            relationship=link.relationship_type,
            confidence=link.confidence,
            evidence=link.evidence,
            source=link.source_id,
            path=[{"type": "cve", "id": cve.cve_id}, {"type": "technique", "id": attack_id}],
        ))

    remaining = max(0, limit - len(output))
    if remaining:
        ioc_rows = await session.execute(
            select(CVEIOCLink, CVERecord, IOCIndicator)
            .join(CVERecord, CVERecord.cve_id == CVEIOCLink.cve_id)
            .join(IOCIndicator, IOCIndicator.id == CVEIOCLink.indicator_id)
            .where(IOCIndicator.technique_ids.contains([attack_id]))
            .order_by(CVERecord.known_exploited.desc(), CVERecord.cvss_score.desc().nulls_last(), CVERecord.cve_id)
            .limit(remaining * 2)
        )
        for link, cve, indicator in ioc_rows.all():
            key = (cve.cve_id, "via-ioc-technique", str(indicator.id))
            if key in seen:
                continue
            seen.add(key)
            output.append(_correlation_row(
                cve,
                relationship="observed-with-ioc-mapped-to-technique",
                confidence=min(link.confidence, int(indicator.confidence or 0), 70),
                evidence=f"{link.evidence}; IOC {indicator.value!r} is mapped to {attack_id}.",
                source=link.source_id,
                path=[
                    {"type": "cve", "id": cve.cve_id},
                    {"type": "ioc", "id": indicator.id, "value": indicator.value},
                    {"type": "technique", "id": attack_id},
                ],
            ))
            if len(output) >= limit:
                break
    return output


async def cves_for_actor(session: AsyncSession, actor_attack_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    """Return direct and IOC-derived CVE links for an ATT&CK actor/group."""
    actor_attack_id = actor_attack_id.upper().strip()
    limit = max(1, min(limit, 500))
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    direct_rows = await session.execute(
        select(CVEActorLink, CVERecord)
        .join(CVERecord, CVERecord.cve_id == CVEActorLink.cve_id)
        .where(CVEActorLink.actor_attack_id == actor_attack_id)
        .order_by(CVERecord.known_exploited.desc(), CVERecord.cvss_score.desc().nulls_last(), CVERecord.cve_id)
        .limit(limit)
    )
    for link, cve in direct_rows.all():
        key = (cve.cve_id, "direct", link.source_id)
        seen.add(key)
        output.append(_correlation_row(
            cve,
            relationship=link.relationship_type,
            confidence=link.confidence,
            evidence=link.evidence,
            source=link.source_id,
            path=[{"type": "cve", "id": cve.cve_id}, {"type": "actor", "id": actor_attack_id, "name": link.actor_name}],
        ))

    remaining = max(0, limit - len(output))
    if remaining:
        ioc_rows = await session.execute(
            select(CVEIOCLink, CVERecord, IOCIndicator, IOCActorLink)
            .join(CVERecord, CVERecord.cve_id == CVEIOCLink.cve_id)
            .join(IOCIndicator, IOCIndicator.id == CVEIOCLink.indicator_id)
            .join(IOCActorLink, IOCActorLink.indicator_id == IOCIndicator.id)
            .where(IOCActorLink.actor_attack_id == actor_attack_id)
            .order_by(CVERecord.known_exploited.desc(), CVERecord.cvss_score.desc().nulls_last(), CVERecord.cve_id)
            .limit(remaining * 2)
        )
        for cve_link, cve, indicator, actor_link in ioc_rows.all():
            key = (cve.cve_id, "via-ioc-actor", str(indicator.id))
            if key in seen:
                continue
            seen.add(key)
            output.append(_correlation_row(
                cve,
                relationship="observed-with-actor-linked-ioc",
                confidence=min(cve_link.confidence, actor_link.confidence, 75),
                evidence=f"{cve_link.evidence}; IOC actor evidence: {actor_link.evidence}",
                source=cve_link.source_id,
                path=[
                    {"type": "cve", "id": cve.cve_id},
                    {"type": "ioc", "id": indicator.id, "value": indicator.value},
                    {"type": "actor", "id": actor_attack_id, "name": actor_link.actor_name},
                ],
            ))
            if len(output) >= limit:
                break
    return output


async def cves_for_ioc(session: AsyncSession, indicator_id: int, *, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 500))
    rows = await session.execute(
        select(CVEIOCLink, CVERecord, IOCIndicator)
        .join(CVERecord, CVERecord.cve_id == CVEIOCLink.cve_id)
        .join(IOCIndicator, IOCIndicator.id == CVEIOCLink.indicator_id)
        .where(CVEIOCLink.indicator_id == indicator_id)
        .order_by(CVERecord.known_exploited.desc(), CVERecord.cvss_score.desc().nulls_last(), CVERecord.cve_id)
        .limit(limit)
    )
    return [
        _correlation_row(
            cve,
            relationship=link.relationship_type,
            confidence=link.confidence,
            evidence=link.evidence,
            source=link.source_id,
            path=[{"type": "cve", "id": cve.cve_id}, {"type": "ioc", "id": indicator.id, "value": indicator.value}],
        )
        for link, cve, indicator in rows.all()
    ]


async def cve_correlation_graph(session: AsyncSession, cve_id: str) -> dict[str, Any] | None:
    """Return a compact graph for one CVE with direct TTP/IOC/APT evidence edges."""
    detail = await get_cve_detail(session, cve_id)
    if detail is None:
        return None
    nodes: list[dict[str, Any]] = [{"id": detail["cve_id"], "type": "cve", "label": detail["cve_id"], "severity": detail["cvss"]["severity"], "score": detail["cvss"]["score"]}]
    edges: list[dict[str, Any]] = []
    for link in detail["techniques"]:
        nodes.append({"id": link["attack_id"], "type": "technique", "label": f"{link['attack_id']} {link['name']}".strip()})
        edges.append({"source": detail["cve_id"], "target": link["attack_id"], "relationship": link["relationship"], "confidence": link["confidence"], "evidence": link["evidence"], "source_id": link["source"]})
    for link in detail["iocs"]:
        node_id = f"ioc:{link['indicator_id']}"
        nodes.append({"id": node_id, "type": "ioc", "label": link["value"], "ioc_type": link["type"]})
        edges.append({"source": detail["cve_id"], "target": node_id, "relationship": link["relationship"], "confidence": link["confidence"], "evidence": link["evidence"], "source_id": link["source"]})
    for link in detail["actors"]:
        nodes.append({"id": link["actor_attack_id"], "type": "actor", "label": f"{link['actor_attack_id']} {link['actor_name']}".strip()})
        edges.append({"source": detail["cve_id"], "target": link["actor_attack_id"], "relationship": link["relationship"], "confidence": link["confidence"], "evidence": link["evidence"], "source_id": link["source"]})
    deduped_nodes = {node["id"]: node for node in nodes}
    return {"cve_id": detail["cve_id"], "nodes": list(deduped_nodes.values()), "edges": edges}


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
                str(cve.source_id or "unknown"),
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


def _parse_ghsa_advisory(item: dict[str, Any]) -> CVEImportItem | None:
    cve_id = str(item.get("cve_id") or "").upper()
    if not CVE_ID_RE.fullmatch(cve_id):
        for identifier in item.get("identifiers") or []:
            value = str(identifier.get("value") or "").upper() if isinstance(identifier, dict) else ""
            if CVE_ID_RE.fullmatch(value):
                cve_id = value
                break
    if not CVE_ID_RE.fullmatch(cve_id):
        return None
    vulnerabilities = item.get("vulnerabilities") or []
    ecosystems = sorted({str(v.get("package", {}).get("ecosystem") or "") for v in vulnerabilities if isinstance(v, dict) and v.get("package")})
    packages = sorted({str(v.get("package", {}).get("name") or "") for v in vulnerabilities if isinstance(v, dict) and v.get("package")})
    cwes = [str(cwe.get("cwe_id") or "") for cwe in (item.get("cwes") or []) if isinstance(cwe, dict) and cwe.get("cwe_id")]
    cvss = item.get("cvss") or {}
    refs = [{"url": url, "source": "GitHub Advisory Database", "tags": ["advisory"]} for url in item.get("references", []) or [] if url]
    severity = str(item.get("severity") or "").upper()
    tags = ["github-advisory", "product-security", *[f"ecosystem-{eco}" for eco in ecosystems if eco], *[f"dependency:{pkg}" for pkg in packages[:20] if pkg]]
    return CVEImportItem(
        cve_id=cve_id,
        source_id=GHSA_SOURCE_ID,
        description=" ".join(part for part in [item.get("summary", ""), item.get("description", "")] if part)[:8000],
        published=item.get("published_at"),
        last_modified=item.get("updated_at"),
        vuln_status="reviewed",
        cvss_version="",
        cvss_score=str(cvss.get("score") or ""),
        cvss_severity=severity,
        cvss_vector=str(cvss.get("vector_string") or ""),
        cwe_ids=cwes,
        references=refs,
        tags=tags,
        raw=item,
    )


def _parse_osv_vuln(vuln: dict[str, Any], package: dict[str, str]) -> list[CVEImportItem]:
    aliases = [str(alias).upper() for alias in vuln.get("aliases", []) or []]
    cve_ids = sorted({alias for alias in aliases if CVE_ID_RE.fullmatch(alias)})
    if not cve_ids:
        vuln_id = str(vuln.get("id") or "").upper()
        if CVE_ID_RE.fullmatch(vuln_id):
            cve_ids = [vuln_id]
    refs = [
        {"url": str(ref.get("url") or ""), "source": "OSV.dev", "tags": [str(ref.get("type") or "reference").lower()]}
        for ref in vuln.get("references", []) or []
        if isinstance(ref, dict) and ref.get("url")
    ]
    severity = _osv_severity(vuln.get("severity") or [])
    tags = [
        "osv",
        "product-security",
        f"ecosystem-{package['ecosystem']}",
        f"dependency:{package['name']}",
    ]
    return [
        CVEImportItem(
            cve_id=cve_id,
            source_id=OSV_SOURCE_ID,
            description=" ".join(part for part in [vuln.get("summary", ""), vuln.get("details", "")] if part)[:8000],
            published=vuln.get("published"),
            last_modified=vuln.get("modified"),
            vuln_status="osv",
            cvss_version=severity.get("version", ""),
            cvss_score=severity.get("score", ""),
            cvss_severity=severity.get("severity", ""),
            cvss_vector=severity.get("vector", ""),
            references=refs,
            tags=tags,
            raw={**vuln, "queried_package": package},
        )
        for cve_id in cve_ids
    ]


def _fetch_osv_vuln_detail(vuln_id: str) -> dict[str, Any] | None:
    normalized = vuln_id.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{3,160}", normalized):
        return None
    response = safe_get(f"{OSV_VULN_URL}/{quote(normalized, safe='')}", headers={"User-Agent": APP_USER_AGENT}, timeout=30)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else None


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


def _osv_severity(items: list[dict[str, Any]]) -> dict[str, str]:
    for item in items:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score") or "")
        if item.get("type") == "CVSS_V3" and score:
            return {"version": "3.x", "score": _cvss_score_from_vector(score), "severity": "", "vector": score}
        if item.get("type") == "CVSS_V4" and score:
            return {"version": "4.0", "score": _cvss_score_from_vector(score), "severity": "", "vector": score}
    return {}


def _cvss_score_from_vector(vector: str) -> str:
    match = re.search(r"/BS:([0-9.]+)", vector)
    return match.group(1) if match else ""


def _normalize_osv_ecosystem(value: str) -> str:
    normalized = value.strip().lower()
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "python": "PyPI",
        "maven": "Maven",
        "go": "Go",
        "golang": "Go",
        "go-module": "Go",
        "nuget": "NuGet",
        "rubygems": "RubyGems",
        "gem": "RubyGems",
        "crates.io": "crates.io",
        "cargo": "crates.io",
        "packagist": "Packagist",
        "composer": "Packagist",
        "docker": "Docker",
        "deb": "Debian",
        "debian": "Debian",
        "alpine": "Alpine",
    }
    return mapping.get(normalized, value.strip())


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _chunks(items: list[str], size: int) -> list[list[str]]:
    return [items[index:index + size] for index in range(0, len(items), size)]


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


def _correlation_row(
    cve: CVERecord,
    *,
    relationship: str,
    confidence: int,
    evidence: str,
    source: str,
    path: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "cve": _cve_row(cve),
        "relationship": relationship,
        "confidence": confidence,
        "evidence": evidence,
        "source": source,
        "path": path,
    }
