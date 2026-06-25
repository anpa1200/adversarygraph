"""
Signal collectors for RetroHunt:
  - NVD CVE API v2 (NIST)
  - CISA Known Exploited Vulnerabilities (KEV)
  - GitHub Security Advisory Database
  - Exploit-DB RSS feed

Each collector returns a CollectResult with counts of new/skipped signals.
All writes are idempotent via external_id unique constraint.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.retrohunt import RetroHuntSignal
from app.services.retrohunt_tagger import extract_cve_ids, tag_signal

logger = logging.getLogger(__name__)

_UA = "AdversaryGraph/1.0 (CTI platform; +https://github.com/anpa1200/adversarygraph)"

# ── helpers ───────────────────────────────────────────────────────────────────

@dataclass
class CollectResult:
    source: str
    inserted: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _cvss_to_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


async def _upsert_signal(db: AsyncSession, row: dict[str, Any]) -> bool:
    """Insert signal if external_id not already present. Returns True if inserted."""
    stmt = (
        pg_insert(RetroHuntSignal)
        .values(**row)
        .on_conflict_do_nothing(index_elements=["external_id"])
    )
    result = await db.execute(stmt)
    return result.rowcount > 0


# ── NVD CVE API v2 ────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Search terms — each is a separate API call to maximise coverage
NVD_SEARCH_TERMS = [
    "NVIDIA",
    "CUDA driver",
    "GeForce driver",
    "InfiniBand Mellanox",
    "BlueField DPU",
    "Jetson",
    "NVIDIA Triton",
]


async def collect_nvd(db: AsyncSession, days: int = 30) -> CollectResult:
    result = CollectResult(source="nvd")
    headers: dict[str, str] = {"User-Agent": _UA}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key

    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(days=days)
    pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    seen_cve_ids: set[str] = set()

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        for term in NVD_SEARCH_TERMS:
            params: dict[str, Any] = {
                "keywordSearch": term,
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": 200,
                "startIndex": 0,
            }
            try:
                resp = await client.get(NVD_BASE, params=params)
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                result.errors.append(f"NVD term={term!r}: {exc}")
                logger.warning("NVD collection error term=%r: %s", term, exc)
                await asyncio.sleep(6)
                continue

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id: str = cve.get("id", "")
                if not cve_id or cve_id in seen_cve_ids:
                    continue
                seen_cve_ids.add(cve_id)

                external_id = f"nvd_{cve_id}"
                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    "",
                )
                refs = [r.get("url", "") for r in cve.get("references", [])]
                primary_url = refs[0] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"

                # CVSS score — try v3.1, v3.0, v2
                metrics = cve.get("metrics", {})
                cvss_score: float | None = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    entries = metrics.get(key, [])
                    if entries:
                        cvss_score = entries[0].get("cvssData", {}).get("baseScore")
                        break

                tags = tag_signal(cve_id + " " + desc, "")
                cve_ids = [cve_id] + [c for c in extract_cve_ids(desc) if c != cve_id]

                row: dict[str, Any] = {
                    "source": "nvd",
                    "signal_type": "cve",
                    "external_id": external_id,
                    "title": cve_id,
                    "body": desc,
                    "url": primary_url,
                    "published_at": _parse_dt(cve.get("published")),
                    "severity": _cvss_to_severity(cvss_score),
                    "cvss_score": cvss_score,
                    "sector_tags": tags["sector_tags"],
                    "tech_tags": tags["tech_tags"],
                    "cve_ids": cve_ids,
                    "product_tags": [],
                    "raw_json": {"cvss": cvss_score, "refs": refs[:10]},
                }
                inserted = await _upsert_signal(db, row)
                if inserted:
                    result.inserted += 1
                else:
                    result.skipped += 1

            # NVD rate limit: 5 req/30s without key, 50 req/30s with key
            await asyncio.sleep(2 if settings.nvd_api_key else 7)

    await db.commit()
    logger.info("NVD collection done inserted=%d skipped=%d", result.inserted, result.skipped)
    return result


# ── CISA KEV ─────────────────────────────────────────────────────────────────

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CISA KEV products we care about (case-insensitive substring match)
KEV_VENDOR_FILTER = ["nvidia", "mellanox", "linux", "vmware", "microsoft", "apache", "cisco", "fortinet"]


async def collect_cisa_kev(db: AsyncSession) -> CollectResult:
    result = CollectResult(source="cisa_kev")
    try:
        async with httpx.AsyncClient(timeout=30, headers={"User-Agent": _UA}) as client:
            resp = await client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        result.errors.append(str(exc))
        logger.warning("CISA KEV fetch failed: %s", exc)
        return result

    for vuln in data.get("vulnerabilities", []):
        vendor = (vuln.get("vendorProject") or "").lower()
        product = (vuln.get("product") or "").lower()
        combined = vendor + " " + product

        # Only import if vendor/product is relevant
        if not any(kw in combined for kw in KEV_VENDOR_FILTER):
            result.skipped += 1
            continue

        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        external_id = f"kev_{cve_id}"
        title = f"{cve_id} — {vuln.get('vulnerabilityName', '')}"
        body = f"{vuln.get('shortDescription', '')} Required action: {vuln.get('requiredAction', '')}"
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        tags = tag_signal(title, body)

        row: dict[str, Any] = {
            "source": "cisa_kev",
            "signal_type": "advisory",
            "external_id": external_id,
            "title": title,
            "body": body,
            "url": url,
            "published_at": _parse_dt(vuln.get("dateAdded")),
            "severity": "high",  # All KEV entries are confirmed exploited — treat as high minimum
            "cvss_score": None,
            "sector_tags": tags["sector_tags"],
            "tech_tags": tags["tech_tags"],
            "cve_ids": [cve_id],
            "product_tags": [vuln.get("vendorProject", ""), vuln.get("product", "")],
            "raw_json": {
                "vendor": vuln.get("vendorProject"),
                "product": vuln.get("product"),
                "due_date": vuln.get("dueDate"),
                "required_action": vuln.get("requiredAction"),
            },
        }
        inserted = await _upsert_signal(db, row)
        if inserted:
            result.inserted += 1
        else:
            result.skipped += 1

    await db.commit()
    logger.info("CISA KEV done inserted=%d skipped=%d", result.inserted, result.skipped)
    return result


# ── GitHub Security Advisory DB ───────────────────────────────────────────────

GITHUB_ADV_URL = "https://api.github.com/advisories"

GITHUB_ECOSYSTEMS = ["pip", "actions", "rust", "go", "npm", "maven"]
GITHUB_KEYWORD_FILTER = [
    "nvidia", "cuda", "torch", "tensorflow", "onnx",
    "triton", "ray", "kubernetes", "docker", "linux",
    "gpu", "mlflow", "huggingface", "transformers",
]


async def collect_github_advisories(db: AsyncSession, days: int = 30) -> CollectResult:
    result = CollectResult(source="github_advisory")
    headers: dict[str, str] = {
        "User-Agent": _UA,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    updated_since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params: dict[str, Any] = {
        "type": "reviewed",
        "per_page": 100,
        "sort": "published",
        "direction": "desc",
        "updated_since": updated_since,
    }

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        page = 1
        while True:
            params["page"] = page
            try:
                resp = await client.get(GITHUB_ADV_URL, params=params)
                resp.raise_for_status()
                advisories: list[dict[str, Any]] = resp.json()
            except Exception as exc:
                result.errors.append(str(exc))
                logger.warning("GitHub advisory fetch page=%d: %s", page, exc)
                break

            if not advisories:
                break

            for adv in advisories:
                ghsa_id: str = adv.get("ghsa_id", "")
                if not ghsa_id:
                    continue

                summary = adv.get("summary", "")
                description = adv.get("description", "") or ""
                cve_id: str = adv.get("cve_id") or ""
                severity: str = (adv.get("severity") or "unknown").lower()
                cvss_score_raw = adv.get("cvss", {})
                cvss_score: float | None = cvss_score_raw.get("score") if isinstance(cvss_score_raw, dict) else None

                full_text = summary + " " + description
                kw_match = any(kw in full_text.lower() for kw in GITHUB_KEYWORD_FILTER)
                if not kw_match:
                    result.skipped += 1
                    continue

                external_id = f"ghsa_{ghsa_id}"
                refs: list[str] = adv.get("references", [])
                url = f"https://github.com/advisories/{ghsa_id}"

                cve_ids_in_text = extract_cve_ids(full_text)
                if cve_id and cve_id not in cve_ids_in_text:
                    cve_ids_in_text.insert(0, cve_id)

                tags = tag_signal(summary, description)

                vuln_packages: list[str] = []
                for v in adv.get("vulnerabilities", []):
                    pkg = v.get("package", {})
                    if pkg.get("name"):
                        vuln_packages.append(f"{pkg.get('ecosystem','?')}:{pkg['name']}")

                row: dict[str, Any] = {
                    "source": "github_advisory",
                    "signal_type": "cve" if cve_id else "advisory",
                    "external_id": external_id,
                    "title": f"{ghsa_id}{' / ' + cve_id if cve_id else ''}: {summary}",
                    "body": description[:4000],
                    "url": url,
                    "published_at": _parse_dt(adv.get("published_at")),
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "sector_tags": tags["sector_tags"],
                    "tech_tags": tags["tech_tags"],
                    "cve_ids": cve_ids_in_text,
                    "product_tags": vuln_packages[:20],
                    "raw_json": {"refs": refs[:10], "packages": vuln_packages[:20]},
                }
                inserted = await _upsert_signal(db, row)
                if inserted:
                    result.inserted += 1
                else:
                    result.skipped += 1

            if len(advisories) < 100:
                break
            page += 1
            await asyncio.sleep(1)

    await db.commit()
    logger.info("GitHub advisory done inserted=%d skipped=%d", result.inserted, result.skipped)
    return result


# ── Exploit-DB RSS ────────────────────────────────────────────────────────────

EXPLOITDB_RSS = "https://www.exploit-db.com/rss.xml"

EXPLOITDB_FILTER = [
    "nvidia", "cuda", "geforce", "driver privilege",
    "linux kernel", "windows kernel", "vmware", "kubernetes",
    "docker", "apache", "gpu", "jetson", "mellanox",
]

_EDB_ID_RE = re.compile(r"exploit-db\.com/exploits/(\d+)", re.IGNORECASE)
_EDB_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


async def collect_exploitdb(db: AsyncSession) -> CollectResult:
    result = CollectResult(source="exploitdb")
    try:
        async with httpx.AsyncClient(
            timeout=30,
            headers={"User-Agent": _UA},
            follow_redirects=True,
        ) as client:
            resp = await client.get(EXPLOITDB_RSS)
            resp.raise_for_status()
            raw = resp.text
    except Exception as exc:
        result.errors.append(str(exc))
        logger.warning("ExploitDB RSS fetch failed: %s", exc)
        return result

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        result.errors.append(f"RSS parse error: {exc}")
        return result

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    channel = root.find("channel")
    items = channel.findall("item") if channel is not None else root.findall(".//item")

    for item in items:
        title_el = item.find("title")
        link_el = item.find("link")
        desc_el = item.find("description")
        date_el = item.find("pubDate")

        title = (title_el.text or "") if title_el is not None else ""
        link = (link_el.text or "") if link_el is not None else ""
        body = (desc_el.text or "") if desc_el is not None else ""
        pub_str = (date_el.text or "") if date_el is not None else ""

        combined = (title + " " + body).lower()
        if not any(kw in combined for kw in EXPLOITDB_FILTER):
            result.skipped += 1
            continue

        # Extract EDB ID from URL
        edb_match = _EDB_ID_RE.search(link)
        edb_id = edb_match.group(1) if edb_match else str(abs(hash(link)) % 10**8)
        external_id = f"edb_{edb_id}"

        cve_ids = [m.upper() for m in _EDB_CVE_RE.findall(title + " " + body)]
        tags = tag_signal(title, body)

        # Parse RFC 2822 date
        published_at: datetime | None = None
        if pub_str:
            try:
                from email.utils import parsedate_to_datetime
                published_at = parsedate_to_datetime(pub_str).replace(tzinfo=timezone.utc)
            except Exception:
                pass

        row: dict[str, Any] = {
            "source": "exploitdb",
            "signal_type": "exploit",
            "external_id": external_id,
            "title": title,
            "body": body[:2000],
            "url": link,
            "published_at": published_at,
            "severity": "high",  # Published exploits are inherently high signal
            "cvss_score": None,
            "sector_tags": tags["sector_tags"],
            "tech_tags": tags["tech_tags"],
            "cve_ids": cve_ids,
            "product_tags": [],
            "raw_json": {"edb_id": edb_id},
        }
        inserted = await _upsert_signal(db, row)
        if inserted:
            result.inserted += 1
        else:
            result.skipped += 1

    await db.commit()
    logger.info("ExploitDB done inserted=%d skipped=%d", result.inserted, result.skipped)
    return result


# ── Orchestrator ──────────────────────────────────────────────────────────────

async def run_all_collectors(db: AsyncSession, days: int = 30) -> list[CollectResult]:
    results: list[CollectResult] = []
    for collector, kwargs in [
        (collect_cisa_kev, {}),
        (collect_nvd, {"days": days}),
        (collect_github_advisories, {"days": days}),
        (collect_exploitdb, {}),
    ]:
        try:
            r = await collector(db, **kwargs)  # type: ignore[call-arg]
            results.append(r)
        except Exception as exc:
            logger.exception("Collector %s failed: %s", collector.__name__, exc)
            results.append(CollectResult(source=collector.__name__, errors=[str(exc)]))
    return results
