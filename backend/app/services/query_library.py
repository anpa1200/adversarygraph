from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable
from urllib.parse import urlparse

from sqlalchemy import String, and_, cast, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ioc import IOCIndicator
from app.models.pipeline import DetectionVersion
from app.models.query_library import HuntQueryLibraryItem
from app.services.detections import validate_detection

ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
FIELD_ALIASES = {
    "tag": "tag",
    "tags": "tag",
    "ttp": "technique",
    "technique": "technique",
    "attack": "technique",
    "lang": "language",
    "language": "language",
    "source": "source",
    "platform": "platform",
    "ioc": "ioc_type",
    "type": "ioc_type",
}
SUPPORTED_LANGUAGES = ["sigma", "yaral", "yara", "kql", "spl", "eql", "lucene", "sql", "osquery", "generic"]
KNOWN_COMMUNITY_LICENSES = {
    "SigmaHQ Rules": "DRL-1.1",
    "Yara-Rules Malware Rules": "GPL-2.0-or-later",
    "Google SecOps Community YARA-L Rules": "Apache-2.0",
}


@dataclass(frozen=True)
class SearchTerm:
    field: str
    value: str


BEHAVIORS = [
    ("encoded-powershell", "Encoded PowerShell execution", "T1059.001", "execution", "powershell encoded command base64", "process_creation", "Windows", "process"),
    ("windows-lolbin-rundll32", "Rundll32 suspicious script execution", "T1218.011", "defense-evasion", "rundll32 javascript protocol suspicious command", "process_creation", "Windows", "process"),
    ("credential-dumping-lsass", "Credential dumping access to LSASS", "T1003.001", "credential-access", "lsass memory credential dumping", "process_access", "Windows", "process"),
    ("scheduled-task", "Suspicious scheduled task creation", "T1053.005", "persistence", "scheduled task schtasks remote creation", "process_creation", "Windows", "process"),
    ("service-install", "New or modified Windows service", "T1543.003", "persistence", "service creation sc.exe registry", "service_creation", "Windows", "process"),
    ("remote-services", "Remote service lateral movement", "T1021.002", "lateral-movement", "admin share smb remote service", "network_and_process", "Windows", "ip"),
    ("dns-tunneling", "Potential DNS tunneling", "T1071.004", "command-and-control", "long dns labels high volume subdomains", "dns", "Linux,Windows,macOS", "domain"),
    ("rare-user-agent", "Rare outbound HTTP user agent", "T1071.001", "command-and-control", "rare user agent outbound http beacon", "network", "Linux,Windows,macOS", "url"),
    ("archive-staging", "Archive utility used for data staging", "T1560.001", "collection", "7zip rar archive staging sensitive paths", "process_creation", "Linux,Windows,macOS", "process"),
    ("cloud-account-key", "Cloud service account key creation", "T1098.001", "persistence", "service account access key created", "cloud_audit", "Cloud", "account"),
    ("linux-shell-download", "Shell downloads and executes remote content", "T1059.004", "execution", "curl wget pipe shell chmod execute", "process_creation", "Linux", "url"),
    ("office-child-process", "Office application spawns a shell", "T1204.002", "execution", "office child process powershell cmd shell", "process_creation", "Windows", "process"),
    ("unsigned-driver", "Suspicious kernel driver load", "T1068", "privilege-escalation", "unsigned rare driver kernel load", "driver_load", "Windows", "hash"),
    ("ssh-authorized-keys", "SSH authorized_keys modification", "T1098.004", "persistence", "authorized_keys file modification ssh", "file_event", "Linux,macOS", "file"),
    ("weaken-defender", "Security tool configuration weakened", "T1562.001", "defense-evasion", "disable antivirus exclusion tamper protection", "process_and_registry", "Windows", "process"),
    ("browser-credential-store", "Browser credential store access", "T1555.003", "credential-access", "browser login data cookies credential store", "file_access", "Linux,Windows,macOS", "file"),
]


def parse_search_query(value: str) -> list[SearchTerm]:
    terms: list[SearchTerm] = []
    for match in re.finditer(r'(?:(\w+):)?(?:"([^"]+)"|(\S+))', value.strip()[:500]):
        raw_field, quoted, bare = match.groups()
        term = (quoted or bare or "").strip()
        if not term:
            continue
        field = FIELD_ALIASES.get((raw_field or "").lower(), "text")
        terms.append(SearchTerm(field, term[:120]))
    return terms[:20]


def _sigma_rule(slug: str, title: str, technique: str, tactic: str, keywords: str, data_source: str) -> str:
    words = [word for word in keywords.split() if len(word) > 3][:5]
    values = "\n".join(f"      - '*{word}*'" for word in words)
    return f"""title: {title}
id: ag-{slug}
status: experimental
description: Reviewed hunt starting point; validate fields and exclusions in the target backend.
references:
  - https://attack.mitre.org/techniques/{technique.replace('.', '/')}/
author: AdversaryGraph
date: 2026-07-20
tags:
  - attack.{tactic}
  - attack.{technique.lower().replace('.', '_')}
logsource:
  category: {data_source}
detection:
  selection:
    CommandLine|contains:
{values}
  condition: selection
falsepositives:
  - Approved administration and software deployment; tune for the environment.
level: medium"""


def _yaral_rule(slug: str, title: str, technique: str, keywords: str) -> str:
    pattern = "|".join(re.escape(word) for word in keywords.split() if len(word) > 3)[:180]
    return f"""rule ag_{slug.replace('-', '_')} {{
  meta:
    author = "AdversaryGraph"
    description = "{title}; analyst-review starting point"
    mitre_attack = "{technique}"
    reference = "https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"
    severity = "Medium"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    re.regex($e.target.process.command_line, `(?i)({pattern})`)

  condition:
    $e
}}"""


def curated_records() -> list[dict]:
    records: list[dict] = []
    for slug, title, technique, tactic, keywords, data_source, platforms, ioc_type in BEHAVIORS:
        base = {
            "description": f"Hunt for {title.lower()} using {data_source.replace('_', ' ')} telemetry. Review schema mapping, time range, baselines, and exclusions before execution.",
            "technique_ids": [technique],
            "tactics": [tactic],
            "tags": list(dict.fromkeys(["threat-hunting", tactic, *keywords.split()[:4]])),
            "data_sources": [data_source],
            "platforms": platforms.split(","),
            "ioc_types": [ioc_type],
            "source_name": "AdversaryGraph Reviewed Examples",
            "source_url": f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/",
            "source_license": "Apache-2.0",
            "quality_score": 85,
            "community": False,
        }
        records.append({**base, "stable_key": f"curated:sigma:{slug}", "title": f"{title} — Sigma", "language": "sigma", "query_text": _sigma_rule(slug, title, technique, tactic, keywords, data_source), "source_rule_id": f"ag-{slug}"})
        records.append({**base, "stable_key": f"curated:yaral:{slug}", "title": f"{title} — YARA-L", "language": "yaral", "query_text": _yaral_rule(slug, title, technique, keywords), "source_rule_id": f"ag_{slug.replace('-', '_')}"})
    return records


async def ensure_curated_library(session: AsyncSession) -> int:
    records = curated_records()
    for record in records:
        record["validation"] = validate_detection(record["language"], record["query_text"])
    statement = (
        pg_insert(HuntQueryLibraryItem)
        .values(records)
        .on_conflict_do_nothing(index_elements=["stable_key"])
    )
    result = await session.execute(statement)
    await session.commit()
    return int(result.rowcount or 0)


async def import_detection_versions(session: AsyncSession) -> dict[str, int]:
    rows = (await session.execute(select(DetectionVersion).order_by(DetectionVersion.created_at.desc()))).scalars().all()
    existing_keys = set((await session.execute(select(HuntQueryLibraryItem.stable_key).where(HuntQueryLibraryItem.community.is_(True)))).scalars().all())
    created = updated = 0
    for row in rows:
        validation = row.validation or {}
        source_url = str(validation.get("source_url") or "")
        if not source_url and not row.created_by.startswith("feed:"):
            continue
        digest = hashlib.sha256(f"{row.created_by}\0{validation.get('rule_id') or row.title}\0{row.format}".encode()).hexdigest()[:32]
        stable_key = f"community:{digest}"
        techniques = sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", f"{row.technique_id} {row.content}", re.I)))
        techniques = [item.upper() for item in techniques]
        tags = sorted(set(re.findall(r"(?im)^\s*-\s*(attack\.[a-z0-9_.-]+)\s*$", row.content)))
        record = {
            "stable_key": stable_key,
            "title": row.title,
            "description": "Community rule imported by the AdversaryGraph detection-feed pipeline. Validate compatibility and tune before use.",
            "language": row.format.lower(),
            "query_text": row.content,
            "technique_ids": techniques,
            "tactics": [tag.removeprefix("attack.") for tag in tags if not re.match(r"attack\.t\d", tag)],
            "tags": ["community", row.format.lower(), *tags],
            "data_sources": [], "platforms": [], "ioc_types": [],
            "source_name": row.created_by.removeprefix("feed:") or "Community feed",
            "source_url": source_url,
            "source_license": str(validation.get("source_license") or KNOWN_COMMUNITY_LICENSES.get(row.created_by.removeprefix("feed:"), "See upstream source")),
            "source_rule_id": str(validation.get("rule_id") or ""),
            "quality_score": 72 if validation.get("valid") else 45,
            "validation": validation,
            "community": True,
            "last_synced_at": datetime.now(timezone.utc),
        }
        existing = (await session.execute(select(HuntQueryLibraryItem).where(HuntQueryLibraryItem.stable_key == stable_key))).scalar_one_or_none()
        if existing:
            for key, value in record.items():
                if key != "stable_key":
                    setattr(existing, key, value)
            updated += 1
        else:
            session.add(HuntQueryLibraryItem(**record))
            existing_keys.add(stable_key)
            created += 1
    await session.commit()
    return {"seen": len(rows), "created": created, "updated": updated}


def _as_text(column):
    return func.lower(cast(column, String))


async def search_library(session: AsyncSession, *, q: str = "", language: str = "", technique: str = "", tag: str = "", source: str = "", platform: str = "", ioc_type: str = "", limit: int = 50, offset: int = 0) -> tuple[list[HuntQueryLibraryItem], int]:
    conditions = [HuntQueryLibraryItem.enabled.is_(True)]
    field_filters = {"language": language, "technique": technique, "tag": tag, "source": source, "platform": platform, "ioc_type": ioc_type}
    free_terms: list[str] = []
    for term in parse_search_query(q):
        if term.field == "text":
            free_terms.append(term.value)
        elif not field_filters.get(term.field):
            field_filters[term.field] = term.value
    if field_filters["language"]:
        conditions.append(func.lower(HuntQueryLibraryItem.language) == field_filters["language"].lower())
    if field_filters["technique"]:
        conditions.append(HuntQueryLibraryItem.technique_ids.contains([field_filters["technique"].upper()]))
    if field_filters["tag"]:
        conditions.append(HuntQueryLibraryItem.tags.contains([field_filters["tag"].lower()]))
    if field_filters["ioc_type"]:
        conditions.append(HuntQueryLibraryItem.ioc_types.contains([field_filters["ioc_type"].lower()]))
    if field_filters["platform"]:
        conditions.append(_as_text(HuntQueryLibraryItem.platforms).contains(field_filters["platform"].lower()))
    if field_filters["source"]:
        conditions.append(func.lower(HuntQueryLibraryItem.source_name).contains(field_filters["source"].lower()))
    searchable = [HuntQueryLibraryItem.title, HuntQueryLibraryItem.description, HuntQueryLibraryItem.query_text, HuntQueryLibraryItem.source_name, HuntQueryLibraryItem.tags, HuntQueryLibraryItem.technique_ids]
    for term in free_terms:
        needle = term.lower()
        conditions.append(or_(*[_as_text(column).contains(needle) for column in searchable]))
    where = and_(*conditions)
    total = int((await session.scalar(select(func.count()).select_from(HuntQueryLibraryItem).where(where))) or 0)
    order = [HuntQueryLibraryItem.quality_score.desc(), HuntQueryLibraryItem.updated_at.desc(), HuntQueryLibraryItem.title.asc()]
    rows = (await session.execute(select(HuntQueryLibraryItem).where(where).order_by(*order).offset(offset).limit(limit))).scalars().all()
    if free_terms:
        needles = [item.lower() for item in free_terms]
        def score(item: HuntQueryLibraryItem) -> tuple[int, int, str]:
            title = item.title.lower(); tags = " ".join(item.tags).lower(); techniques = " ".join(item.technique_ids).lower(); body = f"{item.description} {item.query_text}".lower()
            relevance = sum(30 if n == title else 18 if title.startswith(n) else 12 if n in title else 10 if n in tags or n in techniques else 2 if n in body else 0 for n in needles)
            return (-relevance, -item.quality_score, item.title.lower())
        rows.sort(key=score)
    return rows, total


async def facets(session: AsyncSession) -> dict:
    rows = (await session.execute(select(HuntQueryLibraryItem).where(HuntQueryLibraryItem.enabled.is_(True)))).scalars().all()
    def counts(values: Iterable[str]) -> list[dict]:
        result: dict[str, int] = {}
        for value in values:
            value = str(value).strip()
            if value:
                result[value] = result.get(value, 0) + 1
        return [{"value": key, "count": result[key]} for key in sorted(result, key=lambda key: (-result[key], key.lower()))]
    return {
        "total": len(rows),
        "languages": counts(row.language for row in rows),
        "techniques": counts(value for row in rows for value in row.technique_ids),
        "tags": counts(value for row in rows for value in row.tags),
        "sources": counts(row.source_name for row in rows),
        "platforms": counts(value for row in rows for value in row.platforms),
        "ioc_types": counts(value for row in rows for value in row.ioc_types),
    }


async def autocomplete(session: AsyncSession, q: str, limit: int = 12) -> list[dict]:
    needle = q.strip().lower()
    data = await facets(session)
    candidates: list[dict] = []
    for kind, key in (("language", "languages"), ("technique", "techniques"), ("tag", "tags"), ("source", "sources"), ("platform", "platforms"), ("ioc", "ioc_types")):
        for row in data[key]:
            value = row["value"]
            if not needle or needle in value.lower() or f"{kind}:{value}".lower().startswith(needle):
                candidates.append({"type": kind, "value": value, "label": f"{kind}:{value}", "count": row["count"]})
    candidates.sort(key=lambda item: (0 if item["value"].lower().startswith(needle) else 1, -item["count"], item["label"].lower()))
    return candidates[:limit]


def detect_ioc_type(value: str) -> str:
    value = value.strip()
    try:
        return "ip" if ipaddress.ip_address(value) else "ip"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if "@" in value and re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        return "email"
    if HASH_RE.fullmatch(value):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "hash")
    if re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", value):
        return "domain"
    return "text"


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "")


def build_ioc_query(observables: list[dict], language: str, *, title: str = "IOC match hunt", technique_ids: list[str] | None = None) -> dict:
    language = language.lower()
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported query language: {language}")
    clean: list[dict] = []
    for item in observables[:200]:
        value = str(item.get("value") or "").strip()[:2000]
        if not value:
            continue
        kind = str(item.get("type") or detect_ioc_type(value)).lower()
        clean.append({"value": value, "type": kind})
    clean = list({(item["type"], item["value"]): item for item in clean}.values())
    if not clean:
        raise ValueError("At least one non-empty IOC is required")
    techniques = sorted({item.upper() for item in (technique_ids or []) if ATTACK_ID_RE.fullmatch(item)})
    by_type: dict[str, list[str]] = {}
    for item in clean:
        by_type.setdefault(item["type"], []).append(item["value"])
    field_map = {"ip": "destination.ip", "domain": "dns.question.name", "url": "url.full", "md5": "file.hash.md5", "sha1": "file.hash.sha1", "sha256": "file.hash.sha256", "hash": "file.hash.sha256", "email": "user.email", "text": "message"}
    if language == "sigma":
        sigma_fields = {"ip": "DestinationIp", "domain": "query", "url": "url", "md5": "md5", "sha1": "sha1", "sha256": "sha256", "hash": "Hashes", "email": "User", "text": "Message"}
        blocks = []
        for kind, values in by_type.items():
            blocks.append(f"  selection_{kind}:\n    {sigma_fields.get(kind, 'Message')}:\n" + "\n".join(f"      - '{value.replace(chr(39), chr(39)*2)}'" for value in values))
        tags = "\n".join(f"  - attack.{item.lower().replace('.', '_')}" for item in techniques)
        query = f"title: {title}\nstatus: experimental\ndescription: IOC match generated by AdversaryGraph; validate field mappings and freshness.\nauthor: AdversaryGraph\nlogsource:\n  category: network_connection\ndetection:\n" + "\n".join(blocks) + f"\n  condition: 1 of selection_*\nfalsepositives:\n  - Shared infrastructure, sinks, scanners, or stale indicators\nlevel: medium" + (f"\ntags:\n{tags}" if tags else "")
    elif language == "yaral":
        clauses = []
        udm = {"ip": "$e.target.ip", "domain": "$e.network.dns.questions.name", "url": "$e.target.url", "md5": "$e.target.file.md5", "sha1": "$e.target.file.sha1", "sha256": "$e.target.file.sha256", "hash": "$e.target.file.sha256", "email": "$e.target.user.email_addresses", "text": "$e.security_result.description"}
        for kind, values in by_type.items():
            field = udm.get(kind, "$e.security_result.description")
            clauses.append("(" + " or ".join(f'{field} = "{_quote(value)}"' for value in values) + ")")
        query = f"rule ag_ioc_match_{hashlib.sha256(str(clean).encode()).hexdigest()[:10]} {{\n  meta:\n    author = \"AdversaryGraph\"\n    description = \"{_quote(title)}; validate UDM mappings and IOC freshness\"\n    severity = \"Medium\"\n\n  events:\n    " + "\n    or ".join(clauses) + "\n\n  condition:\n    $e\n}"
    elif language == "yara":
        strings = "\n".join(f'    $ioc_{index} = "{_quote(item["value"])}" ascii wide nocase' for index, item in enumerate(clean, 1))
        query = f"rule ag_ioc_match_{hashlib.sha256(str(clean).encode()).hexdigest()[:10]} {{\n  meta:\n    author = \"AdversaryGraph\"\n    description = \"{_quote(title)}; file-content match only\"\n  strings:\n{strings}\n  condition:\n    any of ($ioc_*)\n}}"
    else:
        clauses = []
        for kind, values in by_type.items():
            field = field_map.get(kind, "message")
            quoted = [_quote(value) for value in values]
            if language == "spl": clauses.append(f'{field} IN ({", ".join(chr(34)+v+chr(34) for v in quoted)})')
            elif language == "eql": clauses.append(f'{field} : ({", ".join(chr(34)+v+chr(34) for v in quoted)})')
            elif language == "kql": clauses.append(f'{field} in~ ({", ".join(chr(34)+v+chr(34) for v in quoted)})')
            elif language == "lucene": clauses.append(f'{field}: ({" OR ".join(chr(34)+v+chr(34) for v in quoted)})')
            elif language in {"sql", "osquery"}: clauses.append(f'{field.replace(".", "_")} IN ({", ".join(chr(39)+v.replace(chr(39), chr(39)*2)+chr(39) for v in quoted)})')
            else: clauses.append(f'{field} IN ({", ".join(quoted)})')
        query = " OR ".join(f"({item})" for item in clauses)
        if language == "spl": query = f"search {query} | table _time host source {', '.join(field_map.get(kind, 'message') for kind in by_type)}"
        elif language in {"sql", "osquery"}: query = f"SELECT * FROM security_events WHERE {query};"
    return {
        "title": title,
        "description": f"Match {len(clean)} supplied IOC{'s' if len(clean) != 1 else ''}. Generated locally without an LLM.",
        "query_language": language,
        "query_text": query,
        "technique_ids": techniques,
        "tags": ["ioc-hunt", *sorted(by_type)],
        "observables": clean,
        "warnings": ["Validate field mappings, IOC freshness, data retention, and allowlists in the destination platform.", "AdversaryGraph generated but did not execute this query."],
    }


async def resolve_iocs(session: AsyncSession, ids: list[int], raw: list[dict]) -> tuple[list[dict], list[str]]:
    techniques: set[str] = set()
    result = list(raw)
    if ids:
        rows = (await session.execute(select(IOCIndicator).where(IOCIndicator.id.in_(ids[:200])))).scalars().all()
        if len(rows) != len(set(ids[:200])):
            raise ValueError("One or more IOC IDs were not found")
        for row in rows:
            result.append({"value": row.value, "type": row.indicator_type, "source": row.source_id, "source_url": row.source_url})
            techniques.update(item.upper() for item in (row.technique_ids or []) if ATTACK_ID_RE.fullmatch(str(item)))
    return result, sorted(techniques)
