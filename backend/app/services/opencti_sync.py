from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.ioc import IOCIndicator, IOCSource
from app.services.ioc_intel import IOCImportItem, enrich_ioc_ttp_mappings, import_iocs
from app.services.ioc_stix import _indicator_pattern, _parse_pattern

OPENCTI_SOURCE_ID = "opencti"
OPENCTI_LABEL = "OpenCTI"
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class OpenCTISyncError(RuntimeError):
    pass


async def ensure_opencti_source(session: AsyncSession) -> None:
    stmt = insert(IOCSource).values(
        source_id=OPENCTI_SOURCE_ID,
        label=OPENCTI_LABEL,
        kind="opencti",
        url=_base_url(),
        enabled=True,
        sync_status="configured",
        sync_error="",
    ).on_conflict_do_update(
        index_elements=["source_id"],
        set_={
            "label": OPENCTI_LABEL,
            "kind": "opencti",
            "url": _base_url(),
            "enabled": True,
        },
    )
    await session.execute(stmt)
    await session.commit()


async def opencti_status() -> dict[str, Any]:
    _require_config()
    try:
        payload = await _graphql("query OpenCTIAbout { about { version } }")
        version = ((payload.get("about") or {}).get("version") or "").strip()
        return _status_payload(version=version)
    except Exception:
        payload = await _graphql("query OpenCTIMe { me { id name } }")
        me = payload.get("me") or {}
        return _status_payload(version="", user=me.get("name") or me.get("id") or "")


async def pull_from_opencti(
    session: AsyncSession,
    *,
    limit: int | None = None,
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    _require_config()
    await ensure_opencti_source(session)
    limit = _limit(limit)
    errors: list[str] = []
    items: list[IOCImportItem] = []
    report_count = 0

    indicators = await _safe_paged_query("indicators", _INDICATORS_QUERY, _INDICATORS_FALLBACK_QUERY, limit, errors)
    for node in indicators:
        item = _indicator_node_to_import_item(node)
        if item:
            items.append(item)

    observables = await _safe_paged_query("stixCyberObservables", _OBSERVABLES_QUERY, _OBSERVABLES_FALLBACK_QUERY, limit, errors)
    for node in observables:
        item = _observable_node_to_import_item(node)
        if item:
            items.append(item)

    reports = await _safe_paged_query("reports", _REPORTS_QUERY, _REPORTS_FALLBACK_QUERY, min(limit, 250), errors)
    for report in reports:
        created = await _upsert_opencti_report(session, report, domain=domain)
        report_count += int(created)
        items.extend(_report_indicator_items(report))

    result = await import_iocs(session, items) if items else {"source": OPENCTI_SOURCE_ID, "inserted": 0, "updated": 0, "actor_links": 0, "ttp_enriched": 0}
    enriched = await enrich_ioc_ttp_mappings(session, source_ids=[OPENCTI_SOURCE_ID], use_ai=False, domain=domain, limit=min(limit, 20000))
    await _mark_opencti_source(session, "ok" if not errors else "partial", "; ".join(errors[:3]))
    await session.commit()
    return {
        "source": OPENCTI_SOURCE_ID,
        "direction": "pull",
        "indicators_seen": len(indicators),
        "observables_seen": len(observables),
        "reports_seen": len(reports),
        "reports_imported": report_count,
        "inserted": int(result.get("inserted", 0)),
        "updated": int(result.get("updated", 0)),
        "actor_links": int(result.get("actor_links", 0)),
        "ttp_enriched": int(enriched.get("updated", 0)),
        "errors": errors,
    }


async def push_to_opencti(
    session: AsyncSession,
    *,
    limit: int | None = None,
    source_id: str = "",
    include_reports: bool = True,
) -> dict[str, Any]:
    _require_config()
    limit = _limit(limit)
    stmt = select(IOCIndicator).order_by(IOCIndicator.updated_at.desc()).limit(limit)
    if source_id:
        stmt = stmt.where(IOCIndicator.source_id == source_id)
    rows = await session.execute(stmt)
    indicators = list(rows.scalars().all())

    pushed = 0
    skipped = 0
    errors: list[str] = []
    for indicator in indicators:
        mutation_input = _indicator_to_opencti_input(indicator)
        if not mutation_input:
            skipped += 1
            continue
        try:
            await _graphql(_INDICATOR_ADD_MUTATION, {"input": mutation_input})
            pushed += 1
        except Exception as exc:
            try:
                await _graphql(_INDICATOR_ADD_MUTATION, {"input": _minimal_indicator_input(mutation_input)})
                pushed += 1
            except Exception as retry_exc:
                errors.append(f"{indicator.value}: {retry_exc or exc}")

    report_pushed = 0
    if include_reports:
        report_rows = await session.execute(
            select(AnalysisSession)
            .options(selectinload(AnalysisSession.result))
            .where(AnalysisSession.status == "completed")
            .order_by(AnalysisSession.updated_at.desc())
            .limit(min(limit, 100))
        )
        for report in report_rows.scalars().all():
            try:
                report_input = _analysis_session_to_report_input(report)
                await _graphql(_REPORT_ADD_MUTATION, {"input": report_input})
                report_pushed += 1
            except Exception as exc:
                try:
                    await _graphql(_REPORT_ADD_MUTATION, {"input": _minimal_report_input(report_input)})
                    report_pushed += 1
                except Exception as retry_exc:
                    errors.append(f"report {report.id}: {retry_exc or exc}")

    await _mark_opencti_source(session, "ok" if not errors else "partial", "; ".join(errors[:3]))
    await session.commit()
    return {
        "source": OPENCTI_SOURCE_ID,
        "direction": "push",
        "seen": len(indicators),
        "pushed_indicators": pushed,
        "skipped": skipped,
        "pushed_reports": report_pushed,
        "errors": errors[:25],
    }


async def sync_opencti(
    session: AsyncSession,
    *,
    limit: int | None = None,
    domain: str = "enterprise-attack",
    include_reports: bool = True,
) -> dict[str, Any]:
    pull = await pull_from_opencti(session, limit=limit, domain=domain)
    push = await push_to_opencti(session, limit=limit, include_reports=include_reports)
    return {"source": OPENCTI_SOURCE_ID, "direction": "bidirectional", "pull": pull, "push": push}


async def _safe_paged_query(
    root: str,
    query: str,
    fallback_query: str,
    limit: int,
    errors: list[str],
) -> list[dict[str, Any]]:
    try:
        return await _paged_query(root, query, limit)
    except Exception as exc:
        errors.append(f"{root} full query failed: {exc}")
    try:
        return await _paged_query(root, fallback_query, limit)
    except Exception as exc:
        errors.append(f"{root} fallback query failed: {exc}")
        return []


async def _paged_query(root: str, query: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    after: str | None = None
    while len(rows) < limit:
        first = min(100, limit - len(rows))
        payload = await _graphql(query, {"first": first, "after": after})
        container = payload.get(root) or {}
        edges = container.get("edges") or []
        rows.extend([edge.get("node") for edge in edges if isinstance(edge, dict) and isinstance(edge.get("node"), dict)])
        page_info = container.get("pageInfo") or {}
        if not page_info.get("hasNextPage") or not page_info.get("endCursor"):
            break
        after = str(page_info["endCursor"])
    return rows


async def _graphql(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    _require_config()
    headers = {
        "Authorization": f"Bearer {settings.opencti_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=90, verify=settings.opencti_verify_tls) as client:
        response = await client.post(f"{_connect_url()}/graphql", headers=headers, json={"query": query, "variables": variables or {}})
        response.raise_for_status()
        payload = response.json()
    if payload.get("errors"):
        messages = "; ".join(str(error.get("message") or error) for error in payload["errors"][:3])
        raise OpenCTISyncError(messages)
    data = payload.get("data")
    if not isinstance(data, dict):
        raise OpenCTISyncError("OpenCTI returned no GraphQL data")
    return data


def _indicator_node_to_import_item(node: dict[str, Any]) -> IOCImportItem | None:
    parsed = _parse_pattern(str(node.get("pattern") or ""))
    if not parsed:
        value = str(node.get("name") or node.get("observable_value") or "").strip()
        parsed = _guess_ioc_type(value)
    if not parsed:
        return None
    labels = _labels(node)
    return IOCImportItem(
        value=parsed["value"],
        indicator_type=parsed["type"],
        source=OPENCTI_SOURCE_ID,
        source_url=_external_url(node) or _object_url(node),
        first_seen=node.get("valid_from") or node.get("created"),
        last_seen=node.get("valid_until") or node.get("modified"),
        confidence=int(node.get("confidence") or 60),
        tags=_dedupe([*labels, "opencti-indicator"]),
        technique_ids=_extract_attack_ids(node),
        description=str(node.get("description") or node.get("name") or "OpenCTI indicator"),
        raw={"opencti": node, "source_kind": "indicator"},
    )


def _observable_node_to_import_item(node: dict[str, Any]) -> IOCImportItem | None:
    value = str(node.get("observable_value") or node.get("value") or _file_hash_value(node) or node.get("name") or node.get("file_name") or "").strip()
    parsed = _guess_ioc_type(value, str(node.get("entity_type") or ""))
    if not parsed:
        return None
    return IOCImportItem(
        value=parsed["value"],
        indicator_type=parsed["type"],
        source=OPENCTI_SOURCE_ID,
        source_url=_object_url(node),
        first_seen=node.get("created_at") or node.get("created"),
        last_seen=node.get("updated_at") or node.get("modified"),
        confidence=int(node.get("confidence") or 50),
        tags=_dedupe([*_labels(node), "opencti-observable"]),
        technique_ids=_extract_attack_ids(node),
        description=str(node.get("description") or f"OpenCTI {node.get('entity_type') or 'observable'}"),
        raw={"opencti": node, "source_kind": "observable"},
    )


def _report_indicator_items(report: dict[str, Any]) -> list[IOCImportItem]:
    labels = _dedupe([*_labels(report), "opencti-report"])
    technique_ids = _extract_attack_ids(report)
    source_url = _external_url(report) or _object_url(report)
    report_labels = report.get("labels") or report.get("objectLabel")
    report_refs = report.get("externalReferences") or report.get("external_references")
    items: list[IOCImportItem] = []
    for obj in _report_objects(report):
        item = None
        if str(obj.get("entity_type") or "").lower().endswith("indicator") or obj.get("pattern"):
            item = _indicator_node_to_import_item({**obj, "objectLabel": report_labels, "description": report.get("name"), "externalReferences": report_refs})
        else:
            item = _observable_node_to_import_item({**obj, "objectLabel": report_labels, "description": report.get("name")})
        if not item:
            continue
        item.tags = _dedupe([*(item.tags or []), *labels])
        item.technique_ids = _dedupe([*(item.technique_ids or []), *technique_ids])
        item.source_url = item.source_url or source_url
        item.raw = {**(item.raw or {}), "opencti_report": _report_summary(report)}
        items.append(item)
    return items


async def _upsert_opencti_report(session: AsyncSession, report: dict[str, Any], domain: str) -> bool:
    report_id = str(report.get("standard_id") or report.get("id") or "")
    if not report_id:
        return False
    filename = f"opencti:{report_id}"
    existing = await session.execute(select(AnalysisSession).where(AnalysisSession.filename == filename))
    session_row = existing.scalar_one_or_none()
    if session_row is None:
        session_row = AnalysisSession(
            status="completed",
            name=str(report.get("name") or "OpenCTI report"),
            input_type="file",
            filename=filename,
            llm_provider="opencti",
            model="opencti-sync",
            domain=domain,
        )
        session.add(session_row)
        await session.flush()
        created = True
    else:
        session_row.status = "completed"
        session_row.name = str(report.get("name") or session_row.name or "OpenCTI report")
        session_row.updated_at = datetime.now(timezone.utc)
        created = False

    result = await session.execute(select(AnalysisResult).where(AnalysisResult.session_id == session_row.id))
    result_row = result.scalar_one_or_none()
    summary = str(report.get("description") or report.get("name") or "OpenCTI report")
    extracted = [{"attack_id": attack_id, "name": "", "tactic": "", "confidence": 70, "evidence": "OpenCTI report metadata"} for attack_id in _extract_attack_ids(report)]
    raw = json.dumps({"opencti_report": report}, ensure_ascii=True, default=str)
    if result_row is None:
        session.add(AnalysisResult(session_id=session_row.id, extracted_techniques=extracted, apt_matches=[], summary=summary, raw_response=raw))
    else:
        result_row.extracted_techniques = extracted
        result_row.summary = summary
        result_row.raw_response = raw
    await session.flush()
    return created


def _indicator_to_opencti_input(indicator: IOCIndicator) -> dict[str, Any] | None:
    pattern = _indicator_pattern(indicator.indicator_type, indicator.value)
    if not pattern:
        return None
    labels = _dedupe([indicator.indicator_type, *(indicator.tags or []), "adversarygraph"])
    return {
        "name": indicator.value[:255],
        "description": indicator.description or f"Synced from AdversaryGraph source {indicator.source_id}",
        "pattern": pattern,
        "pattern_type": "stix",
        "x_opencti_main_observable_type": _opencti_observable_type(indicator.indicator_type),
        "valid_from": _date_or_now(indicator.first_seen),
        "confidence": max(0, min(100, indicator.confidence or 50)),
        "labels": labels,
        "update": True,
        "x_adversarygraph_source": indicator.source_id,
        "x_adversarygraph_technique_ids": indicator.technique_ids or [],
    }


def _analysis_session_to_report_input(report: AnalysisSession) -> dict[str, Any]:
    summary = report.result.summary if report.result else ""
    return {
        "name": (report.name or report.filename or str(report.id))[:255],
        "description": summary or f"AdversaryGraph analysis session {report.id}",
        "published": _date_or_now(report.updated_at.isoformat() if report.updated_at else None),
        "report_types": ["threat-report"],
        "confidence": 60,
        "update": True,
    }


def _minimal_indicator_input(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": value["name"],
        "description": value.get("description", ""),
        "pattern": value["pattern"],
        "pattern_type": value.get("pattern_type", "stix"),
        "valid_from": value.get("valid_from") or _date_or_now(None),
        "confidence": value.get("confidence", 50),
        "update": True,
    }


def _minimal_report_input(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": value["name"],
        "description": value.get("description", ""),
        "published": value.get("published") or _date_or_now(None),
        "report_types": value.get("report_types") or ["threat-report"],
        "confidence": value.get("confidence", 60),
        "update": True,
    }


async def _mark_opencti_source(session: AsyncSession, status: str, error: str) -> None:
    stmt = insert(IOCSource).values(
        source_id=OPENCTI_SOURCE_ID,
        label=OPENCTI_LABEL,
        kind="opencti",
        url=_base_url(),
        enabled=True,
        last_synced_at=datetime.now(timezone.utc),
        sync_status=status,
        sync_error=error[:4000],
    ).on_conflict_do_update(
        index_elements=["source_id"],
        set_={
            "url": _base_url(),
            "last_synced_at": datetime.now(timezone.utc),
            "sync_status": status,
            "sync_error": error[:4000],
        },
    )
    await session.execute(stmt)


def _require_config() -> None:
    if not settings.opencti_url or not settings.opencti_token:
        raise OpenCTISyncError("OPENCTI_URL and OPENCTI_TOKEN are required for OpenCTI sync.")


def _base_url() -> str:
    return settings.opencti_url.rstrip("/")


def _connect_url() -> str:
    configured = _base_url()
    parsed = urlsplit(configured)
    if parsed.hostname in {"localhost", "127.0.0.1"}:
        netloc = "host.docker.internal"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), "", ""))
    return configured


def _status_payload(version: str, user: str = "") -> dict[str, Any]:
    payload = {"configured": True, "reachable": True, "version": version, "url": _base_url()}
    if user:
        payload["user"] = user
    if _connect_url() != _base_url():
        payload["connection_url"] = _connect_url()
        payload["note"] = "Docker translated localhost/127.0.0.1 to host.docker.internal for backend connectivity."
    return payload


def _limit(value: int | None) -> int:
    return max(1, min(int(value or settings.opencti_sync_limit or 500), 5000))


def _labels(node: dict[str, Any]) -> list[str]:
    raw = node.get("labels") or node.get("objectLabel") or []
    if isinstance(raw, list):
        return _dedupe([str(item.get("value") if isinstance(item, dict) else item) for item in raw])
    if isinstance(raw, dict) and raw.get("value"):
        return _dedupe([str(raw.get("value") or "")])
    edges = (raw.get("edges") if isinstance(raw, dict) else []) or []
    return _dedupe([str(((edge.get("node") or {}).get("value")) or "") for edge in edges if isinstance(edge, dict)])


def _external_url(node: dict[str, Any]) -> str:
    refs = node.get("externalReferences") or node.get("external_references") or []
    if isinstance(refs, dict):
        refs = refs.get("edges") or []
        refs = [(edge.get("node") or {}) for edge in refs if isinstance(edge, dict)]
    for ref in refs if isinstance(refs, list) else []:
        if isinstance(ref, dict) and ref.get("url"):
            return str(ref["url"])
    return ""


def _object_url(node: dict[str, Any]) -> str:
    object_id = str(node.get("id") or "")
    return f"{_base_url()}/dashboard/id/{object_id}" if object_id and _base_url() else _base_url()


def _report_objects(report: dict[str, Any]) -> list[dict[str, Any]]:
    objects = report.get("objects") or report.get("objectRefs") or {}
    edges = objects.get("edges") if isinstance(objects, dict) else []
    return [(edge.get("node") or {}) for edge in edges or [] if isinstance(edge, dict) and isinstance(edge.get("node"), dict)]


def _report_summary(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": report.get("id"),
        "standard_id": report.get("standard_id"),
        "name": report.get("name"),
        "published": report.get("published"),
        "labels": _labels(report),
        "url": _external_url(report) or _object_url(report),
    }


def _guess_ioc_type(value: str, entity_type: str = "") -> dict[str, str] | None:
    value = value.strip()
    lowered = entity_type.lower()
    if not value:
        return None
    if "ipv4" in lowered or re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?", value):
        return {"type": "ip:port" if ":" in value else "ipv4", "value": value}
    if "ipv6" in lowered or (":" in value and re.fullmatch(r"[0-9a-fA-F:]+", value)):
        return {"type": "ipv6", "value": value}
    if "url" in lowered or value.startswith(("http://", "https://")):
        return {"type": "url", "value": value}
    if "domain" in lowered or re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d{1,5})?", value):
        return {"type": "domain", "value": value}
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return {"type": "sha256", "value": value.lower()}
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return {"type": "sha1", "value": value.lower()}
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return {"type": "md5", "value": value.lower()}
    return None


def _file_hash_value(node: dict[str, Any]) -> str:
    hashes = node.get("hashes") or []
    if isinstance(hashes, dict):
        hashes = hashes.get("edges") or hashes.get("values") or []
    candidates: list[tuple[str, str]] = []
    for entry in hashes if isinstance(hashes, list) else []:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("node") if isinstance(entry.get("node"), dict) else entry
        algorithm = str(raw.get("algorithm") or raw.get("hash_type") or raw.get("type") or "").lower()
        value = str(raw.get("hash") or raw.get("value") or "").strip()
        if value:
            candidates.append((algorithm, value))
    for preferred in ("sha-256", "sha256", "sha-1", "sha1", "md5"):
        for algorithm, value in candidates:
            if algorithm == preferred:
                return value
    return candidates[0][1] if candidates else ""


def _extract_attack_ids(value: Any) -> list[str]:
    return _dedupe([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(value, default=str))])


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        clean = str(value or "").strip()
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result[:100]


def _date_or_now(value: str | None) -> str:
    if value:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except Exception:
            pass
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _opencti_observable_type(indicator_type: str) -> str:
    return {
        "ipv4": "IPv4-Addr",
        "ip": "IPv4-Addr",
        "ip:port": "IPv4-Addr",
        "ipv6": "IPv6-Addr",
        "domain": "Domain-Name",
        "url": "Url",
        "sha256": "StixFile",
        "sha1": "StixFile",
        "md5": "StixFile",
        "email": "Email-Addr",
    }.get(indicator_type, "Unknown")


_INDICATORS_QUERY = """
query OpenCTIIndicators($first: Int!, $after: ID) {
  indicators(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node {
      id standard_id entity_type name description pattern pattern_type valid_from valid_until confidence created modified
      objectLabel { value color }
      externalReferences { edges { node { source_name url external_id description } } }
    } }
  }
}
"""

_INDICATORS_FALLBACK_QUERY = """
query OpenCTIIndicatorsFallback($first: Int!, $after: ID) {
  indicators(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { id standard_id entity_type name description pattern pattern_type confidence created modified } }
  }
}
"""

_OBSERVABLES_QUERY = """
query OpenCTIObservables($first: Int!, $after: ID) {
  stixCyberObservables(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node {
      id standard_id entity_type observable_value created_at updated_at
      objectLabel { value color }
      ... on DomainName { value }
      ... on Hostname { value }
      ... on IPv4Addr { value }
      ... on IPv6Addr { value }
      ... on Url { value }
      ... on EmailAddr { value }
      ... on StixFile { file_name: name hashes { algorithm hash } }
    } }
  }
}
"""

_OBSERVABLES_FALLBACK_QUERY = """
query OpenCTIObservablesFallback($first: Int!, $after: ID) {
  stixCyberObservables(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { id standard_id entity_type observable_value } }
  }
}
"""

_REPORTS_QUERY = """
query OpenCTIReports($first: Int!, $after: ID) {
  reports(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node {
      id standard_id entity_type name description published confidence report_types created modified
      objectLabel { value color }
      externalReferences { edges { node { source_name url external_id description } } }
      objects(first: 50) { edges { node {
        ... on BasicObject { id standard_id entity_type }
        ... on Indicator { id standard_id entity_type name description pattern pattern_type valid_from valid_until confidence created modified }
        ... on StixCyberObservable {
          id standard_id entity_type observable_value created_at updated_at
          ... on DomainName { value }
          ... on Hostname { value }
          ... on IPv4Addr { value }
          ... on IPv6Addr { value }
          ... on Url { value }
          ... on EmailAddr { value }
          ... on StixFile { file_name: name hashes { algorithm hash } }
        }
      } } }
    } }
  }
}
"""

_REPORTS_FALLBACK_QUERY = """
query OpenCTIReportsFallback($first: Int!, $after: ID) {
  reports(first: $first, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { id standard_id entity_type name description published confidence created modified } }
  }
}
"""

_INDICATOR_ADD_MUTATION = """
mutation AdversaryGraphIndicatorAdd($input: IndicatorAddInput!) {
  indicatorAdd(input: $input) { id standard_id name }
}
"""

_REPORT_ADD_MUTATION = """
mutation AdversaryGraphReportAdd($input: ReportAddInput!) {
  reportAdd(input: $input) { id standard_id name }
}
"""
