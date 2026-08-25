from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.ioc import IOCIndicator, IOCSource
from app.models.operations import ReportIntake
from app.models.report_review import (
    ReportPromotion,
    ReportPromotionRevocation,
    ReportReview,
)
from app.services.ioc_intel import IOCImportItem, enrich_ioc_ttp_mappings, import_iocs
from app.services.ioc_stix import _indicator_pattern, _parse_pattern
from app.services.report_promotion import (
    accepted_claims,
    authorized_report_promotion_indicator_ids,
    get_active_report_promotion,
    promotion_allows,
)
from app.services.report_intake import latest_report_intake_id_subquery
from app.services.report_review import (
    ReviewActor,
    _source_metadata,
    run_preflight,
    start_review,
)

OPENCTI_SOURCE_ID = "opencti"
OPENCTI_LABEL = "OpenCTI"
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
NETWORK_FINGERPRINT_TYPES = {"ja3", "ja3s", "ja4", "ja4s", "ja4h", "ja4l", "ja4ls", "ja4x", "ja4ssh", "ja4t"}
NETWORK_FINGERPRINT_VALUE_RE = re.compile(
    r"^(?=[a-z0-9]{3,32}_)(?=[a-z0-9]*\d)[a-z0-9]{3,32}_[a-f0-9]{8,64}(?:_[a-f0-9]{8,64}){0,3}$", re.IGNORECASE
)
OPENCTI_REPORT_TEXT_LIMIT = 120_000
OPENCTI_REVIEW_ACTOR = ReviewActor(
    name="OpenCTI sync service",
    actor_id="service:opencti-sync",
)
logger = logging.getLogger(__name__)


class OpenCTISyncError(RuntimeError):
    pass


async def ensure_opencti_source(session: AsyncSession) -> None:
    stmt = (
        insert(IOCSource)
        .values(
            source_id=OPENCTI_SOURCE_ID,
            label=OPENCTI_LABEL,
            kind="opencti",
            url=_base_url(),
            enabled=True,
            sync_status="configured",
            sync_error="",
        )
        .on_conflict_do_update(
            index_elements=["source_id"],
            set_={
                "label": OPENCTI_LABEL,
                "kind": "opencti",
                "url": _base_url(),
                "enabled": True,
            },
        )
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
    protected_reports = 0
    for report in reports:
        outcome = await _upsert_opencti_report(session, report, domain=domain)
        report_count += int(outcome == "created")
        protected_reports += int(outcome == "protected")

    result = (
        await import_iocs(session, items)
        if items
        else {"source": OPENCTI_SOURCE_ID, "inserted": 0, "updated": 0, "actor_links": 0, "ttp_enriched": 0}
    )
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
        "skipped": protected_reports,
        "inserted": _as_int(result.get("inserted")),
        "updated": _as_int(result.get("updated")),
        "actor_links": _as_int(result.get("actor_links")),
        "ttp_enriched": _as_int(enriched.get("updated")),
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
    promotion_indicators = [indicator for indicator in indicators if str(indicator.source_id or "").startswith("report-promotion-")]
    authorized_promotion_indicators = await authorized_report_promotion_indicator_ids(
        session,
        promotion_indicators,
        target="exports",
    )
    authority_skipped = sum(
        1
        for indicator in indicators
        if str(indicator.source_id or "").startswith("report-promotion-") and indicator.id not in authorized_promotion_indicators
    )
    indicators = [
        indicator
        for indicator in indicators
        if not str(indicator.source_id or "").startswith("report-promotion-") or indicator.id in authorized_promotion_indicators
    ]

    pushed = 0
    skipped = authority_skipped
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
            except Exception:
                logger.exception(
                    "OpenCTI indicator push failed after fallback indicator_id=%s original_error=%r",
                    indicator.id,
                    exc,
                )
                errors.append(f"indicator {indicator.id}: push failed. See server logs.")

    report_pushed = 0
    if include_reports:
        report_rows = await session.execute(
            select(
                AnalysisSession,
                AnalysisResult,
                ReportPromotion,
                ReportReview,
                ReportIntake,
            )
            .join(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
            .join(ReportPromotion, ReportPromotion.session_id == AnalysisSession.id)
            .join(ReportReview, ReportReview.id == ReportPromotion.review_id)
            .outerjoin(
                ReportIntake,
                ReportIntake.id == latest_report_intake_id_subquery(AnalysisSession.id),
            )
            .outerjoin(
                ReportPromotionRevocation,
                ReportPromotionRevocation.promotion_id == ReportPromotion.id,
            )
            .where(
                AnalysisSession.status == "completed",
                ReportReview.state == "promoted",
                ReportPromotionRevocation.id.is_(None),
            )
            .order_by(AnalysisSession.updated_at.desc(), AnalysisSession.id.desc())
            .limit(min(limit, 100))
        )
        for report, _result, promotion, _review, _intake in report_rows.all():
            active = await get_active_report_promotion(session, report.id)
            if (
                active is None
                or active.promotion.id != promotion.id
                or not promotion_allows(active.promotion, "exports")
            ):
                skipped += 1
                continue
            try:
                report_input = _analysis_session_to_report_input(report, promotion)
            except Exception:
                logger.exception("OpenCTI report serialization failed report_id=%s", report.id)
                errors.append(f"report {report.id}: serialization failed. See server logs.")
                continue
            try:
                await _graphql(_REPORT_ADD_MUTATION, {"input": report_input})
                report_pushed += 1
            except Exception as exc:
                try:
                    await _graphql(_REPORT_ADD_MUTATION, {"input": _minimal_report_input(report_input)})
                    report_pushed += 1
                except Exception:
                    logger.exception(
                        "OpenCTI report push failed after fallback report_id=%s original_error=%r",
                        report.id,
                        exc,
                    )
                    errors.append(f"report {report.id}: push failed. See server logs.")

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
    except Exception:
        logger.exception("OpenCTI full query failed root=%s", root)
        errors.append(f"{root} full query failed. See server logs.")
    try:
        return await _paged_query(root, fallback_query, limit)
    except Exception:
        logger.exception("OpenCTI fallback query failed root=%s", root)
        errors.append(f"{root} fallback query failed. See server logs.")
        return []


async def _paged_query(root: str, query: str, limit: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    after: str | None = None
    while len(rows) < limit:
        first = min(100, limit - len(rows))
        payload = await _graphql(query, {"first": first, "after": after})
        container_value = payload.get(root)
        if not isinstance(container_value, dict):
            raise OpenCTISyncError(f"OpenCTI returned an invalid {root} connection")
        edges_value = container_value.get("edges")
        edges = edges_value if isinstance(edges_value, list) else []
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            node = edge.get("node")
            if isinstance(node, dict):
                rows.append(node)
        page_info_value = container_value.get("pageInfo")
        page_info = page_info_value if isinstance(page_info_value, dict) else {}
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
    async with httpx.AsyncClient(
        timeout=90,
        verify=settings.opencti_verify_tls,
        trust_env=False,
    ) as client:
        response = await client.post(f"{_connect_url()}/graphql", headers=headers, json={"query": query, "variables": variables or {}})
        response.raise_for_status()
        payload = response.json()
    if not isinstance(payload, dict):
        raise OpenCTISyncError("OpenCTI returned an invalid GraphQL response")
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
    value = str(
        node.get("observable_value") or node.get("value") or _file_hash_value(node) or node.get("name") or node.get("file_name") or ""
    ).strip()
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
            item = _indicator_node_to_import_item(
                {**obj, "objectLabel": report_labels, "description": report.get("name"), "externalReferences": report_refs}
            )
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


async def _upsert_opencti_report(
    session: AsyncSession,
    report: dict[str, Any],
    domain: str,
) -> str:
    report_id = str(report.get("standard_id") or report.get("id") or "")
    if not report_id:
        return "ignored"
    filename = f"opencti:{report_id}"
    existing = await session.execute(select(AnalysisSession).where(AnalysisSession.filename == filename).with_for_update())
    session_row = existing.scalar_one_or_none()
    source_text = _opencti_report_source_text(report)
    summary = str(report.get("description") or report.get("name") or "OpenCTI report")
    extracted = _opencti_report_techniques(report, source_text)
    raw = json.dumps({"opencti_report": report}, ensure_ascii=True, default=str)

    if session_row is None:
        session_row = AnalysisSession(
            status="completed",
            name=str(report.get("name") or "OpenCTI report"),
            input_type="file",
            filename=filename,
            llm_provider="opencti",
            model="opencti-sync",
            domain=domain,
            tlp="TLP:AMBER+STRICT",
            source_text=source_text,
            source_provenance=_opencti_source_provenance(report, source_text),
        )
        session.add(session_row)
        await session.flush()
        result_row = AnalysisResult(
            session_id=session_row.id,
            extracted_techniques=extracted,
            apt_matches=[],
            summary=summary,
            raw_response=raw,
        )
        session.add(result_row)
        intake = _new_opencti_report_intake(
            session_row,
            report,
            source_text=source_text,
            summary=summary,
            technique_ids=[item["attack_id"] for item in extracted],
        )
        session.add(intake)
        await session.flush()
        await _initialize_opencti_review(session, session_row.id, report_id)
        await session.flush()
        return "created"

    result = await session.execute(select(AnalysisResult).where(AnalysisResult.session_id == session_row.id).limit(1).with_for_update())
    result_row = result.scalar_one_or_none()
    protection_reason = await _analysis_write_protection_reason(
        session,
        session_row.id,
        result_row,
    )
    if protection_reason:
        logger.info(
            "Skipping OpenCTI report overwrite report_id=%s session_id=%s reason=%s",
            report_id,
            session_row.id,
            protection_reason,
        )
        return "protected"

    session_row.status = "completed"
    session_row.name = str(report.get("name") or session_row.name or "OpenCTI report")
    session_row.domain = domain
    session_row.source_text = source_text
    session_row.source_provenance = _opencti_source_provenance(report, source_text)
    session_row.updated_at = datetime.now(timezone.utc)
    if result_row is None:
        session.add(
            AnalysisResult(
                session_id=session_row.id,
                extracted_techniques=extracted,
                apt_matches=[],
                summary=summary,
                raw_response=raw,
            )
        )
    else:
        result_row.extracted_techniques = extracted
        result_row.summary = summary
        result_row.raw_response = raw
    intake = await _opencti_report_intake(session, session_row.id)
    if intake is None:
        session.add(
            _new_opencti_report_intake(
                session_row,
                report,
                source_text=source_text,
                summary=summary,
                technique_ids=[item["attack_id"] for item in extracted],
            )
        )
    await session.flush()
    await _initialize_opencti_review(session, session_row.id, report_id)
    await session.flush()
    return "updated"


async def _opencti_report_intake(
    session: AsyncSession,
    session_id: Any,
) -> ReportIntake | None:
    row = await session.execute(
        select(ReportIntake)
        .where(ReportIntake.analysis_session_id == session_id)
        .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
        .limit(1)
        .with_for_update()
    )
    return row.scalar_one_or_none()


async def _initialize_opencti_review(
    session: AsyncSession,
    session_id: Any,
    report_id: str,
) -> None:
    """Require every writable OpenCTI analysis to enter deterministic review."""

    try:
        review = await start_review(
            session,
            session_id,
            OPENCTI_REVIEW_ACTOR,
            profile="external_cti",
        )
        await run_preflight(
            session,
            session_id,
            OPENCTI_REVIEW_ACTOR,
            expected_version=review.version,
        )
    except Exception as exc:
        logger.exception(
            "OpenCTI report failed required Review Gate initialization report_id=%s",
            report_id,
        )
        raise OpenCTISyncError("An OpenCTI report could not enter the required Review Gate") from exc


async def _analysis_write_protection_reason(
    session: AsyncSession,
    session_id: Any,
    result: AnalysisResult | None,
) -> str:
    review_id = await session.scalar(select(ReportReview.id).where(ReportReview.session_id == session_id).limit(1))
    if review_id is not None:
        return "review_history"
    promotion_id = await session.scalar(select(ReportPromotion.id).where(ReportPromotion.session_id == session_id).limit(1))
    if promotion_id is not None:
        return "promotion_history"
    if result is not None and _has_legacy_analyst_review(result):
        return "legacy_analyst_review"
    return ""


def _has_legacy_analyst_review(result: AnalysisResult) -> bool:
    for item in result.extracted_techniques or []:
        if not isinstance(item, dict):
            continue
        status = str(item.get("review_status") or "suggested").strip().lower().replace("_", "-")
        if status not in {"", "suggested"}:
            return True
    return False


def _opencti_report_source_text(report: dict[str, Any]) -> str:
    report_id = str(report.get("standard_id") or report.get("id") or "unknown")
    name = str(report.get("name") or "OpenCTI report").strip()
    description = str(report.get("description") or "").strip()
    source_url = _external_url(report) or _object_url(report)
    lines = [f"OpenCTI report: {name}", f"OpenCTI object ID: {report_id}"]
    if report.get("published"):
        lines.append(f"Published: {report.get('published')}")
    if source_url:
        lines.append(f"Source URL: {source_url}")
    lines.extend(f"OpenCTI report references ATT&CK technique {attack_id}." for attack_id in _extract_attack_ids(report))
    if description:
        lines.extend(["", "Description:", description])
    return "\n".join(lines).strip()[:OPENCTI_REPORT_TEXT_LIMIT]


def _opencti_report_techniques(
    report: dict[str, Any],
    source_text: str,
) -> list[dict[str, Any]]:
    techniques: list[dict[str, Any]] = []
    for attack_id in _extract_attack_ids(report):
        evidence = f"OpenCTI report references ATT&CK technique {attack_id}."
        start = source_text.find(evidence)
        techniques.append(
            {
                "attack_id": attack_id,
                "name": "",
                "tactic": "",
                "confidence": 70,
                "evidence": evidence,
                "evidence_start": start if start >= 0 else None,
                "evidence_end": start + len(evidence) if start >= 0 else None,
                "review_status": "suggested",
                "llm_verified": False,
            }
        )
    return techniques


def _opencti_source_provenance(
    report: dict[str, Any],
    source_text: str,
) -> dict[str, Any]:
    acquired_at = datetime.now(timezone.utc).isoformat()
    content = json.dumps(report, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
    return {
        "schema_version": "analysis-source-provenance-v1",
        # The deterministic source gate understands point-in-time file
        # acquisitions.  An OpenCTI GraphQL object is treated as that kind of
        # immutable snapshot; its origin remains explicit in separate fields.
        "source_kind": "file",
        "origin_kind": "opencti-report",
        "source_system": OPENCTI_SOURCE_ID,
        "acquisition": {
            "schema_version": "source-acquisition-v1",
            "source_kind": "file",
            "origin_kind": "opencti-report",
            "source_system": OPENCTI_SOURCE_ID,
            "filename": str(report.get("standard_id") or report.get("id") or ""),
            "acquired_at": acquired_at,
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "content_size_bytes": len(content),
            "extracted_text_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            "extracted_text_chars": len(source_text),
            "superseded": False,
        },
    }


def _new_opencti_report_intake(
    session_row: AnalysisSession,
    report: dict[str, Any],
    *,
    source_text: str,
    summary: str,
    technique_ids: list[str],
) -> ReportIntake:
    source_url = _external_url(report) or _object_url(report)
    publication_date = _opencti_publication_date(report.get("published"))
    publication_candidates = [{"value": publication_date, "source": "opencti.report.published"}] if publication_date else []
    return ReportIntake(
        analysis_session_id=session_row.id,
        title=str(report.get("name") or "OpenCTI report")[:500],
        # This report was acquired through the OpenCTI GraphQL response, not by
        # dereferencing its external reference.  Keep that reference as
        # metadata rather than fabricating a successful URL retrieval receipt.
        url="",
        publisher=OPENCTI_LABEL,
        status="draft",
        summary=summary[:100_000],
        source_reliability="unknown",
        actor_ids=[],
        technique_ids=technique_ids,
        # Objects embedded by a report remain report-local candidates. Only a
        # live promotion may materialize accepted indicator claims globally;
        # first-class OpenCTI indicator/observable queries above retain their
        # independent feed semantics.
        indicators=[asdict(item) for item in _report_indicator_items(report)],
        tags=_dedupe([*_labels(report), "opencti-report"]),
        provenance={
            "source_kind": "file",
            "origin_kind": "opencti-report",
            "source_system": OPENCTI_SOURCE_ID,
            "external_reference_url": source_url,
            "analysis_session_id": str(session_row.id),
            "opencti_report_id": str(report.get("standard_id") or report.get("id") or ""),
            "retrieval": {
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
                "extracted_text_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
                "publication_date_candidates": publication_candidates,
            },
        },
        analyst_notes=json.dumps(
            {
                "source_kind": "file",
                "origin_kind": "opencti-report",
                "opencti_report_id": str(report.get("standard_id") or report.get("id") or ""),
            },
            ensure_ascii=True,
        ),
    )


def _opencti_publication_date(value: Any) -> str:
    clean = str(value or "").strip()
    if not clean:
        return ""
    try:
        return datetime.fromisoformat(clean.replace("Z", "+00:00")).date().isoformat()
    except (TypeError, ValueError):
        match = re.match(r"^(\d{4}-\d{2}-\d{2})", clean)
        return match.group(1) if match else ""


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


def _analysis_session_to_report_input(
    report: AnalysisSession,
    promotion: ReportPromotion,
) -> dict[str, Any]:
    claims = accepted_claims(promotion)
    accepted_narrative = "\n".join(
        str(claim.get("statement") or "").strip() for claim in claims if str(claim.get("statement") or "").strip()
    )[:20_000]
    return {
        "name": (report.name or report.filename or str(report.id))[:255],
        "description": (f"{accepted_narrative}\n\n" if accepted_narrative else "")
        + (f"AdversaryGraph promotion {promotion.id}; manifest {promotion.manifest_checksum}."),
        "published": _promotion_publication_date(claims, promotion),
        "report_types": ["threat-report"],
        "confidence": 60,
        "update": True,
    }


def _promotion_publication_date(
    claims: list[dict[str, Any]],
    promotion: ReportPromotion,
) -> str:
    for claim in claims:
        if claim.get("claim_type") != "publication_date":
            continue
        value = str(claim.get("object") or "").strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return f"{value}T00:00:00.000Z"
    fallback = promotion.promoted_at.isoformat() if promotion.promoted_at else None
    return _date_or_now(fallback)


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
    stmt = (
        insert(IOCSource)
        .values(
            source_id=OPENCTI_SOURCE_ID,
            label=OPENCTI_LABEL,
            kind="opencti",
            url=_base_url(),
            enabled=True,
            last_synced_at=datetime.now(timezone.utc),
            sync_status=status,
            sync_error=error[:4000],
        )
        .on_conflict_do_update(
            index_elements=["source_id"],
            set_={
                "url": _base_url(),
                "last_synced_at": datetime.now(timezone.utc),
                "sync_status": status,
                "sync_error": error[:4000],
            },
        )
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
    for kind in NETWORK_FINGERPRINT_TYPES:
        if kind in lowered:
            return {"type": kind, "value": value.lower()}
    if NETWORK_FINGERPRINT_VALUE_RE.fullmatch(value):
        return {"type": "ja4", "value": value.lower()}
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
        nested_node = entry.get("node")
        raw = nested_node if isinstance(nested_node, dict) else entry
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


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


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
        "ja3": "Unknown",
        "ja3s": "Unknown",
        "ja4": "Unknown",
        "ja4s": "Unknown",
        "ja4h": "Unknown",
        "ja4l": "Unknown",
        "ja4ls": "Unknown",
        "ja4x": "Unknown",
        "ja4ssh": "Unknown",
        "ja4t": "Unknown",
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
