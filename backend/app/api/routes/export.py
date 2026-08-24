"""
GET  /api/export/analysis/{session_id}       — full PDF report from a stored analysis
GET  /api/export/analysis/{session_id}/stix  — STIX 2.1 bundle for OpenCTI import
POST /api/export/layer                       — PDF report for the current Navigator layer
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import AptGroup, Technique
from app.services.auth import TeamUser, require_permission
from app.services.report_promotion import (
    accepted_claims,
    accepted_actor_ids,
    accepted_technique_ids,
    get_active_report_promotion,
    promotion_allows,
)

router = APIRouter(prefix="/export", tags=["Export"])
export_data = require_permission("export_data")

_PDF_HEADERS = {
    "Content-Disposition": 'attachment; filename="adversarygraph-report.pdf"',
    "Cache-Control": "no-store",
}

_PDF_RESPONSE = {
    200: {
        "description": "Generated PDF document.",
        "content": {
            "application/pdf": {
                "schema": {"type": "string", "format": "binary"},
            },
        },
    },
    202: {
        "description": "The source analysis is not complete yet.",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {"detail": {"type": "string"}},
                    "required": ["detail"],
                },
            },
        },
    },
}

_STIX_RESPONSE = {
    200: {
        "description": "STIX 2.1 bundle.",
        "content": {
            "application/stix+json": {
                "schema": {"type": "string", "format": "binary"},
            },
        },
    },
    202: _PDF_RESPONSE[202],
    409: {
        "description": "The report does not have an active Review Gate promotion.",
    },
}


def _technique_export_query(
    attack_ids: set[str],
    domain: str,
    version_id: int,
):
    return select(Technique).where(
        Technique.attack_id.in_(sorted(attack_ids)),
        Technique.domain == domain,
        Technique.version_id == version_id,
    )


def _group_export_query(
    group_ids: set[str],
    domain: str,
    version_id: int,
):
    return select(AptGroup).where(
        AptGroup.attack_id.in_(sorted(group_ids)),
        AptGroup.domain == domain,
        AptGroup.version_id == version_id,
    )


# ── Analysis PDF ──────────────────────────────────────────────────────────────

@router.get("/analysis/{session_id}", response_class=Response, responses=_PDF_RESPONSE)
@router.post("/analysis/{session_id}", response_class=Response, responses=_PDF_RESPONSE)
async def export_analysis_pdf(
    session_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(export_data),
):
    """Generate a PDF for an existing analysis session."""
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisSession).where(AnalysisSession.id == sid)
    )
    db_session = row.scalar_one_or_none()
    if not db_session:
        raise HTTPException(404, "Session not found")
    if db_session.status != "completed":
        return JSONResponse(
            status_code=202,
            content={"detail": f"Session is {db_session.status}"},
        )

    res_row = await db.execute(
        select(AnalysisResult).where(AnalysisResult.session_id == sid)
    )
    res = res_row.scalar_one_or_none()
    if not res:
        raise HTTPException(404, "No result found for session")

    from app.services.report_review import ReviewNotFoundError, assessment

    try:
        review = await assessment(db, sid)
    except ReviewNotFoundError:
        review = {
            "state": "unreviewed",
            "profile": "",
            "revision": None,
            "policy_version": "",
            "source_char_count": len(db_session.source_text or ""),
            "analyzed_char_count": 0,
            "gates": [],
            "claims": [],
            "readiness": {"ready": False, "blockers": ["review_not_started"]},
        }
    active = await get_active_report_promotion(db, sid)
    export_authorized = (
        active is not None and promotion_allows(active.promotion, "exports")
    )
    promoted_claims = accepted_claims(active.promotion) if export_authorized else []
    promoted_techniques = [
        {
            "attack_id": str(claim.get("attack_id") or "").upper(),
            "name": str(claim.get("object") or claim.get("attack_id") or ""),
            "tactic": str((claim.get("metadata") or {}).get("tactic") or "")
            if isinstance(claim.get("metadata"), dict)
            else "",
            "confidence": (
                (claim.get("metadata") or {}).get("confidence")
                if isinstance(claim.get("metadata"), dict)
                else None
            ) or 0,
            "evidence": str(
                next(
                    (
                        ref.get("excerpt") or ref.get("value") or ""
                        for ref in claim.get("evidence_refs", [])
                        if isinstance(ref, dict)
                    ),
                    "",
                )
            ),
            "review_status": "accepted",
        }
        for claim in promoted_claims
        if claim.get("claim_type") == "procedure" and claim.get("attack_id")
    ]

    from app.services.report_generator import generate_analysis_report

    data = {
        "session_id": session_id,
        "provider":   db_session.llm_provider,
        "model":      db_session.model,
        "domain":     db_session.domain,
        "summary":    "\n".join(
            str(claim.get("statement") or "").strip()
            for claim in promoted_claims
            if str(claim.get("statement") or "").strip()
        ) or res.summary,
        "techniques": promoted_techniques if export_authorized else [
            item for item in (res.extracted_techniques or [])
            if item.get("review_status") == "accepted"
            and item.get("evidence_source") in {"source-text", "analyst-source-text"}
        ],
        # Similarity is an investigation lead and cannot be promoted as actor
        # attribution in an analyst export.
        "apt_matches": [],
        "apt_hints":  [],
        "review_state": review["state"],
        "review": review,
        "authoritative": export_authorized,
    }

    pdf_bytes = generate_analysis_report(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            **_PDF_HEADERS,
            "Content-Disposition": f'attachment; filename="analysis-{session_id[:8]}.pdf"',
            "X-AdversaryGraph-Review-State": str(review["state"]),
            "X-AdversaryGraph-Authoritative": "true" if export_authorized else "false",
        },
    )


# ── Analysis STIX 2.1 / OpenCTI ───────────────────────────────────────────────

@router.get("/analysis/{session_id}/stix", response_class=Response, responses=_STIX_RESPONSE)
async def export_analysis_stix(
    session_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(export_data),
):
    """Generate a STIX 2.1 bundle for OpenCTI import."""
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.id == sid)
    )
    pair = row.first()
    if not pair:
        raise HTTPException(404, "Session not found")

    db_session, res = pair
    if db_session.status != "completed":
        return JSONResponse(
            status_code=202,
            content={"detail": f"Session is {db_session.status}"},
        )
    if not res:
        raise HTTPException(404, "No result found for session")

    active_promotion = await get_active_report_promotion(db, sid)
    if active_promotion is None:
        raise HTTPException(
            409,
            "STIX export requires an active Review Gate promotion",
        )
    if not promotion_allows(active_promotion.promotion, "exports"):
        raise HTTPException(
            409,
            "The active Review Gate promotion does not authorize trusted exports",
        )

    attack_ids = set(accepted_technique_ids(active_promotion.promotion))
    group_ids = set(accepted_actor_ids(active_promotion.promotion))
    from app.api.routes.attack import _resolve_version_id

    version_id = (
        await _resolve_version_id(db, db_session.domain, None)
        if attack_ids or group_ids
        else None
    )

    technique_lookup = {}
    if attack_ids:
        assert version_id is not None
        technique_rows = await db.execute(
            _technique_export_query(attack_ids, db_session.domain, version_id)
        )
        for technique_row in technique_rows.scalars().all():
            technique_lookup[technique_row.attack_id] = {
                "stix_id": technique_row.stix_id,
                "name": technique_row.name,
                "description": technique_row.description,
                "url": technique_row.url,
            }

    group_lookup = {}
    if group_ids:
        assert version_id is not None
        group_rows = await db.execute(
            _group_export_query(group_ids, db_session.domain, version_id)
        )
        for group_row in group_rows.scalars().all():
            group_lookup[group_row.attack_id] = {
                "stix_id": group_row.stix_id,
                "name": group_row.name,
                "description": group_row.description,
                "aliases": group_row.aliases or [],
                "url": group_row.url,
            }

    from app.services.stix_export import build_analysis_stix_bundle

    bundle = build_analysis_stix_bundle(
        db_session,
        res,
        technique_lookup=technique_lookup,
        group_lookup=group_lookup,
        promotion=active_promotion.promotion,
    )
    import json
    payload = json.dumps(bundle, indent=2).encode("utf-8")
    return Response(
        content=payload,
        media_type="application/stix+json",
        headers={
            "Content-Disposition": f'attachment; filename="analysis-{session_id[:8]}-opencti.stix.json"',
            "Cache-Control": "no-store",
        },
    )


# ── Navigator layer PDF ───────────────────────────────────────────────────────

class LayerPdfRequest(BaseModel):
    technique_ids: list[str]
    domain: str = "enterprise-attack"
    version: str | None = None


@router.post("/layer", response_class=Response, responses={200: _PDF_RESPONSE[200]})
async def export_layer_pdf(
    req: LayerPdfRequest,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(export_data),
):
    """Generate a simple PDF listing all techniques in the Navigator layer."""
    if not req.technique_ids:
        raise HTTPException(400, "No techniques provided")

    from app.api.routes.attack import _resolve_version_id
    from app.models.attack import Technique
    from sqlalchemy.orm import selectinload

    ver_id = await _resolve_version_id(db, req.domain, req.version)

    rows = await db.execute(
        select(Technique)
        .where(
            Technique.attack_id.in_([t.upper() for t in req.technique_ids]),
            Technique.version_id == ver_id,
        )
        .options(selectinload(Technique.tactics))
    )
    techs = rows.scalars().all()

    details = [
        {
            "attack_id": t.attack_id,
            "name":      t.name,
            "tactics":   [tc.shortname for tc in t.tactics],
            "platforms": t.platforms or [],
        }
        for t in techs
    ]

    from app.services.report_generator import generate_layer_report

    # Use the DB-normalised IDs so the header count matches the table rows
    found_ids: list[str] = [str(detail["attack_id"]) for detail in details]
    pdf_bytes = generate_layer_report(found_ids, req.domain, details)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers=_PDF_HEADERS,
    )
