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

router = APIRouter(prefix="/export", tags=["Export"])

_PDF_HEADERS = {
    "Content-Disposition": 'attachment; filename="threatmapper-report.pdf"',
    "Cache-Control": "no-store",
}


# ── Analysis PDF ──────────────────────────────────────────────────────────────

@router.get("/analysis/{session_id}", response_class=Response)
async def export_analysis_pdf(
    session_id: str,
    db: AsyncSession = Depends(get_session),
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

    from app.services.report_generator import generate_analysis_report

    data = {
        "session_id": session_id,
        "provider":   db_session.llm_provider,
        "model":      db_session.model,
        "domain":     db_session.domain,
        "summary":    res.summary,
        "techniques": res.extracted_techniques,
        "apt_matches":res.apt_matches,
        "apt_hints":  [],
    }

    pdf_bytes = generate_analysis_report(data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={**_PDF_HEADERS,
                 "Content-Disposition": f'attachment; filename="analysis-{session_id[:8]}.pdf"'},
    )


# ── Analysis STIX 2.1 / OpenCTI ───────────────────────────────────────────────

@router.get("/analysis/{session_id}/stix", response_class=Response)
async def export_analysis_stix(
    session_id: str,
    db: AsyncSession = Depends(get_session),
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

    attack_ids = {
        str(item.get("attack_id", "")).upper()
        for item in (res.extracted_techniques or [])
        if item.get("attack_id")
    }
    group_ids = {
        str(item.get("group_attack_id", "")).upper()
        for item in (res.apt_matches or [])
        if item.get("group_attack_id")
    }

    technique_lookup = {}
    if attack_ids:
        rows = await db.execute(
            select(Technique).where(
                Technique.attack_id.in_(sorted(attack_ids)),
                Technique.domain == db_session.domain,
            )
        )
        for technique in rows.scalars().all():
            technique_lookup[technique.attack_id] = {
                "stix_id": technique.stix_id,
                "name": technique.name,
                "description": technique.description,
                "url": technique.url,
            }

    group_lookup = {}
    if group_ids:
        rows = await db.execute(
            select(AptGroup).where(
                AptGroup.attack_id.in_(sorted(group_ids)),
                AptGroup.domain == db_session.domain,
            )
        )
        for group in rows.scalars().all():
            group_lookup[group.attack_id] = {
                "stix_id": group.stix_id,
                "name": group.name,
                "description": group.description,
                "aliases": group.aliases or [],
                "url": group.url,
            }

    from app.services.stix_export import build_analysis_stix_bundle

    bundle = build_analysis_stix_bundle(
        db_session,
        res,
        technique_lookup=technique_lookup,
        group_lookup=group_lookup,
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


@router.post("/layer", response_class=Response)
async def export_layer_pdf(
    req: LayerPdfRequest,
    db: AsyncSession = Depends(get_session),
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
    found_ids = [d["attack_id"] for d in details]
    pdf_bytes = generate_layer_report(found_ids, req.domain, details)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers=_PDF_HEADERS,
    )
