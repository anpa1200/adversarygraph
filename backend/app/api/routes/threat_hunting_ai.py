from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import AliasChoices, BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.analysis import AnalysisSession
from app.models.threat_hunting import ThreatHuntAIAssistance
from app.services import threat_hunting as hunts
from app.services import threat_hunting_ai as hunt_ai
from app.services.auth import TeamUser, audit, require_permission

router = APIRouter(prefix="/threat-hunting/ai", tags=["Threat Hunting AI"])
run_hunt_ai = require_permission("run_analysis")

AIProvider = Literal["local", "claude", "openai", "gemini", "minimax"]
AIStage = Literal["plan", "query", "findings", "outcome"]
AIQueryLanguage = Literal["generic", "sigma", "kql", "spl", "eql", "lucene", "sql", "osquery", "yara", "yaral", "other"]
TLP = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
_VALID_TLP_MARKINGS = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}


class ProviderOut(BaseModel):
    id: AIProvider
    label: str
    model: str
    configured: bool
    available: bool
    status: hunt_ai.AIProviderStatus
    reason: str
    remote: bool
    requires_acknowledgement: bool
    default: bool


class CitationOut(BaseModel):
    source_session_id: UUID | None = None
    source_type: str
    source_ref: str
    quote: str
    start: int | None = None
    end: int | None = None
    verified: bool


class AssistRequest(BaseModel):
    model_config = {"extra": "forbid"}

    provider: AIProvider = "local"
    model: str | None = Field(None, max_length=160)
    stage: AIStage
    hunt_id: UUID | None = None
    context: dict[str, Any] = Field(default_factory=dict, max_length=40)
    target_query_language: AIQueryLanguage | None = None
    analyst_focus: str = Field("", max_length=2_000)
    cloud_processing_acknowledged: bool = False

    @model_validator(mode="after")
    def bound_context(self):
        if len(hunt_ai.canonical_json(self.context)) > 60_000:
            raise ValueError("Threat Hunting AI context exceeds the 60,000 character request limit")
        if self.target_query_language is not None and self.stage != "query":
            raise ValueError("target_query_language is only valid for query assistance")
        return self


class AssistResponse(BaseModel):
    assistance_id: UUID
    provider: AIProvider
    model: str
    stage: AIStage
    lifecycle_status: Literal["suggested"] = "suggested"
    generated_at: datetime
    prompt_version: str
    summary: str
    recommended_actions: list[str]
    questions: list[str]
    evidence_gaps: list[str]
    cautions: list[str]
    suggested_patch: dict[str, Any]
    finding_drafts: list[dict[str, Any]]
    citations: list[CitationOut]
    warnings: list[str]
    requires_human_review: bool = True
    execution_boundary: str = hunt_ai.EXECUTION_BOUNDARY


class HypothesisRequest(BaseModel):
    model_config = {"extra": "forbid", "populate_by_name": True}

    provider: AIProvider = "local"
    model: str | None = Field(None, max_length=160)
    source_session_id: UUID
    source_type: Literal["report", "research"]
    source_title: str = Field("", max_length=500)
    source_ref: str = Field("", max_length=1_000)
    # Retained as an ignored compatibility field for older clients. The stored
    # report marking is authoritative at the provider-egress boundary.
    tlp: TLP | None = Field(
        None,
        validation_alias=AliasChoices("tlp", "source_tlp"),
    )
    analyst_focus: str = Field(
        "",
        max_length=2_000,
        validation_alias=AliasChoices("analyst_focus", "focus"),
    )
    count: int = Field(3, ge=1, le=3)
    cloud_processing_acknowledged: bool = False


class HypothesisCandidateOut(BaseModel):
    title: str
    hypothesis: str
    description: str = ""
    scope: str = ""
    technique_ids: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    telemetry_sources: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    query_language: str = "generic"
    query_text: str = ""
    expected_evidence: str = ""
    false_positive_notes: str = ""
    assumptions: str = ""
    rationale: str
    source_evidence: list[CitationOut] = Field(default_factory=list)


class HypothesisResponse(BaseModel):
    assistance_id: UUID
    provider: AIProvider
    model: str
    lifecycle_status: Literal["suggested"] = "suggested"
    generated_at: datetime
    prompt_version: str
    source_session_id: UUID
    source_type: str
    source_title: str
    source_ref: str
    candidates: list[HypothesisCandidateOut]
    warnings: list[str]
    requires_human_review: bool = True
    execution_boundary: str = hunt_ai.EXECUTION_BOUNDARY


class AssistanceHistoryOut(BaseModel):
    id: UUID
    hunt_id: UUID | None
    source_session_id: UUID | None
    task: str
    stage: str
    lifecycle_status: str
    provider: str
    model: str
    cloud_processing_acknowledged: bool
    prompt_version: str
    effective_tlp: str
    source_refs: list[dict[str, Any]]
    input_checksum: str
    output_checksum: str
    structured_output: dict[str, Any]
    warnings: list[str]
    created_by: str
    created_at: datetime

    model_config = {"from_attributes": True}


@router.get("/providers", response_model=list[ProviderOut])
async def providers(_: TeamUser = Depends(run_hunt_ai)) -> list[dict[str, Any]]:
    return await hunt_ai.provider_catalog_with_readiness()


@router.post("/assist", response_model=AssistResponse)
async def assist(
    body: AssistRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_hunt_ai),
) -> AssistResponse:
    requested_draft_tlp = str(body.context.get("tlp") or "")
    draft_context = hunt_ai.sanitize_client_context(body.stage, body.context)
    target_query_language = body.target_query_language
    if body.stage == "query" and target_query_language is None:
        context_language = str(draft_context.get("query_language") or "")
        target_query_language = context_language if context_language in hunt_ai.QUERY_LANGUAGES else "generic"
    source_session_id: UUID | None = None
    context_warnings: list[str] = []

    if body.hunt_id is None:
        if body.stage != "plan":
            raise HTTPException(422, "Unsaved hunt AI assistance is limited to the plan stage")
        if hunt_ai.provider_is_remote(body.provider) and requested_draft_tlp not in _VALID_TLP_MARKINGS:
            raise HTTPException(422, "Unsaved remote AI assistance requires an explicit valid TLP marking")
        effective_tlp = requested_draft_tlp or "TLP:AMBER"
        if effective_tlp not in _VALID_TLP_MARKINGS:
            effective_tlp = "TLP:AMBER"
        provider_context = {"draft": draft_context, "effective_tlp": effective_tlp}
        source_texts = [hunt_ai.CitationSource("hunt", "draft-context", _source_text(draft_context))]
        source_refs: list[dict[str, Any]] = [{"type": "draft", "ref": "draft-context", "checksum": hunt_ai.checksum(draft_context)}]
        canonical_hunt_id = None
    else:
        hunt = await hunts.get_hunt(db, body.hunt_id)
        findings = await hunts.list_findings(db, hunt.id)
        versions = await hunts.list_query_versions(db, hunt.id)
        effective_tlp = _maximum_tlp([
            hunt.tlp,
            *[finding.tlp for finding in findings],
            requested_draft_tlp,
        ])
        draft_context.pop("tlp", None)
        canonical = _canonical_hunt_context(hunt, findings, versions)
        context_warnings = _hunt_context_warnings(hunt, findings, versions)
        provider_context = {
            "canonical": canonical,
            "unsaved_draft": draft_context,
            "effective_tlp": effective_tlp,
        }
        source_texts = _hunt_citation_sources(hunt, findings, versions)
        source_refs = [
            {"type": "hunt", "ref": str(hunt.id), "updated_at": hunt.updated_at.isoformat() if hunt.updated_at else ""},
            *[{"type": "query_version", "ref": str(version.id), "checksum": version.checksum} for version in versions[:5]],
            *[{"type": "finding", "ref": str(finding.id)} for finding in findings[:50]],
        ]
        canonical_hunt_id = hunt.id

    input_payload = {
        "stage": body.stage,
        "provider_context": provider_context,
        "target_query_language": target_query_language,
        "analyst_focus": body.analyst_focus,
    }
    input_checksum = hunt_ai.checksum(input_payload)
    await db.rollback()  # Never keep a database transaction open across a provider call.

    adapter = hunt_ai.create_adapter(
        body.provider,
        body.model,
        effective_tlp=effective_tlp,
        cloud_processing_acknowledged=body.cloud_processing_acknowledged,
    )
    system, prompt = hunt_ai.assist_prompt(
        body.stage,
        provider_context,
        body.analyst_focus,
        target_query_language=target_query_language,
    )
    cloud_attempt = None
    if hunt_ai.provider_is_remote(adapter.provider):
        cloud_attempt = await _start_cloud_egress_audit(
            db,
            user,
            task="assist",
            stage=body.stage,
            hunt_id=canonical_hunt_id,
            source_session_id=source_session_id,
            provider=adapter.provider,
            model=adapter.model,
            cloud_processing_acknowledged=body.cloud_processing_acknowledged,
            prompt_version=hunt_ai.PROMPT_VERSION,
            effective_tlp=effective_tlp,
            input_checksum=input_checksum,
        )
    raw = await _complete_or_http(
        adapter,
        system,
        prompt,
        db=db,
        user=user,
        cloud_attempt=cloud_attempt,
    )
    if canonical_hunt_id is not None:
        # Every hunt/finding/query mutation locks the parent hunt first. Keep
        # that lock through the state check and assistance insert so the saved
        # checksum and structured suggestion describe one canonical snapshot.
        try:
            fresh_hunt = await hunts.get_hunt(db, canonical_hunt_id, for_update=True)
            fresh_findings = await hunts.list_findings(db, canonical_hunt_id)
            fresh_versions = await hunts.list_query_versions(db, canonical_hunt_id)
            fresh_effective_tlp = _maximum_tlp([
                fresh_hunt.tlp,
                *[finding.tlp for finding in fresh_findings],
                requested_draft_tlp,
            ])
            fresh_context = {
                "canonical": _canonical_hunt_context(fresh_hunt, fresh_findings, fresh_versions),
                "unsaved_draft": draft_context,
                "effective_tlp": fresh_effective_tlp,
            }
            fresh_checksum = hunt_ai.checksum({
                "stage": body.stage,
                "provider_context": fresh_context,
                "target_query_language": target_query_language,
                "analyst_focus": body.analyst_focus,
            })
        except Exception:
            await _finalize_cloud_egress_failure(
                db,
                user,
                cloud_attempt,
                "canonical_context_revalidation_failed",
            )
            raise
        if fresh_checksum != input_checksum:
            await db.rollback()
            await _finalize_cloud_egress_failure(db, user, cloud_attempt, "canonical_context_changed")
            raise HTTPException(409, "Threat hunt changed while AI assistance was being generated; retry with the current hunt state")
    try:
        parsed = hunt_ai.parse_assist_output(raw)
        sanitized, warnings = await hunt_ai.sanitize_assist_output(
            parsed,
            stage=body.stage,
            effective_tlp=effective_tlp,
            source_texts=source_texts,
            target_query_language=target_query_language,
            db=db,
        )
    except hunt_ai.AIOutputError as exc:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "invalid_provider_output")
        raise HTTPException(502, str(exc)) from exc
    except Exception:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "output_validation_failed")
        raise
    warnings = [*context_warnings, *warnings]

    generated_at = datetime.now(timezone.utc)
    response_payload = {
        **sanitized,
        "provider": adapter.provider,
        "model": adapter.model,
        "stage": body.stage,
        "lifecycle_status": "suggested",
        "generated_at": generated_at,
        "prompt_version": hunt_ai.PROMPT_VERSION,
        "warnings": hunt_ai.clean_list(warnings, max_items=20),
        "requires_human_review": True,
        "execution_boundary": hunt_ai.EXECUTION_BOUNDARY,
    }
    try:
        row = await _persist_assistance(
            db,
            user,
            task="assist",
            stage=body.stage,
            hunt_id=canonical_hunt_id,
            source_session_id=source_session_id,
            provider=adapter.provider,
            model=adapter.model,
            cloud_processing_acknowledged=(
                body.cloud_processing_acknowledged and hunt_ai.provider_is_remote(adapter.provider)
            ),
            prompt_version=hunt_ai.PROMPT_VERSION,
            effective_tlp=effective_tlp,
            source_refs=source_refs,
            input_checksum=input_checksum,
            output=response_payload,
            warnings=response_payload["warnings"],
            created_at=generated_at,
            cloud_egress_attempt=cloud_attempt,
        )
    except Exception:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "assistance_persistence_failed")
        raise
    return AssistResponse(assistance_id=row.id, **response_payload)


@router.post("/hypotheses", response_model=HypothesisResponse)
async def hypotheses(
    body: HypothesisRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_hunt_ai),
) -> HypothesisResponse:
    source = await db.get(AnalysisSession, body.source_session_id)
    if not source:
        raise HTTPException(404, "Stored report/research session not found")
    if source.status != "completed":
        raise HTTPException(409, "Stored report/research session must be completed before generating hypotheses")
    source_text = source.source_text or ""
    if not source_text.strip():
        raise HTTPException(422, "Stored report/research session has no source text")
    if source.domain != "enterprise-attack":
        raise HTTPException(422, "Report-to-hypothesis generation currently supports Enterprise ATT&CK sources only")

    source_id = source.id
    source_domain = source.domain
    source_title = (source.name or _safe_source_ref(source.filename or "") or f"Stored source {str(source_id)[:8]}").strip()[:500]
    source_ref = _safe_source_ref(source.filename or str(source_id))
    bounded_text, coverage_warnings = hunt_ai.bounded_source_text(source_text)
    source_hash = hunt_ai.checksum(source_text)
    source_state_checksum = hunt_ai.checksum(_source_state(source))
    stored_tlp = _authoritative_report_tlp(source.tlp)
    effective_tlp = _maximum_tlp([stored_tlp, body.tlp or stored_tlp])
    effective_count = hunt_ai.candidate_limit(body.count)
    if effective_count < body.count:
        coverage_warnings.append(
            f"The operator policy limited hypothesis generation to {effective_count} candidate(s)."
        )
    if body.tlp is not None and body.tlp != effective_tlp:
        coverage_warnings.append(
            "The request could not lower the stored report TLP; the stricter marking controls AI processing."
        )
    citation_source = hunt_ai.CitationSource(
        source_type=body.source_type,
        source_ref=source_ref,
        text=bounded_text,
        source_session_id=source_id,
    )
    input_payload = {
        "source_session_id": str(source_id),
        "source_state_checksum": source_state_checksum,
        "source_coverage_hash": hunt_ai.checksum(bounded_text),
        "source_type": body.source_type,
        "effective_tlp": effective_tlp,
        "analyst_focus": body.analyst_focus,
        "count": effective_count,
    }
    await db.rollback()  # Release the read transaction before external processing.

    adapter = hunt_ai.create_adapter(
        body.provider,
        body.model,
        effective_tlp=effective_tlp,
        cloud_processing_acknowledged=body.cloud_processing_acknowledged,
    )
    system, prompt = hunt_ai.hypothesis_prompt(
        source_title=source_title,
        source_type=body.source_type,
        source_text=bounded_text,
        analyst_focus=body.analyst_focus,
        count=effective_count,
    )
    cloud_attempt = None
    if hunt_ai.provider_is_remote(adapter.provider):
        cloud_attempt = await _start_cloud_egress_audit(
            db,
            user,
            task="hypotheses",
            stage="plan",
            hunt_id=None,
            source_session_id=source_id,
            provider=adapter.provider,
            model=adapter.model,
            cloud_processing_acknowledged=body.cloud_processing_acknowledged,
            prompt_version=hunt_ai.HYPOTHESIS_PROMPT_VERSION,
            effective_tlp=effective_tlp,
            input_checksum=hunt_ai.checksum(input_payload),
        )
    raw = await _complete_or_http(
        adapter,
        system,
        prompt,
        db=db,
        user=user,
        cloud_attempt=cloud_attempt,
    )
    try:
        current_source = (
            await db.execute(
                select(AnalysisSession)
                .where(AnalysisSession.id == source_id)
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        source_context_changed = (
            current_source is None
            or hunt_ai.checksum(_source_state(current_source)) != source_state_checksum
        )
    except Exception:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "source_context_revalidation_failed")
        raise
    if source_context_changed:
        await db.rollback()
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "source_context_changed")
        raise HTTPException(409, "Stored report/research changed while hypotheses were being generated; retry with the current source")
    try:
        parsed = hunt_ai.parse_hypothesis_output(raw)
        candidates, warnings = await hunt_ai.sanitize_hypothesis_output(
            parsed,
            count=effective_count,
            domain=source_domain,
            source=citation_source,
            db=db,
        )
    except hunt_ai.AIOutputError as exc:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "invalid_provider_output")
        raise HTTPException(502, str(exc)) from exc
    except Exception:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "output_validation_failed")
        raise
    warnings = [*coverage_warnings, *warnings]
    generated_at = datetime.now(timezone.utc)
    response_payload = {
        "provider": adapter.provider,
        "model": adapter.model,
        "lifecycle_status": "suggested",
        "generated_at": generated_at,
        "prompt_version": hunt_ai.HYPOTHESIS_PROMPT_VERSION,
        "source_session_id": source_id,
        "source_type": body.source_type,
        "source_title": source_title,
        "source_ref": source_ref,
        "candidates": candidates,
        "warnings": hunt_ai.clean_list(warnings, max_items=20),
        "requires_human_review": True,
        "execution_boundary": hunt_ai.EXECUTION_BOUNDARY,
    }
    try:
        row = await _persist_assistance(
            db,
            user,
            task="hypotheses",
            stage="plan",
            hunt_id=None,
            source_session_id=source_id,
            provider=adapter.provider,
            model=adapter.model,
            cloud_processing_acknowledged=(
                body.cloud_processing_acknowledged and hunt_ai.provider_is_remote(adapter.provider)
            ),
            prompt_version=hunt_ai.HYPOTHESIS_PROMPT_VERSION,
            effective_tlp=effective_tlp,
            source_refs=[{
                "type": body.source_type,
                "ref": str(source_id),
                "source_hash": source_hash,
                "stored_tlp": stored_tlp,
                "tlp": effective_tlp,
                "coverage_chars": len(bounded_text),
                "source_chars": len(source_text),
            }],
            input_checksum=hunt_ai.checksum(input_payload),
            output=response_payload,
            warnings=response_payload["warnings"],
            created_at=generated_at,
            cloud_egress_attempt=cloud_attempt,
        )
    except Exception:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "assistance_persistence_failed")
        raise
    return HypothesisResponse(assistance_id=row.id, **response_payload)


@router.get("/history", response_model=list[AssistanceHistoryOut])
async def history(
    hunt_id: UUID | None = None,
    source_session_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(run_hunt_ai),
) -> list[ThreatHuntAIAssistance]:
    statement = select(ThreatHuntAIAssistance)
    if hunt_id is not None:
        statement = statement.where(ThreatHuntAIAssistance.hunt_id == hunt_id)
    if source_session_id is not None:
        statement = statement.where(ThreatHuntAIAssistance.source_session_id == source_session_id)
    statement = statement.order_by(ThreatHuntAIAssistance.created_at.desc()).limit(limit)
    return list((await db.execute(statement)).scalars().all())


async def _complete_or_http(
    adapter,
    system: str,
    prompt: str,
    *,
    db: AsyncSession,
    user: TeamUser,
    cloud_attempt: CloudEgressAttempt | None,
) -> str:
    try:
        return await hunt_ai.complete(adapter, system, prompt)
    except asyncio.CancelledError:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "request_cancelled")
        raise
    except hunt_ai.AIProviderTimeoutError as exc:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "provider_timeout")
        raise HTTPException(504, "AI provider timed out before returning a suggestion") from exc
    except hunt_ai.AIProviderCallError as exc:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "provider_call_failed")
        raise HTTPException(502, "AI provider failed. Review provider configuration and retry.") from exc
    except Exception:
        await _finalize_cloud_egress_failure(db, user, cloud_attempt, "provider_request_failed")
        raise


CloudEgressAttempt = tuple[UUID, dict[str, Any]]


async def _start_cloud_egress_audit(
    db: AsyncSession,
    user: TeamUser,
    *,
    task: str,
    stage: str,
    hunt_id: UUID | None,
    source_session_id: UUID | None,
    provider: str,
    model: str,
    cloud_processing_acknowledged: bool,
    prompt_version: str,
    effective_tlp: str,
    input_checksum: str,
) -> CloudEgressAttempt:
    """Durably record redacted cloud egress metadata before sending a prompt."""

    if not cloud_processing_acknowledged:
        raise RuntimeError("Cloud egress audit requires explicit processing acknowledgement")
    correlation_id = uuid4()
    details: dict[str, Any] = {
        "task": task,
        "stage": stage,
        "hunt_id": str(hunt_id) if hunt_id else "",
        "source_session_id": str(source_session_id) if source_session_id else "",
        "provider": provider,
        "model": model[:160],
        "cloud_processing_acknowledged": True,
        "prompt_version": prompt_version,
        "effective_tlp": effective_tlp,
        "input_checksum": input_checksum,
        "status": "attempted",
    }
    await audit(
        db,
        user,
        "threat_hunting.ai.egress.attempt",
        "threat_hunting.ai.cloud_egress",
        str(correlation_id),
        details,
    )
    # This commit is the egress gate: no remote request is made unless the
    # redacted attempt and acknowledgement are durable first.
    await db.commit()
    return correlation_id, details


async def _finalize_cloud_egress_failure(
    db: AsyncSession,
    user: TeamUser,
    attempt: CloudEgressAttempt | None,
    error_category: str,
) -> None:
    """Append a terminal egress event without retaining provider error text."""

    if attempt is None:
        return
    await db.rollback()
    correlation_id, attempt_details = attempt
    await audit(
        db,
        user,
        "threat_hunting.ai.egress.failed",
        "threat_hunting.ai.cloud_egress",
        str(correlation_id),
        {
            **attempt_details,
            "status": "failed",
            "error_category": error_category,
        },
    )
    await db.commit()


async def _persist_assistance(
    db: AsyncSession,
    user: TeamUser,
    *,
    task: str,
    stage: str,
    hunt_id: UUID | None,
    source_session_id: UUID | None,
    provider: str,
    model: str,
    cloud_processing_acknowledged: bool,
    prompt_version: str,
    effective_tlp: str,
    source_refs: list[dict[str, Any]],
    input_checksum: str,
    output: dict[str, Any],
    warnings: list[str],
    created_at: datetime,
    cloud_egress_attempt: CloudEgressAttempt | None = None,
) -> ThreatHuntAIAssistance:
    stored_output = _json_safe(output)
    row = ThreatHuntAIAssistance(
        hunt_id=hunt_id,
        source_session_id=source_session_id,
        task=task,
        stage=stage,
        lifecycle_status="suggested",
        provider=provider,
        model=model[:160],
        cloud_processing_acknowledged=cloud_processing_acknowledged,
        prompt_version=prompt_version,
        effective_tlp=effective_tlp,
        source_refs=source_refs,
        input_checksum=input_checksum,
        output_checksum=hunt_ai.checksum(stored_output),
        structured_output=stored_output,
        warnings=warnings,
        created_by=user.name,
        created_at=created_at,
    )
    db.add(row)
    await db.flush()
    correlation_id = cloud_egress_attempt[0] if cloud_egress_attempt is not None else None
    await audit(
        db,
        user,
        "threat_hunting.ai.suggest",
        "threat_hunt_ai_assistance",
        str(row.id),
        {
            "task": task,
            "stage": stage,
            "hunt_id": str(hunt_id) if hunt_id else "",
            "source_session_id": str(source_session_id) if source_session_id else "",
            "provider": provider,
            "model": model[:160],
            "cloud_processing_acknowledged": cloud_processing_acknowledged,
            "prompt_version": prompt_version,
            "effective_tlp": effective_tlp,
            "input_checksum": input_checksum,
            "output_checksum": row.output_checksum,
            "warning_count": len(warnings),
            "lifecycle_status": "suggested",
            "cloud_egress_correlation_id": str(correlation_id) if correlation_id else "",
        },
    )
    if cloud_egress_attempt is not None:
        _, attempt_details = cloud_egress_attempt
        await audit(
            db,
            user,
            "threat_hunting.ai.egress.succeeded",
            "threat_hunting.ai.cloud_egress",
            str(correlation_id),
            {
                **attempt_details,
                "status": "succeeded",
                "assistance_id": str(row.id),
                "output_checksum": row.output_checksum,
            },
        )
    await db.commit()
    return row


def _canonical_hunt_context(hunt, findings, versions) -> dict[str, Any]:
    return {
        "coverage": {
            "query_versions_total": len(versions),
            "query_versions_included": min(len(versions), 5),
            "findings_total": len(findings),
            "findings_included": min(len(findings), 50),
        },
        "hunt": {
            "id": str(hunt.id),
            "title": hunt.title,
            "hypothesis": hunt.hypothesis,
            "description": hunt.description,
            "scope": hunt.scope,
            "status": hunt.status,
            "priority": hunt.priority,
            "technique_ids": hunt.technique_ids or [],
            "tactics": hunt.tactics or [],
            "telemetry_sources": hunt.telemetry_sources,
            "required_fields": hunt.required_fields or [],
            "query_language": hunt.query_language,
            "query_text": (hunt.query_text or "")[:12_000],
            "expected_evidence": hunt.expected_evidence,
            "false_positive_notes": hunt.false_positive_notes,
            "assumptions": hunt.assumptions,
            "result_summary": hunt.result_summary,
            "disposition": hunt.disposition,
            "tlp": hunt.tlp,
            "updated_at": hunt.updated_at,
        },
        "query_versions": [
            {
                "id": str(version.id),
                "version": version.version,
                "language": version.language,
                "query_text": (version.query_text or "")[:6_000],
                "backend_assumptions": (version.backend_assumptions or "")[:4_000],
                "checksum": version.checksum,
            }
            for version in versions[:5]
        ],
        "findings": [
            {
                "id": str(finding.id),
                "title": finding.title,
                "summary": (finding.summary or "")[:3_000],
                "severity": finding.severity,
                "confidence": finding.confidence,
                "status": finding.status,
                "verdict": finding.verdict,
                "tlp": finding.tlp,
                "technique_ids": finding.technique_ids or [],
                "notes": (finding.notes or "")[:2_000],
                "query_version_id": str(finding.query_version_id) if finding.query_version_id else None,
            }
            for finding in findings[:50]
        ],
    }


def _hunt_context_warnings(hunt, findings, versions) -> list[str]:
    warnings: list[str] = []
    if len(hunt.query_text or "") > 12_000:
        warnings.append("Canonical hunt query context was limited to 12,000 characters for AI processing.")
    if len(versions) > 5:
        warnings.append(f"AI context included the newest 5 of {len(versions)} append-only query versions.")
    truncated_version_queries = sum(1 for version in versions[:5] if len(version.query_text or "") > 6_000)
    if truncated_version_queries:
        warnings.append(f"Query text was truncated in {truncated_version_queries} included query version(s).")
    truncated_version_assumptions = sum(1 for version in versions[:5] if len(version.backend_assumptions or "") > 4_000)
    if truncated_version_assumptions:
        warnings.append(f"Backend assumptions were truncated in {truncated_version_assumptions} included query version(s).")
    if len(findings) > 50:
        warnings.append(f"AI context included the newest 50 of {len(findings)} active findings.")
    truncated_summaries = sum(1 for finding in findings[:50] if len(finding.summary or "") > 3_000)
    if truncated_summaries:
        warnings.append(f"Finding summaries were truncated in {truncated_summaries} included finding(s).")
    truncated_notes = sum(1 for finding in findings[:50] if len(finding.notes or "") > 2_000)
    if truncated_notes:
        warnings.append(f"Finding notes were truncated in {truncated_notes} included finding(s).")
    return warnings


def _hunt_citation_sources(hunt, findings, versions) -> list[hunt_ai.CitationSource]:
    sources = [hunt_ai.CitationSource("hunt", str(hunt.id), _source_text({
        "title": hunt.title,
        "hypothesis": hunt.hypothesis,
        "description": hunt.description,
        "scope": hunt.scope,
        "expected_evidence": hunt.expected_evidence,
        "false_positive_notes": hunt.false_positive_notes,
        "assumptions": hunt.assumptions,
        "result_summary": hunt.result_summary,
    }))]
    sources.extend(
        hunt_ai.CitationSource("query_version", str(version.id), version.query_text or "")
        for version in versions[:5]
    )
    sources.extend(
        hunt_ai.CitationSource("finding", str(finding.id), _source_text({
            "title": finding.title,
            "summary": finding.summary,
            "notes": finding.notes,
        }))
        for finding in findings[:50]
    )
    return sources


def _source_text(value: dict[str, Any]) -> str:
    lines: list[str] = []
    for item in value.values():
        if isinstance(item, str) and item.strip():
            lines.append(item.strip())
        elif isinstance(item, list):
            lines.extend(str(part).strip() for part in item if str(part).strip())
    return "\n".join(lines)


def _json_safe(value: dict[str, Any]) -> dict[str, Any]:
    return __import__("json").loads(hunt_ai.canonical_json(value))


def _maximum_tlp(values: list[str]) -> str:
    rank = {
        "TLP:CLEAR": 0,
        "TLP:GREEN": 1,
        "TLP:AMBER": 2,
        "TLP:AMBER+STRICT": 3,
        "TLP:RED": 4,
    }
    return max((value for value in values if value in rank), key=lambda value: rank[value], default="TLP:AMBER")


def _authoritative_report_tlp(value: str | None) -> str:
    allowed = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}
    return value if value in allowed else "TLP:AMBER+STRICT"


def _safe_source_ref(value: str) -> str:
    """Remove URL credentials, query strings, and fragments from displayed provenance."""
    text = re.sub(r"[\x00-\x1f\x7f]", "", value).strip()[:1_000]
    web_ref = text.lower().startswith(("http://", "https://"))
    basename = text.replace("\\", "/").rsplit("/", 1)[-1]
    fallback = re.split(r"[?#]", basename, maxsplit=1)[0][:500]
    try:
        parsed = urlsplit(text)
        host = parsed.hostname
    except (UnicodeError, ValueError):
        return "invalid-source-ref" if web_ref else fallback
    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return "invalid-source-ref" if web_ref else fallback
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path, "", ""))[:1_000]


def _source_state(source: AnalysisSession) -> dict[str, Any]:
    return {
        "id": str(source.id),
        "status": source.status,
        "name": source.name or "",
        "filename": source.filename or "",
        "domain": source.domain,
        "tlp": _authoritative_report_tlp(source.tlp),
        "source_hash": hunt_ai.checksum(source.source_text or ""),
    }
