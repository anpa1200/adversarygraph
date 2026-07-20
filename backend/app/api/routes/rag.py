"""Governed hybrid retrieval, RAG assistance, and Navigator proposals."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.attack import AttackVersion
from app.models.rag import (
    RAGAssistance,
    RAGChunk,
    RAGDocument,
    RAGIndexRun,
    RAGNavigatorProposal,
)
from app.models.sector import ClientProfile
from app.services import rag as rag_service
from app.services import rag_ai
from app.services import threat_hunting_ai as governed_ai
from app.services.auth import TeamUser, audit, has_permission, require_permission

router = APIRouter(prefix="/rag", tags=["Unified Intelligence RAG"])
read_rag = require_permission("read")
run_rag = require_permission("run_analysis")
manage_rag = require_permission("manage_feeds")
manage_profiles = require_permission("manage_intel")

AIProvider = Literal["local", "claude", "openai", "gemini", "minimax"]
AttackDomain = Literal[
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
    "atlas",
]
TLP_ORDER = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}


class SearchRequest(BaseModel):
    model_config = {"extra": "forbid"}

    query: str = Field(..., min_length=1, max_length=4_000)
    source_types: list[str] = Field(default_factory=list, max_length=20)
    domain: AttackDomain = "enterprise-attack"
    attack_version: str | None = Field(default=None, min_length=1, max_length=40)
    client_profile_id: int | None = Field(default=None, ge=1)
    limit: int = Field(default=settings.rag_default_result_limit, ge=1, le=25)

    @model_validator(mode="after")
    def validate_sources(self):
        unknown = sorted(set(self.source_types).difference(rag_service.SUPPORTED_SOURCE_TYPES))
        if unknown:
            raise ValueError(f"Unsupported RAG source types: {', '.join(unknown)}")
        self.source_types = list(dict.fromkeys(self.source_types))
        return self


class AssistRequest(SearchRequest):
    provider: AIProvider = "local"
    model: str | None = Field(default=None, max_length=160)
    cloud_processing_acknowledged: bool = False


class ReindexRequest(BaseModel):
    model_config = {"extra": "forbid"}

    source_types: list[str] = Field(default_factory=list, max_length=20)
    include_embeddings: bool = True

    @model_validator(mode="after")
    def validate_sources(self):
        unknown = sorted(set(self.source_types).difference(rag_service.SUPPORTED_SOURCE_TYPES))
        if unknown:
            raise ValueError(f"Unsupported RAG source types: {', '.join(unknown)}")
        self.source_types = list(dict.fromkeys(self.source_types))
        return self


class ProposalConfirmRequest(BaseModel):
    model_config = {"extra": "forbid"}

    proposal_checksum: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    mode: Literal["add", "replace"] = "add"


class ClientProfileWrite(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=2, max_length=255)
    sector: str = Field(..., min_length=2, max_length=120)
    region: str = Field(default="", max_length=120)
    technologies: list[str] = Field(default_factory=list, max_length=100)
    crown_jewels: list[str] = Field(default_factory=list, max_length=100)
    notes: str = Field(default="", max_length=5_000)

    @model_validator(mode="after")
    def normalize_profile(self):
        self.name = self.name.strip()
        self.sector = self.sector.strip()
        self.region = self.region.strip()
        self.notes = self.notes.strip()
        if len(self.name) < 2 or len(self.sector) < 2:
            raise ValueError("Profile name and sector cannot be blank")
        self.technologies = _profile_terms(self.technologies)
        self.crown_jewels = _profile_terms(self.crown_jewels)
        return self


class SearchItemOut(BaseModel):
    chunk_id: str
    document_id: str
    source_type: str
    source_id: str
    source_version: str = "current"
    logical_key: str = ""
    title: str
    excerpt: str
    route: str = ""
    domain: str = ""
    tlp: str
    legal_sensitive: bool = False
    score: float
    lexical_score: float = 0.0
    vector_score: float = 0.0
    exact_match: bool = False
    verified: bool
    retrieval_signals: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    content_hash: str = ""
    source_updated_at: str | None = None
    indexed_at: str | None = None


class SearchResponseOut(BaseModel):
    query: str
    retrieval_mode: str
    items: list[SearchItemOut]
    warnings: list[str]
    corpus_indexed_at: str | None = None


class CitationOut(BaseModel):
    source_ref: str
    source_type: str
    source_id: str
    title: str
    excerpt: str
    route: str = ""
    tlp: str
    legal_sensitive: bool = False
    score: float
    verified: bool


class NavigatorProposalOut(BaseModel):
    id: UUID
    name: str
    domain: str
    attack_version: str
    technique_ids: list[str]
    rationale: str
    proposal_checksum: str
    expires_at: datetime
    requires_confirmation: bool = True


class AssistResponseOut(BaseModel):
    assistance_id: UUID
    provider: str
    model: str
    retrieval_mode: str
    effective_tlp: str
    answer: str
    citations: list[CitationOut]
    entities: list[dict[str, Any]]
    cautions: list[str]
    warnings: list[str]
    navigator_proposal: NavigatorProposalOut | None = None
    requires_human_review: bool = True
    execution_boundary: str = rag_ai.EXECUTION_BOUNDARY


@router.get("/providers")
async def providers(_: TeamUser = Depends(run_rag)) -> list[dict[str, Any]]:
    if not settings.rag_enabled:
        return []
    return await governed_ai.provider_catalog_with_readiness()


@router.get("/status")
async def status(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(read_rag),
) -> dict[str, Any]:
    result = await rag_service.get_index_status(db)
    providers = await governed_ai.provider_catalog_with_readiness() if settings.rag_enabled else []
    latest_payload = result.get("latest_run")
    if isinstance(latest_payload, dict):
        try:
            latest_id = UUID(str(latest_payload.get("id") or ""))
        except ValueError:
            latest_id = None
        if latest_id is not None:
            persisted_run = await db.get(RAGIndexRun, latest_id)
            if persisted_run is not None:
                latest_payload["attempt_count"] = int(
                    persisted_run.attempt_count or 0
                )
                latest_payload["heartbeat_at"] = persisted_run.heartbeat_at
    result.update({
        "enabled": settings.rag_enabled,
        "embedding_enabled": settings.rag_embedding_enabled,
        "embedding_provider": settings.rag_embedding_provider,
        "embedding_model": settings.rag_embedding_model,
        "embedding_dimensions": settings.rag_embedding_dimensions,
        "default_result_limit": settings.rag_default_result_limit,
        "supported_source_types": list(rag_service.SUPPORTED_SOURCE_TYPES),
        "providers": providers,
    })
    document_count = int(result.get("documents_sanitized") or 0)
    result["ready"] = bool(settings.rag_enabled and document_count > 0)
    result.setdefault(
        "retrieval_mode",
        "hybrid" if int(result.get("chunks_embedded") or 0) > 0 else "exact+fts",
    )
    warnings: list[str] = []
    if settings.rag_enabled and document_count == 0:
        warnings.append("The sanitized RAG corpus is empty; queue a reconciliation before searching.")
    if int(result.get("chunks_pending_or_failed") or 0) > 0:
        warnings.append("Some chunks do not have usable embeddings; exact and full-text search remain available.")
    result["warnings"] = warnings
    return result


@router.get("/profiles")
async def client_profiles(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(run_rag),
) -> list[dict[str, Any]]:
    rows = await db.execute(select(ClientProfile).order_by(ClientProfile.name).limit(250))
    return [_profile_payload(row) for row in rows.scalars().all()]


@router.post("/profiles", status_code=201)
async def create_client_profile(
    body: ClientProfileWrite,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_profiles),
) -> dict[str, Any]:
    profile = ClientProfile(**body.model_dump())
    db.add(profile)
    await db.flush()
    await audit(
        db,
        user,
        "rag.profile.create",
        "client_profile",
        str(profile.id),
        {
            "name": profile.name,
            "sector": profile.sector,
            "region": profile.region,
            "technology_count": len(profile.technologies or []),
            "crown_jewel_count": len(profile.crown_jewels or []),
        },
    )
    await db.commit()
    return _profile_payload(profile)


@router.put("/profiles/{profile_id}")
async def update_client_profile(
    profile_id: int,
    body: ClientProfileWrite,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_profiles),
) -> dict[str, Any]:
    profile = await db.get(ClientProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "Client profile not found")
    for key, value in body.model_dump().items():
        setattr(profile, key, value)
    await audit(
        db,
        user,
        "rag.profile.update",
        "client_profile",
        str(profile.id),
        {
            "name": profile.name,
            "sector": profile.sector,
            "region": profile.region,
            "technology_count": len(profile.technologies or []),
            "crown_jewel_count": len(profile.crown_jewels or []),
        },
    )
    await db.commit()
    return _profile_payload(profile)


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_client_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_profiles),
) -> None:
    profile = await db.get(ClientProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "Client profile not found")
    await audit(
        db,
        user,
        "rag.profile.delete",
        "client_profile",
        str(profile.id),
        {"name": profile.name},
    )
    await db.delete(profile)
    await db.commit()


@router.post("/search", response_model=SearchResponseOut)
async def search(
    body: SearchRequest,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(run_rag),
) -> dict[str, Any]:
    _require_enabled()
    if body.client_profile_id is not None:
        await _client_profile_context(db, body.client_profile_id)
        await db.rollback()
    result = await rag_service.hybrid_search(
        db,
        body.query,
        source_types=body.source_types or None,
        domain=body.domain,
        client_profile_id=body.client_profile_id,
        limit=body.limit,
    )
    await _require_current_attack_version(db, body.domain, body.attack_version)
    payload = _search_response_payload(result)
    payload["query"] = body.query
    if body.client_profile_id is None and _looks_like_business_relevance_query(body.query):
        payload.setdefault("warnings", []).append(
            "No saved client profile was selected; prompt text is being used as search context, not authoritative business scope."
        )
    return payload


@router.get("/entity/{source_type}/{source_id:path}")
async def entity(
    source_type: str,
    source_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(run_rag),
) -> dict[str, Any]:
    _require_enabled()
    if source_type not in rag_service.SUPPORTED_SOURCE_TYPES:
        raise HTTPException(404, "Indexed entity not found")
    if not source_id or len(source_id) > 255:
        raise HTTPException(400, "Invalid source ID")
    result = await rag_service.get_indexed_entity(db, source_type, source_id)
    if result is None:
        raise HTTPException(404, "Indexed entity not found")
    return result


@router.post("/assist", response_model=AssistResponseOut)
async def assist(
    body: AssistRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_rag),
) -> dict[str, Any]:
    _require_enabled()
    if body.client_profile_id is not None:
        await _client_profile_context(db, body.client_profile_id)
        await db.rollback()
    result = await rag_service.hybrid_search(
        db,
        body.query,
        source_types=body.source_types or None,
        domain=body.domain,
        client_profile_id=body.client_profile_id,
        limit=body.limit,
    )
    await _require_current_attack_version(db, body.domain, body.attack_version)
    search_payload = _search_response_payload(result)
    items = list(search_payload.get("items") or [])
    if not items:
        raise HTTPException(
            status_code=409,
            detail=(
                "No indexed evidence matched this question. Reindex sources or broaden "
                "the reviewed filters before asking AI."
            ),
        )

    business_context = await _client_profile_context(db, body.client_profile_id)
    if (
        body.client_profile_id is not None
        and result.business_context_checksum
        != rag_service.checksum(business_context or {})
    ):
        raise HTTPException(
            409,
            "The selected business profile changed during retrieval; run the query again",
        )
    sources, context_warnings = rag_ai.build_sources(
        items,
        max_context_chars=settings.rag_max_context_chars,
        question=body.query,
        business_context=business_context,
    )
    if not sources:
        raise HTTPException(409, "Retrieved records contained no safe source excerpts for AI grounding")
    effective_tlp = _effective_tlp(
        items,
        includes_business_profile=business_context is not None,
    )
    adapter = governed_ai.create_adapter(
        body.provider,
        body.model,
        effective_tlp=effective_tlp,
        cloud_processing_acknowledged=body.cloud_processing_acknowledged,
    )
    system, prompt = rag_ai.rag_prompt(
        question=body.query,
        domain=body.domain,
        sources=sources,
        business_context=business_context,
    )
    input_checksum = rag_ai.checksum({
        "query": body.query,
        "domain": body.domain,
        "attack_version": body.attack_version,
        "source_types": body.source_types,
        "client_profile_id": body.client_profile_id,
        "business_context_checksum": rag_ai.checksum(business_context or {}),
        "source_refs": [
            {
                "type": source.source_type,
                "id": source.source_id,
                "chunk_id": source.chunk_id,
                "content_hash": source.content_hash,
                "excerpt_hash": rag_ai.checksum(source.excerpt),
            }
            for source in sources
        ],
    })
    if governed_ai.provider_is_remote(body.provider):
        # Persist the fact of remote egress before the call. Timeouts, malformed
        # output, and later freshness rejection must not erase this audit fact.
        await audit(
            db,
            user,
            "rag.assist.remote_attempt",
            "rag_assistance",
            input_checksum,
            {
                "provider": body.provider,
                "model": str(adapter.model)[:160],
                "effective_tlp": effective_tlp,
                "source_count": len(sources),
                "client_profile_id": body.client_profile_id,
                "cloud_processing_acknowledged": bool(
                    body.cloud_processing_acknowledged
                ),
            },
        )
        await db.commit()
    else:
        # Never retain a database transaction across provider egress.
        await db.rollback()
    try:
        raw = await governed_ai.complete(adapter, system, prompt)
    except governed_ai.AIProviderTimeoutError as exc:
        raise HTTPException(504, "AI provider timed out before returning a grounded answer") from exc
    except governed_ai.AIProviderCallError as exc:
        raise HTTPException(502, "AI provider failed while producing a grounded answer") from exc

    try:
        parsed = rag_ai.parse_output(raw)
        sanitized, output_warnings = await rag_ai.sanitize_output(
            parsed,
            sources=sources,
            domain=body.domain,
            db=db,
        )
    except rag_ai.RAGOutputError as exc:
        raise HTTPException(502, str(exc)) from exc
    stale = await _stale_source_refs(db, items)
    if stale:
        raise HTTPException(409, "Retrieved intelligence changed while the answer was generated; run the query again")
    if body.client_profile_id is not None:
        try:
            current_business_context = await _client_profile_context(
                db,
                body.client_profile_id,
            )
        except HTTPException as exc:
            if exc.status_code == 404:
                raise HTTPException(
                    409,
                    "The selected business profile changed while the answer was generated; run the query again",
                ) from exc
            raise
        if rag_ai.checksum(current_business_context or {}) != rag_ai.checksum(
            business_context or {}
        ):
            raise HTTPException(
                409,
                "The selected business profile changed while the answer was generated; run the query again",
            )

    cloud_ack = bool(
        body.cloud_processing_acknowledged
        and governed_ai.provider_is_remote(body.provider)
    )
    source_refs = [
        {
            "source_ref": source.ref,
            "source_type": source.source_type,
            "source_id": source.source_id,
            "tlp": source.tlp,
            "chunk_id": source.chunk_id,
            "content_hash": source.content_hash,
            "excerpt_hash": rag_ai.checksum(source.excerpt),
        }
        for source in sources
    ]
    warnings = _clean_strings([
        *search_payload.get("warnings", []),
        *context_warnings,
        *output_warnings,
        *(
            ["No saved client profile was selected; business scope in the prompt is non-authoritative."]
            if body.client_profile_id is None and _looks_like_business_relevance_query(body.query)
            else []
        ),
    ], 30)
    proposal_data = sanitized.get("navigator_proposal")
    proposal_version: AttackVersion | None = None
    if proposal_data:
        proposal_version = (
            await db.execute(
                select(AttackVersion).where(
                    AttackVersion.domain == body.domain,
                    AttackVersion.is_latest.is_(True),
                )
            )
        ).scalar_one_or_none()
        if proposal_version is None:
            warnings.append(
                "Navigator proposal was removed because the selected ATT&CK catalog is unavailable."
            )
            proposal_data = None

    stored_output = {
        "answer": sanitized["answer"],
        "citations": sanitized["citations"],
        "cautions": sanitized["cautions"],
        "navigator_proposal": proposal_data,
    }
    assistance = RAGAssistance(
        provider=body.provider,
        model=str(adapter.model)[:160],
        cloud_processing_acknowledged=cloud_ack,
        retrieval_mode=str(search_payload.get("retrieval_mode") or "lexical"),
        effective_tlp=effective_tlp,
        prompt_version=rag_ai.PROMPT_VERSION,
        query_checksum=input_checksum,
        output_checksum=rag_ai.checksum(stored_output),
        filters={
            "source_types": body.source_types,
            "domain": body.domain,
            "attack_version": body.attack_version,
            "client_profile_id": body.client_profile_id,
            "limit": body.limit,
        },
        source_refs=source_refs,
        structured_output=stored_output,
        warnings=warnings,
        created_by=user.name,
    )
    db.add(assistance)
    await db.flush()

    proposal_out: dict[str, Any] | None = None
    if proposal_data and proposal_version is not None:
        cited_refs = {
            str(citation.get("source_ref") or "")
            for citation in sanitized["citations"]
        }
        proposal_source_refs = [
            source_ref
            for source_ref in source_refs
            if source_ref["source_ref"] in cited_refs
        ]
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        proposal_payload = {
            "assistance_id": str(assistance.id),
            "name": proposal_data["name"],
            "domain": body.domain,
            "attack_version": str(proposal_version.version),
            "technique_ids": sorted(proposal_data["technique_ids"]),
            "rationale": proposal_data["rationale"],
            "source_refs": proposal_source_refs,
            "expires_at": expires_at.isoformat(),
        }
        proposal = RAGNavigatorProposal(
            assistance_id=assistance.id,
            status="suggested",
            name=proposal_payload["name"],
            domain=body.domain,
            attack_version=str(proposal_version.version),
            technique_ids=proposal_payload["technique_ids"],
            rationale=proposal_payload["rationale"],
            source_refs=proposal_source_refs,
            proposal_checksum=rag_ai.checksum(proposal_payload),
            created_by=user.name,
            expires_at=expires_at,
        )
        db.add(proposal)
        await db.flush()
        proposal_out = {
            "id": proposal.id,
            "name": proposal.name,
            "domain": proposal.domain,
            "attack_version": proposal.attack_version,
            "technique_ids": proposal.technique_ids,
            "rationale": proposal.rationale,
            "proposal_checksum": proposal.proposal_checksum,
            "expires_at": proposal.expires_at,
            "requires_confirmation": True,
        }

    await audit(
        db,
        user,
        "rag.assist.suggest",
        "rag_assistance",
        str(assistance.id),
        {
            "provider": body.provider,
            "model": str(adapter.model)[:160],
            "cloud_processing_acknowledged": cloud_ack,
            "retrieval_mode": assistance.retrieval_mode,
            "effective_tlp": effective_tlp,
            "source_count": len(source_refs),
            "query_checksum": input_checksum,
            "output_checksum": assistance.output_checksum,
            "proposal_created": proposal_out is not None,
        },
    )
    await db.commit()

    entities = _entities_from_items(items)
    return {
        "assistance_id": assistance.id,
        "provider": assistance.provider,
        "model": assistance.model,
        "retrieval_mode": assistance.retrieval_mode,
        "effective_tlp": assistance.effective_tlp,
        "answer": sanitized["answer"],
        "citations": sanitized["citations"],
        "entities": entities,
        "cautions": sanitized["cautions"],
        "warnings": warnings,
        "navigator_proposal": proposal_out,
    }


@router.post("/proposals/{proposal_id}/confirm")
async def confirm_proposal(
    proposal_id: UUID,
    body: ProposalConfirmRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_rag),
) -> dict[str, Any]:
    _require_enabled()
    row = await db.execute(
        select(RAGNavigatorProposal)
        .where(RAGNavigatorProposal.id == proposal_id)
        .with_for_update()
    )
    proposal = row.scalar_one_or_none()
    if proposal is None:
        raise HTTPException(404, "Navigator proposal not found")
    if proposal.created_by != user.name and not has_permission(user, "manage_intel"):
        raise HTTPException(403, "Only the proposal owner or an intelligence manager can confirm it")
    if proposal.status != "suggested":
        raise HTTPException(409, f"Navigator proposal is already {proposal.status}")
    now = datetime.now(timezone.utc)
    expires_at = proposal.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        proposal.status = "expired"
        await db.commit()
        raise HTTPException(409, "Navigator proposal expired; generate a fresh evidence-backed proposal")
    if proposal.proposal_checksum != body.proposal_checksum:
        raise HTTPException(409, "Navigator proposal checksum does not match the reviewed suggestion")
    if not await _proposal_sources_current(db, list(proposal.source_refs or [])):
        raise HTTPException(
            409,
            "Navigator proposal evidence changed or was withdrawn; generate a fresh grounded proposal",
        )

    version = (
        await db.execute(
            select(AttackVersion).where(
                AttackVersion.domain == proposal.domain,
                AttackVersion.is_latest.is_(True),
            )
        )
    ).scalar_one_or_none()
    if version is None or str(version.version) != proposal.attack_version:
        raise HTTPException(409, "ATT&CK catalog changed; generate a fresh Navigator proposal")
    verified, validation_warnings = await governed_ai.verify_technique_ids(
        db,
        list(proposal.technique_ids or []),
        domain=proposal.domain,
    )
    if verified != list(proposal.technique_ids or []):
        raise HTTPException(409, "Navigator proposal no longer matches the current ATT&CK catalog")

    proposal.status = "confirmed"
    proposal.confirmed_by = user.name
    proposal.confirmation_mode = body.mode
    proposal.confirmed_at = now
    await audit(
        db,
        user,
        "rag.navigator.confirm",
        "rag_navigator_proposal",
        str(proposal.id),
        {
            "mode": body.mode,
            "domain": proposal.domain,
            "attack_version": proposal.attack_version,
            "technique_count": len(verified),
            "proposal_checksum": proposal.proposal_checksum,
        },
    )
    await db.commit()
    return {
        "proposal_id": str(proposal.id),
        "status": "confirmed",
        "mode": body.mode,
        "domain": proposal.domain,
        "attack_version": proposal.attack_version,
        "technique_ids": verified,
        "warnings": validation_warnings,
        "persisted": False,
        "message": "Proposal confirmed for client-side Navigator preview/application; no saved layer was created.",
    }


@router.post("/reindex", status_code=202)
async def reindex(
    body: ReindexRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_rag),
) -> dict[str, Any]:
    _require_enabled()
    from app.tasks.rag import (
        acquire_rag_enqueue_lock,
        rag_index_run_is_stale,
        reconcile_rag,
    )

    await acquire_rag_enqueue_lock(db)
    active_run = await db.scalar(
        select(RAGIndexRun)
        .where(RAGIndexRun.status.in_(("queued", "running")))
        .order_by(RAGIndexRun.created_at.desc())
        .limit(1)
    )
    if active_run is not None:
        should_dispatch = (
            active_run.status == "queued"
            or rag_index_run_is_stale(active_run)
        )
        if should_dispatch:
            await audit(
                db,
                user,
                "rag.index.redispatch",
                "rag_index_run",
                str(active_run.id),
                {
                    "status": active_run.status,
                    "stale": rag_index_run_is_stale(active_run),
                },
            )
        # Release the transaction-scoped enqueue lock before contacting Redis.
        await db.commit()
        if should_dispatch:
            try:
                reconcile_rag.delay(str(active_run.id))
            except Exception as exc:
                # Publication errors can be ambiguous after broker acceptance,
                # and another request may already have redispatched this row.
                # Preserve its recoverable state for the next idempotent pass.
                raise HTTPException(
                    503,
                    "RAG index worker queue is unavailable",
                ) from exc
        response = {
            "run_id": str(active_run.id),
            "status": active_run.status,
            "deduplicated": True,
        }
        if should_dispatch:
            response["redispatched"] = True
        return response
    run = RAGIndexRun(
        status="queued",
        source_types=body.source_types or list(rag_service.SUPPORTED_SOURCE_TYPES),
        include_embeddings=body.include_embeddings and settings.rag_embedding_enabled,
        created_by=user.name,
    )
    db.add(run)
    await db.flush()
    await audit(
        db,
        user,
        "rag.index.queue",
        "rag_index_run",
        str(run.id),
        {
            "source_types": run.source_types,
            "include_embeddings": run.include_embeddings,
        },
    )
    await db.commit()
    try:
        reconcile_rag.delay(str(run.id))
    except Exception as exc:
        # Keep the run queued: the request may have failed after Redis accepted
        # it, and a future API/beat pass can safely redispatch it.
        raise HTTPException(503, "RAG index worker queue is unavailable") from exc
    return {"run_id": str(run.id), "status": "queued"}


@router.get("/index-runs")
async def index_runs(
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(manage_rag),
) -> list[dict[str, Any]]:
    rows = await db.execute(
        select(RAGIndexRun).order_by(RAGIndexRun.created_at.desc()).limit(limit)
    )
    return [
        {
            "id": str(run.id),
            "status": run.status,
            "source_types": run.source_types,
            "include_embeddings": run.include_embeddings,
            "documents_seen": run.documents_seen,
            "documents_created": run.documents_created,
            "documents_updated": run.documents_updated,
            "documents_removed": run.documents_removed,
            "chunks_created": run.chunks_created,
            "embeddings_created": run.embeddings_created,
            "embeddings_failed": run.embeddings_failed,
            "failure_summary": run.failure_summary,
            "created_by": run.created_by,
            "attempt_count": int(run.attempt_count or 0),
            "heartbeat_at": run.heartbeat_at.isoformat() if run.heartbeat_at else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "created_at": run.created_at.isoformat() if run.created_at else None,
        }
        for run in rows.scalars().all()
    ]


async def _client_profile_context(
    db: AsyncSession,
    profile_id: int | None,
) -> dict[str, Any] | None:
    if profile_id is None:
        return None
    profile = await db.get(ClientProfile, profile_id)
    if profile is None:
        raise HTTPException(404, "Client profile not found")
    return {
        "profile_id": profile.id,
        "name": profile.name,
        "sector": profile.sector,
        "region": profile.region,
        "technologies": list(profile.technologies or [])[:100],
        "crown_jewels": list(profile.crown_jewels or [])[:100],
    }


def _search_response_payload(result: rag_service.SearchResponse) -> dict[str, Any]:
    payload = result.to_dict()
    for item in payload.get("items", []):
        if not isinstance(item, dict):
            continue
        item["route"] = str(item.pop("canonical_route", item.get("route") or ""))[:1_000]
    return payload


async def _require_current_attack_version(
    db: AsyncSession,
    domain: str,
    requested_version: str | None,
) -> None:
    if requested_version is None:
        return
    current = (
        await db.execute(
            select(AttackVersion.version).where(
                AttackVersion.domain == domain,
                AttackVersion.is_latest.is_(True),
            )
        )
    ).scalar_one_or_none()
    await db.rollback()
    if current is None:
        raise HTTPException(409, "The selected ATT&CK/ATLAS catalog is unavailable")
    if str(current) != requested_version:
        raise HTTPException(
            409,
            "The RAG corpus and AI proposals use the current ATT&CK/ATLAS catalog. Switch Navigator to the latest version before using the assistant.",
        )


async def _stale_source_refs(db: AsyncSession, items: list[dict[str, Any]]) -> bool:
    """Detect a corpus update between retrieval and accepted provider output."""
    expected = {
        str(item.get("chunk_id")): str(item.get("content_hash") or "")
        for item in items
        if item.get("chunk_id") and item.get("content_hash")
    }
    if not expected:
        return False
    try:
        ids = [UUID(value) for value in expected]
    except ValueError:
        return True
    rows = await db.execute(
        select(RAGChunk.id, RAGChunk.content_hash)
        .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
        .where(
            RAGChunk.id.in_(ids),
            RAGDocument.is_active.is_(True),
            RAGDocument.sanitized.is_(True),
        )
    )
    actual = {str(chunk_id): content_hash for chunk_id, content_hash in rows.all()}
    return actual != expected


async def _proposal_sources_current(
    db: AsyncSession,
    source_refs: list[dict[str, Any]],
) -> bool:
    expected = {
        str(source_ref.get("chunk_id") or ""): str(
            source_ref.get("content_hash") or ""
        )
        for source_ref in source_refs
        if isinstance(source_ref, dict)
        and source_ref.get("chunk_id")
        and source_ref.get("content_hash")
    }
    if not expected or len(expected) != len(source_refs):
        return False
    try:
        ids = [UUID(value) for value in expected]
    except ValueError:
        return False
    rows = await db.execute(
        select(RAGChunk.id, RAGChunk.content_hash)
        .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
        .where(
            RAGChunk.id.in_(ids),
            RAGDocument.is_active.is_(True),
            RAGDocument.sanitized.is_(True),
        )
    )
    actual = {str(chunk_id): content_hash for chunk_id, content_hash in rows.all()}
    return actual == expected


def _effective_tlp(
    items: list[dict[str, Any]],
    *,
    includes_business_profile: bool = False,
) -> str:
    values = [rag_service.normalize_tlp(item.get("tlp")) for item in items]
    # Legal-sensitive content never crosses the cloud boundary even when a
    # source was mistakenly marked with a permissive TLP value.
    if includes_business_profile or any(
        bool(item.get("legal_sensitive")) for item in items
    ):
        values.append("TLP:AMBER+STRICT")
    return max(values or ["TLP:AMBER"], key=lambda value: TLP_ORDER.get(value, 4))


def _entities_from_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entities: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (str(item.get("source_type") or ""), str(item.get("source_id") or ""))
        if not all(key) or key in seen:
            continue
        seen.add(key)
        entities.append({
            "source_type": key[0],
            "source_id": key[1],
            "title": str(item.get("title") or "")[:700],
            "route": str(item.get("route") or "")[:1_000],
            "tlp": str(item.get("tlp") or "TLP:CLEAR"),
            "legal_sensitive": bool(item.get("legal_sensitive")),
            "metadata": dict(item.get("metadata") or {}),
        })
    return entities[:50]


def _profile_payload(profile: ClientProfile) -> dict[str, Any]:
    return {
        "id": profile.id,
        "name": profile.name,
        "sector": profile.sector,
        "region": profile.region,
        "technologies": list(profile.technologies or [])[:100],
        "crown_jewels": list(profile.crown_jewels or [])[:100],
    }


def _profile_terms(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()[:200]
        normalized = text.casefold()
        if text and normalized not in seen:
            seen.add(normalized)
            result.append(text)
    return result[:100]


def _looks_like_business_relevance_query(query: str) -> bool:
    lowered = query.lower()
    return any(
        marker in lowered
        for marker in ("my business", "our business", "my company", "our company", "relevant for", "relevant to")
    )


def _clean_strings(values: list[Any], limit: int) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value).strip()[:1_000]
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _require_enabled() -> None:
    if not settings.rag_enabled:
        raise HTTPException(503, "Unified intelligence RAG is disabled by the operator")
