"""Unified, provenance-preserving hybrid retrieval for AdversaryGraph.

This module owns retrieval and corpus reconciliation only.  It deliberately
does not call a chat model, mutate analyst workflows, or execute assistant
actions.  Source collectors are explicit allowlists: raw provider payloads,
model responses, and arbitrary JSON metadata are never copied into the corpus.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.asset_surface import AssetRegistryItem
from app.models.attack import (
    AptGroup,
    AptGroupTechnique,
    AttackVersion,
    Campaign,
    CampaignTechnique,
    Technique,
)
from app.models.cve import CVEIOCLink, CVERecord
from app.models.evidence_graph import EvidenceGraphNode
from app.models.ioc import IOCIndicator
from app.models.knowledge import KnowledgeArticle
from app.models.operations import ReportIntake
from app.models.rag import RAGChunk, RAGDocument, RAGIndexRun
from app.models.sector import ActorIntelObservation, ClientProfile
from app.models.threat_radar import (
    ThreatCompanySpace,
    ThreatHuntRequest,
    ThreatSignal,
    ThreatSpaceAsset,
)

logger = logging.getLogger(__name__)

SUPPORTED_SOURCE_TYPES: tuple[str, ...] = (
    "attack_technique",
    "attack_group",
    "attack_campaign",
    "actor_intel",
    "ioc",
    "cve",
    "analysis_report",
    "knowledge",
    "threat_signal",
    "threat_hunt",
    "evidence_node",
    "asset",
)

_TLP_VALUES = {
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
}
_TLP_ORDER = {
    "TLP:CLEAR": 0,
    "TLP:GREEN": 1,
    "TLP:AMBER": 2,
    "TLP:AMBER+STRICT": 3,
    "TLP:RED": 4,
}
_TLP_ALIASES = {
    "CLEAR": "TLP:CLEAR",
    "WHITE": "TLP:CLEAR",
    "TLP:WHITE": "TLP:CLEAR",
    "GREEN": "TLP:GREEN",
    "AMBER": "TLP:AMBER",
    "AMBER+STRICT": "TLP:AMBER+STRICT",
    "AMBER-STRICT": "TLP:AMBER+STRICT",
    "TLP:AMBER-STRICT": "TLP:AMBER+STRICT",
    "RED": "TLP:RED",
}
_REMOTE_BLOCKED_TLPS = {"TLP:AMBER+STRICT", "TLP:RED"}
_TOKEN_RE = re.compile(r"[\w@./:+-]+", re.UNICODE)
_ATTACK_ID_RE = re.compile(
    r"\b(?:TA\d{4}|T\d{4}(?:\.\d{3})?|G\d{4}|C\d{4}|AML\.TA?\d{4}(?:\.\d{3})?)\b",
    re.IGNORECASE,
)
_CVE_ID_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_DOMAIN_RE = re.compile(
    r"(?<![@\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,62})\.)+[a-zA-Z]{2,63}\b"
)
_MAX_QUERY_CHARS = 4_000
_MAX_SEARCH_LIMIT = 100
_MAX_METADATA_LIST = 200
_RRF_WEIGHTS = {"exact": 2.0, "fts": 1.25, "relationship": 1.1, "vector": 1.0}
_PROFILE_QUERY_TERM_LIMIT = 24
_RELATIONSHIP_QUERY_TERM_LIMIT = 32
_BUSINESS_CONTEXT_SEED_TYPES: tuple[str, ...] = (
    "actor_intel",
    "attack_campaign",
    "attack_group",
    "threat_signal",
    "knowledge",
)
_RELATIONSHIP_METADATA_KEYS = frozenset(
    {
        "actor_attack_id",
        "actor_ids",
        "actor_name",
        "actor_names",
        "attack_id",
        "campaign",
        "campaign_ids",
        "campaign_names",
        "cve_id",
        "cve_ids",
        "group_ids",
        "group_names",
        "indicator_refs",
        "malware_family",
        "technique_ids",
    }
)
_EXCERPT_STOPWORDS = frozenset(
    {
        "about",
        "all",
        "and",
        "are",
        "business",
        "company",
        "find",
        "for",
        "from",
        "ioc",
        "iocs",
        "most",
        "our",
        "relevant",
        "show",
        "that",
        "the",
        "their",
        "these",
        "this",
        "those",
        "through",
        "what",
        "with",
    }
)
_EMBEDDING_PROBE_TTL_SECONDS = 60.0
_embedding_probe_cache: tuple[tuple[Any, ...], float, dict[str, Any]] | None = None


class RAGError(RuntimeError):
    """Base error for bounded RAG service failures."""


class EmbeddingConfigurationError(RAGError):
    """The configured embedding provider cannot be used safely."""


class EmbeddingValidationError(RAGError):
    """An embedding response did not match the configured contract."""


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Normalized, allowlisted representation of one source row."""

    source_type: str
    source_id: str
    source_version: str
    logical_key: str
    title: str
    body: str
    canonical_route: str = ""
    domain: str = ""
    tlp: str = "TLP:AMBER+STRICT"
    source_updated_at: datetime | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    space_id: UUID | None = None
    legal_sensitive: bool = False
    sanitized: bool = True

    def __post_init__(self) -> None:
        if self.source_type not in SUPPORTED_SOURCE_TYPES:
            raise ValueError(f"Unsupported RAG source type: {self.source_type}")
        for label, value, maximum in (
            ("source_id", self.source_id, 255),
            ("source_version", self.source_version, 120),
            ("logical_key", self.logical_key, 500),
            ("title", self.title, 700),
            ("canonical_route", self.canonical_route, 1_000),
            ("domain", self.domain, 80),
        ):
            if not isinstance(value, str):
                raise TypeError(f"{label} must be a string")
            if (
                label in {"source_id", "source_version", "logical_key", "title"}
                and not value.strip()
            ):
                raise ValueError(f"{label} cannot be empty")
            if len(value) > maximum:
                raise ValueError(f"{label} exceeds {maximum} characters")
        if not self.sanitized:
            raise ValueError("Unsanitized source records cannot enter the RAG corpus")
        object.__setattr__(self, "tlp", normalize_tlp(self.tlp))
        object.__setattr__(self, "metadata", _safe_metadata(self.metadata))

    @property
    def rendered_text(self) -> str:
        header = _compose_sections(
            (
                ("Title", self.title),
                ("Source type", self.source_type.replace("_", " ")),
                ("Identifier", self.logical_key),
                ("Domain", self.domain),
            )
        )
        return normalize_text(f"{header}\n\n{self.body}")

    @property
    def content_hash(self) -> str:
        return checksum(
            {
                "source_type": self.source_type,
                "source_id": self.source_id,
                "source_version": self.source_version,
                "logical_key": self.logical_key,
                "title": self.title,
                "canonical_route": self.canonical_route,
                "domain": self.domain,
                "tlp": self.tlp,
                "space_id": str(self.space_id) if self.space_id else None,
                "legal_sensitive": self.legal_sensitive,
                "sanitized": self.sanitized,
                "metadata": self.metadata,
                "content": self.rendered_text,
            }
        )


@dataclass(frozen=True, slots=True)
class SearchItem:
    document_id: str
    chunk_id: str
    source_type: str
    source_id: str
    source_version: str
    logical_key: str
    title: str
    canonical_route: str
    domain: str
    tlp: str
    legal_sensitive: bool
    excerpt: str
    score: float
    lexical_score: float
    vector_score: float
    exact_match: bool
    retrieval_signals: tuple[str, ...]
    content_hash: str
    source_updated_at: datetime | None
    indexed_at: datetime | None
    metadata: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "chunk_id": self.chunk_id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "source_version": self.source_version,
            "logical_key": self.logical_key,
            "title": self.title,
            "canonical_route": self.canonical_route,
            "route": self.canonical_route,
            "domain": self.domain,
            "tlp": self.tlp,
            "legal_sensitive": self.legal_sensitive,
            "excerpt": self.excerpt,
            "score": self.score,
            "lexical_score": self.lexical_score,
            "vector_score": self.vector_score,
            "exact_match": self.exact_match,
            "verified": True,
            "retrieval_signals": list(self.retrieval_signals),
            "content_hash": self.content_hash,
            "source_updated_at": (
                self.source_updated_at.isoformat() if self.source_updated_at else None
            ),
            "indexed_at": self.indexed_at.isoformat() if self.indexed_at else "",
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class SearchResponse:
    items: tuple[SearchItem, ...]
    retrieval_mode: str
    warnings: tuple[str, ...]
    corpus_indexed_at: datetime | None
    business_context_checksum: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "retrieval_mode": self.retrieval_mode,
            "warnings": list(self.warnings),
            "corpus_indexed_at": (
                self.corpus_indexed_at.isoformat() if self.corpus_indexed_at else None
            ),
        }


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    status: str
    source_types: tuple[str, ...]
    documents_seen: int
    documents_created: int
    documents_updated: int
    documents_removed: int
    chunks_created: int
    embeddings_created: int
    embeddings_failed: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "source_types": list(self.source_types),
            "documents_seen": self.documents_seen,
            "documents_created": self.documents_created,
            "documents_updated": self.documents_updated,
            "documents_removed": self.documents_removed,
            "chunks_created": self.chunks_created,
            "embeddings_created": self.embeddings_created,
            "embeddings_failed": self.embeddings_failed,
        }


@dataclass(frozen=True, slots=True)
class ClientContext:
    name: str
    sector: str
    region: str
    technologies: tuple[str, ...]
    crown_jewels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BusinessContext:
    """Server-owned business context derived from a saved profile or company space."""

    kind: str
    identifier: str
    context: ClientContext
    checksum: str
    payload: Mapping[str, Any]


@dataclass(slots=True)
class _Candidate:
    chunk: RAGChunk
    document: RAGDocument
    signals: set[str] = field(default_factory=set)
    mode_scores: dict[str, float] = field(default_factory=dict)
    fused_score: float = 0.0
    profile_score: float = 0.0


def normalize_tlp(value: Any, default: str = "TLP:AMBER+STRICT") -> str:
    """Return one canonical TLP 2.0 label; unknown labels fail closed."""

    normalized_default = (
        str(default or "TLP:AMBER+STRICT").strip().upper().replace(" ", "")
    )
    normalized_default = _TLP_ALIASES.get(normalized_default, normalized_default)
    if normalized_default not in _TLP_VALUES:
        normalized_default = "TLP:AMBER+STRICT"
    if value is None:
        return normalized_default
    normalized = str(value).strip().upper().replace(" ", "")
    normalized = _TLP_ALIASES.get(normalized, normalized)
    if normalized and not normalized.startswith("TLP:"):
        normalized = _TLP_ALIASES.get(normalized, f"TLP:{normalized}")
    return normalized if normalized in _TLP_VALUES else normalized_default


def _strictest_tlp(values: Iterable[Any], *, default: str = "TLP:CLEAR") -> str:
    """Return the most restrictive normalized marking in ``values``."""

    normalized = [normalize_tlp(value) for value in values]
    fallback = normalize_tlp(default)
    return max(normalized or [fallback], key=_TLP_ORDER.__getitem__)


def checksum(value: Any) -> str:
    """Return a deterministic SHA-256 checksum for text or JSON-compatible data."""

    if isinstance(value, str):
        payload = value.encode("utf-8")
    elif isinstance(value, bytes):
        payload = value
    else:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        ).encode("utf-8")
    return sha256(payload).hexdigest()


def normalize_text(value: Any) -> str:
    """Normalize source text without changing words or evidence offsets later."""

    text = (
        str(value or "").replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    )
    paragraphs: list[str] = []
    for paragraph in re.split(r"\n\s*\n", text):
        collapsed = re.sub(r"[\t\f\v ]+", " ", paragraph)
        collapsed = re.sub(r" *\n *", "\n", collapsed).strip()
        if collapsed:
            paragraphs.append(collapsed)
    return "\n\n".join(paragraphs)


def chunk_text(
    text: str, max_chars: int | None = None, overlap_chars: int | None = None
) -> list[str]:
    """Deterministically split normalized text at readable boundaries."""

    maximum = int(max_chars if max_chars is not None else settings.rag_chunk_chars)
    overlap = int(
        overlap_chars if overlap_chars is not None else settings.rag_chunk_overlap_chars
    )
    if maximum < 128:
        raise ValueError("max_chars must be at least 128")
    if overlap < 0 or overlap >= maximum:
        raise ValueError(
            "overlap_chars must be non-negative and smaller than max_chars"
        )

    source = normalize_text(text)
    if not source:
        return []
    if len(source) <= maximum:
        return [source]

    chunks: list[str] = []
    start = 0
    minimum_break = max(1, int(maximum * 0.55))
    while start < len(source):
        hard_end = min(len(source), start + maximum)
        end = hard_end
        if hard_end < len(source):
            window = source[start:hard_end]
            candidates = [
                window.rfind("\n\n", minimum_break),
                window.rfind(". ", minimum_break),
                window.rfind("; ", minimum_break),
                window.rfind("\n", minimum_break),
                window.rfind(" ", minimum_break),
            ]
            boundary = max(candidates)
            if boundary >= minimum_break:
                end = (
                    start
                    + boundary
                    + (2 if window[boundary : boundary + 2] in {". ", "; "} else 0)
                )
        chunk = source[start:end].strip()
        if chunk and (not chunks or chunk != chunks[-1]):
            chunks.append(chunk)
        if end >= len(source):
            break
        next_start = max(start + 1, end - overlap)
        while next_start < end and source[next_start].isspace():
            next_start += 1
        start = next_start
    return chunks


def reciprocal_rank_fusion(
    rankings: Mapping[str, Sequence[str]],
    *,
    k: int = 60,
    weights: Mapping[str, float] | None = None,
) -> dict[str, float]:
    """Fuse ordered result identifiers, ignoring duplicates within one ranking."""

    if k <= 0:
        raise ValueError("k must be positive")
    scores: dict[str, float] = {}
    for mode, identifiers in rankings.items():
        weight = float((weights or {}).get(mode, 1.0))
        if not math.isfinite(weight) or weight < 0:
            raise ValueError("ranking weights must be finite and non-negative")
        seen: set[str] = set()
        rank = 0
        for raw_identifier in identifiers:
            identifier = str(raw_identifier)
            if not identifier or identifier in seen:
                continue
            seen.add(identifier)
            rank += 1
            scores[identifier] = scores.get(identifier, 0.0) + weight / (k + rank)
    return scores


def business_relevance_score(text: str, context: ClientContext) -> float:
    """Return a deterministic, bounded business-context relevance boost."""

    haystack = f" {_search_normalize(text)} "
    score = 0.0
    if _contains_term(haystack, context.region):
        score += 0.30
    if _contains_term(haystack, context.sector):
        score += 0.25
    score += min(
        0.30,
        sum(0.15 for term in context.technologies if _contains_term(haystack, term)),
    )
    score += min(
        0.15,
        sum(0.15 for term in context.crown_jewels if _contains_term(haystack, term)),
    )
    return round(min(1.0, score), 6)


class OpenAICompatibleEmbeddingAdapter:
    """Strict adapter for local or explicitly enabled OpenAI embeddings."""

    def __init__(
        self,
        *,
        provider: str,
        model: str,
        dimensions: int,
        client: Any | None = None,
    ) -> None:
        normalized_provider = provider.strip().lower()
        if normalized_provider not in {"local", "openai"}:
            raise EmbeddingConfigurationError(
                "Embedding provider must be 'local' or 'openai'"
            )
        if not model.strip() or len(model) > 160:
            raise EmbeddingConfigurationError("Embedding model is missing or invalid")
        if dimensions <= 0 or dimensions > 65_535:
            raise EmbeddingConfigurationError(
                "Embedding dimensions are outside the supported range"
            )
        if (
            normalized_provider == "openai"
            and not settings.threat_hunting_ai_cloud_enabled
        ):
            raise EmbeddingConfigurationError(
                "Cloud embedding processing is disabled by operator policy"
            )

        self.provider = normalized_provider
        self.model = model.strip()
        self.dimensions = int(dimensions)
        self.is_remote = normalized_provider == "openai"
        self._client = client or self._build_client()

    def _build_client(self) -> Any:
        from openai import AsyncOpenAI

        if self.provider == "openai":
            if not settings.openai_api_key:
                raise EmbeddingConfigurationError(
                    "OpenAI embedding credentials are not configured"
                )
            return AsyncOpenAI(
                api_key=settings.openai_api_key, timeout=45.0, max_retries=1
            )
        base_url = str(settings.local_llm_base_url or "").strip().rstrip("/")
        if not base_url:
            raise EmbeddingConfigurationError(
                "Local embedding endpoint is not configured"
            )
        from app.services.threat_hunting_ai import local_ai_endpoint_is_private

        if not local_ai_endpoint_is_private(base_url):
            raise EmbeddingConfigurationError(
                "Local embedding endpoint must use a loopback, private IP, or private service DNS origin"
            )
        return AsyncOpenAI(
            api_key=settings.local_llm_api_key or "local",
            base_url=base_url,
            timeout=45.0,
            max_retries=1,
        )

    async def embed_texts(self, texts: Sequence[str]) -> list[list[float]]:
        bounded = [normalize_text(text) for text in texts]
        if not bounded or any(not text for text in bounded):
            raise EmbeddingValidationError("Embedding input cannot be empty")
        request: dict[str, Any] = {"model": self.model, "input": bounded}
        if self.provider == "openai":
            request["dimensions"] = self.dimensions
        response = await self._client.embeddings.create(**request)
        data = list(getattr(response, "data", []) or [])
        if len(data) != len(bounded):
            raise EmbeddingValidationError(
                "Embedding response count does not match input count"
            )

        indexed: dict[int, Any] = {}
        for position, item in enumerate(data):
            item_index = _response_value(item, "index", position)
            if (
                isinstance(item_index, bool)
                or not isinstance(item_index, int)
                or item_index in indexed
            ):
                raise EmbeddingValidationError("Embedding response indexes are invalid")
            indexed[item_index] = item
        if set(indexed) != set(range(len(bounded))):
            raise EmbeddingValidationError("Embedding response indexes are incomplete")

        return [
            self._validate_vector(_response_value(indexed[index], "embedding", None))
            for index in range(len(bounded))
        ]

    async def embed_query(self, query: str) -> list[float]:
        vectors = await self.embed_texts([query])
        return vectors[0]

    def _validate_vector(self, raw_vector: Any) -> list[float]:
        if (
            not isinstance(raw_vector, (list, tuple))
            or len(raw_vector) != self.dimensions
        ):
            raise EmbeddingValidationError(
                f"Embedding vector must contain exactly {self.dimensions} values"
            )
        vector: list[float] = []
        for value in raw_vector:
            if isinstance(value, bool):
                raise EmbeddingValidationError(
                    "Embedding vector contains a non-numeric value"
                )
            try:
                numeric = float(value)
            except (TypeError, ValueError) as exc:
                raise EmbeddingValidationError(
                    "Embedding vector contains a non-numeric value"
                ) from exc
            if not math.isfinite(numeric):
                raise EmbeddingValidationError(
                    "Embedding vector contains a non-finite value"
                )
            vector.append(numeric)
        if not any(abs(value) > 1e-15 for value in vector):
            raise EmbeddingValidationError("Embedding vector cannot be all zeros")
        return vector


def create_embedding_adapter() -> OpenAICompatibleEmbeddingAdapter:
    return OpenAICompatibleEmbeddingAdapter(
        provider=settings.rag_embedding_provider,
        model=settings.rag_embedding_model,
        dimensions=settings.rag_embedding_dimensions,
    )


async def probe_embedding_readiness(*, force: bool = False) -> dict[str, Any]:
    """Verify the configured embedding contract against the private endpoint."""

    global _embedding_probe_cache
    configured = bool(
        settings.rag_embedding_model
        and settings.rag_embedding_dimensions
        and (settings.rag_embedding_provider != "local" or settings.local_llm_base_url)
    )
    if not settings.rag_embedding_enabled:
        _embedding_probe_cache = None
        return {
            "enabled": False,
            "configured": configured,
            "available": False,
            "status": "disabled",
            "provider": settings.rag_embedding_provider,
            "model": settings.rag_embedding_model,
            "dimensions": settings.rag_embedding_dimensions,
            "reason": "Semantic embeddings are disabled; exact and full-text retrieval remain available.",
        }

    key = (
        settings.rag_embedding_provider,
        settings.rag_embedding_model,
        settings.rag_embedding_dimensions,
        str(settings.local_llm_base_url or ""),
    )
    now = time.monotonic()
    cached = _embedding_probe_cache
    if (
        not force
        and cached is not None
        and cached[0] == key
        and now - cached[1] < _EMBEDDING_PROBE_TTL_SECONDS
    ):
        return dict(cached[2])

    try:
        adapter = create_embedding_adapter()
        vector = await adapter.embed_query(
            "AdversaryGraph private embedding readiness probe"
        )
        result = {
            "enabled": True,
            "configured": True,
            "available": True,
            "status": "ready",
            "provider": adapter.provider,
            "model": adapter.model,
            "dimensions": len(vector),
            "reason": "The configured embedding endpoint returned a valid vector.",
        }
    except Exception as exc:
        result = {
            "enabled": True,
            "configured": configured,
            "available": False,
            "status": "unavailable",
            "provider": settings.rag_embedding_provider,
            "model": settings.rag_embedding_model,
            "dimensions": settings.rag_embedding_dimensions,
            "reason": (
                f"The configured embedding endpoint failed its contract probe "
                f"({type(exc).__name__})."
            ),
        }
    _embedding_probe_cache = (key, now, dict(result))
    return result


async def collect_source_records(
    db: AsyncSession, source_types: Sequence[str] | None = None
) -> list[SourceRecord]:
    """Collect the selected allowlisted source types in deterministic order."""

    selected = _validate_source_types(source_types)
    collectors = {
        "attack_technique": _collect_attack_techniques,
        "attack_group": _collect_attack_groups,
        "attack_campaign": _collect_attack_campaigns,
        "actor_intel": _collect_actor_intel,
        "ioc": _collect_iocs,
        "cve": _collect_cves,
        "analysis_report": _collect_analysis_reports,
        "knowledge": _collect_knowledge,
        "threat_signal": _collect_threat_signals,
        "threat_hunt": _collect_threat_hunts,
        "evidence_node": _collect_evidence_nodes,
        "asset": _collect_assets,
    }
    records: list[SourceRecord] = []
    for source_type in selected:
        records.extend(await collectors[source_type](db))

    deduplicated: dict[tuple[str, str, str], SourceRecord] = {}
    for record in records:
        key = (record.source_type, record.source_id, record.source_version)
        current = deduplicated.get(key)
        if current is None or record.content_hash > current.content_hash:
            deduplicated[key] = record
    return [deduplicated[key] for key in sorted(deduplicated)]


async def reconcile_corpus(
    db: AsyncSession,
    run: RAGIndexRun | None,
    source_types: Sequence[str] | None = None,
    include_embeddings: bool = True,
) -> ReconcileResult:
    """Idempotently reconcile selected sources and tombstone disappeared rows."""

    selected = _validate_source_types(source_types)
    now = datetime.now(timezone.utc)
    if run is None:
        run = RAGIndexRun(
            source_types=list(selected), include_embeddings=bool(include_embeddings)
        )
        db.add(run)
    run.status = "running"
    run.source_types = list(selected)
    run.include_embeddings = bool(include_embeddings)
    run.started_at = now
    run.completed_at = None
    run.failure_summary = ""
    for counter in (
        "documents_seen",
        "documents_created",
        "documents_updated",
        "documents_removed",
        "chunks_created",
        "embeddings_created",
        "embeddings_failed",
    ):
        setattr(run, counter, 0)
    await db.flush()

    try:
        records = await collect_source_records(db, selected)
        run.documents_seen = len(records)

        existing = await _load_existing_documents(db, selected)
        existing_by_key = {
            (doc.source_type, doc.source_id, doc.source_version): doc
            for doc in existing
        }
        seen: set[tuple[str, str, str]] = set()
        pending_embeddings: list[RAGChunk] = []

        for record in records:
            key = (record.source_type, record.source_id, record.source_version)
            seen.add(key)
            document = existing_by_key.get(key)
            changed = (
                document is None
                or _document_needs_update(document, record)
                or not document.chunks
            )
            if document is None:
                document = _new_document(record, now)
                db.add(document)
                existing_by_key[key] = document
                run.documents_created += 1
            else:
                _apply_record(document, record, now if changed else None)
                if changed:
                    run.documents_updated += 1

            if changed:
                changed_chunks = _reconcile_document_chunks(
                    document,
                    record,
                    embedding_requested=bool(
                        include_embeddings and settings.rag_embedding_enabled
                    ),
                )
                run.chunks_created += changed_chunks
            if include_embeddings and settings.rag_embedding_enabled:
                pending_embeddings.extend(
                    chunk for chunk in document.chunks if _embedding_needed(chunk)
                )

        for document in existing:
            key = (document.source_type, document.source_id, document.source_version)
            if key not in seen and document.is_active:
                document.is_active = False
                document.indexed_at = now
                run.documents_removed += 1

        if pending_embeddings:
            # Make the sanitized lexical corpus durable and release database
            # locks before contacting the embedding service. A later run can
            # safely retry chunks left pending by a provider/process failure.
            await db.flush()
            await db.commit()

            async def persist_heartbeat() -> None:
                run.heartbeat_at = datetime.now(timezone.utc)
                await db.commit()

            created, failed = await _embed_chunks(
                pending_embeddings,
                heartbeat=persist_heartbeat,
            )
            run.embeddings_created = created
            run.embeddings_failed = failed

        run.status = "degraded" if run.embeddings_failed else "completed"
        if run.embeddings_failed:
            run.failure_summary = f"Embedding failed or was policy-blocked for {run.embeddings_failed} chunks."
        run.completed_at = datetime.now(timezone.utc)
        await db.flush()
        return ReconcileResult(
            status=run.status,
            source_types=selected,
            documents_seen=run.documents_seen,
            documents_created=run.documents_created,
            documents_updated=run.documents_updated,
            documents_removed=run.documents_removed,
            chunks_created=run.chunks_created,
            embeddings_created=run.embeddings_created,
            embeddings_failed=run.embeddings_failed,
        )
    except Exception as exc:
        run.status = "failed"
        run.failure_summary = f"{type(exc).__name__}: corpus reconciliation failed"[
            :500
        ]
        run.completed_at = datetime.now(timezone.utc)
        try:
            await db.flush()
        # Preserve the original reconciliation error if the failed transaction
        # can no longer flush its bounded status update.
        except Exception as status_exc:
            logger.warning(
                "RAG reconciliation status flush failed error=%s",
                type(status_exc).__name__,
            )
        raise


async def hybrid_search(
    db: AsyncSession,
    query: str,
    source_types: Sequence[str] | None = None,
    domain: str | None = None,
    client_profile_id: int | None = None,
    company_space_id: UUID | None = None,
    limit: int = 12,
) -> SearchResponse:
    """Run exact, PostgreSQL FTS, and optional vector retrieval with RRF."""

    normalized_query = normalize_text(query)
    if not normalized_query:
        raise ValueError("query cannot be empty")
    if len(normalized_query) > _MAX_QUERY_CHARS:
        raise ValueError(f"query exceeds {_MAX_QUERY_CHARS} characters")
    if limit < 1 or limit > _MAX_SEARCH_LIMIT:
        raise ValueError(f"limit must be between 1 and {_MAX_SEARCH_LIMIT}")
    selected = _validate_source_types(source_types)
    normalized_domain = str(domain or "").strip()
    if len(normalized_domain) > 80:
        raise ValueError("domain exceeds 80 characters")

    candidate_limit = min(200, max(40, limit * 8))
    warnings: list[str] = []
    modes: list[str] = []

    context: ClientContext | None = None
    business_context_checksum: str | None = None
    profile_query = ""
    business_context = await load_business_context(
        db,
        client_profile_id=client_profile_id,
        company_space_id=company_space_id,
    )
    if business_context is not None:
        context = business_context.context
        business_context_checksum = business_context.checksum
        profile_query = _profile_search_query(context)
        # Loading business context opens a transaction. Release it before local
        # embedding-provider call; the assist route rechecks this context after
        # generation before it accepts the result.
        await db.rollback()

    # Obtain the query vector without holding a database transaction across
    # embedding-provider egress.
    query_embedding: list[float] | None = None
    if settings.rag_embedding_enabled:
        try:
            adapter = create_embedding_adapter()
            if adapter.is_remote and business_context is not None:
                raise EmbeddingConfigurationError(
                    "Business-context queries require the private embedding provider"
                )
            query_embedding = await adapter.embed_query(
                _embedding_query(normalized_query, context)
            )
        except Exception as exc:
            warnings.append(
                f"Vector retrieval unavailable ({type(exc).__name__}); exact and full-text results were used."
            )

    exact = await _exact_candidates(
        db,
        normalized_query,
        selected,
        normalized_domain,
        candidate_limit,
        space_id=company_space_id,
    )
    if exact:
        modes.append("exact")
    lexical = await _fts_candidates(
        db,
        normalized_query,
        selected,
        normalized_domain,
        candidate_limit,
        profile_query=profile_query,
        space_id=company_space_id,
    )
    modes.append("fts")

    vector: list[_Candidate] = []
    if query_embedding is not None:
        # Do not swallow PostgreSQL errors: a failed vector statement can
        # abort the transaction and must be visible to readiness checks.
        vector = await _vector_candidates(
            db,
            query_embedding,
            selected,
            normalized_domain,
            candidate_limit,
            space_id=company_space_id,
        )
        modes.append("vector")

    ranking_candidates = {"exact": exact, "fts": lexical, "vector": vector}
    rankings = {
        mode: _unique_document_ids(rows)
        for mode, rows in ranking_candidates.items()
        if rows
    }
    fused = reciprocal_rank_fusion(rankings, weights=_RRF_WEIGHTS)
    candidates = _merge_candidates(ranking_candidates, fused)

    relationship_targets = _relationship_target_types(normalized_query, selected)
    if relationship_targets:
        seeds = sorted(
            candidates.values(),
            key=lambda item: (item.fused_score, item.document.logical_key),
            reverse=True,
        )[:24]
        if context is not None and profile_query:
            context_seeds = await _fts_candidates(
                db,
                profile_query,
                _BUSINESS_CONTEXT_SEED_TYPES,
                normalized_domain,
                24,
                signal="business-context",
                natural_language_fallback=False,
                space_id=company_space_id,
            )
            existing_seed_ids = {str(seed.document.id) for seed in seeds}
            seeds.extend(
                seed
                for seed in context_seeds
                if str(seed.document.id) not in existing_seed_ids
            )
        relationship_query = _relationship_search_query(seeds)
        if relationship_query:
            relationship = await _fts_candidates(
                db,
                relationship_query,
                relationship_targets,
                normalized_domain,
                candidate_limit,
                signal="relationship",
                natural_language_fallback=False,
                space_id=company_space_id,
            )
            if relationship:
                ranking_candidates["relationship"] = relationship
                modes.append("relationship")
                warnings.append(
                    "Relationship expansion matched shared stored entity identifiers; "
                    "validate the cited relationship evidence before operational use. "
                    "Link-based relevance is not proof of targeting or compromise."
                )
                rankings = {
                    mode: _unique_document_ids(rows)
                    for mode, rows in ranking_candidates.items()
                    if rows
                }
                fused = reciprocal_rank_fusion(rankings, weights=_RRF_WEIGHTS)
                candidates = _merge_candidates(ranking_candidates, fused)

    for candidate in candidates.values():
        if context:
            searchable = f"{candidate.document.title}\n{candidate.chunk.content}\n{_metadata_search_text(candidate.document.metadata_)}"
            candidate.profile_score = business_relevance_score(searchable, context)

    ordered = sorted(
        candidates.values(),
        key=lambda item: (
            item.fused_score + item.profile_score * 0.02,
            item.fused_score,
            item.document.logical_key,
        ),
        reverse=True,
    )[:limit]
    excerpt_query = f"{normalized_query} {profile_query}".strip()
    items = tuple(_candidate_to_item(candidate, excerpt_query) for candidate in ordered)
    corpus_indexed_at = await db.scalar(
        select(func.max(RAGDocument.indexed_at)).where(
            *_search_filters(selected, normalized_domain, company_space_id),
        )
    )
    if corpus_indexed_at is None:
        warnings.append(
            "The sanitized RAG corpus is empty or has not been reconciled yet."
        )
    retrieval_mode = "+".join(modes) if modes else "none"
    return SearchResponse(
        items=items,
        retrieval_mode=retrieval_mode,
        warnings=tuple(dict.fromkeys(warnings)),
        corpus_indexed_at=corpus_indexed_at,
        business_context_checksum=business_context_checksum,
    )


async def get_index_status(db: AsyncSession) -> dict[str, Any]:
    """Return bounded corpus/index health without exposing document content."""

    active = int(
        await db.scalar(
            select(func.count(RAGDocument.id)).where(RAGDocument.is_active.is_(True))
        )
        or 0
    )
    tombstoned = int(
        await db.scalar(
            select(func.count(RAGDocument.id)).where(RAGDocument.is_active.is_(False))
        )
        or 0
    )
    sanitized = int(
        await db.scalar(
            select(func.count(RAGDocument.id)).where(
                RAGDocument.is_active.is_(True),
                RAGDocument.sanitized.is_(True),
            )
        )
        or 0
    )
    active_chunk_filters = (
        RAGDocument.is_active.is_(True),
        RAGDocument.sanitized.is_(True),
    )
    chunk_count = int(
        await db.scalar(
            select(func.count(RAGChunk.id))
            .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
            .where(*active_chunk_filters)
        )
        or 0
    )
    embedded = int(
        await db.scalar(
            select(func.count(RAGChunk.id))
            .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
            .where(*active_chunk_filters, RAGChunk.embedding_status == "complete")
        )
        or 0
    )
    pending = int(
        await db.scalar(
            select(func.count(RAGChunk.id))
            .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
            .where(
                *active_chunk_filters,
                RAGChunk.embedding_status.in_(("pending", "failed", "blocked")),
            )
        )
        or 0
    )
    indexed_at = await db.scalar(
        select(func.max(RAGDocument.indexed_at)).where(RAGDocument.is_active.is_(True))
    )
    source_rows = (
        await db.execute(
            select(RAGDocument.source_type, func.count(RAGDocument.id))
            .where(RAGDocument.is_active.is_(True))
            .group_by(RAGDocument.source_type)
            .order_by(RAGDocument.source_type)
        )
    ).all()
    latest_run = await db.scalar(
        select(RAGIndexRun).order_by(RAGIndexRun.created_at.desc()).limit(1)
    )
    return {
        "enabled": bool(settings.rag_enabled),
        "embedding_enabled": bool(settings.rag_embedding_enabled),
        "embedding_provider": settings.rag_embedding_provider,
        "embedding_model": settings.rag_embedding_model,
        "embedding_dimensions": settings.rag_embedding_dimensions,
        "document_count": sanitized,
        "documents": sanitized,
        "documents_active": active,
        "documents_sanitized": sanitized,
        "documents_tombstoned": tombstoned,
        "chunks": chunk_count,
        "chunks_embedded": embedded,
        "chunks_pending_or_failed": pending,
        "ready_embeddings": bool(embedded > 0),
        "source_counts": {
            str(source_type): int(count) for source_type, count in source_rows
        },
        "corpus_indexed_at": indexed_at,
        "latest_run": _index_run_dict(latest_run) if latest_run else None,
    }


async def get_indexed_entity(
    db: AsyncSession,
    source_type: str,
    source_id: str,
    *,
    space_id: UUID | None = None,
) -> dict[str, Any] | None:
    """Return one active sanitized indexed entity and its provenance chunks."""

    selected = _validate_source_types([source_type])
    normalized_id = str(source_id or "").strip()
    if not normalized_id or len(normalized_id) > 255:
        raise ValueError("source_id is missing or invalid")
    document = await db.scalar(
        select(RAGDocument)
        .options(selectinload(RAGDocument.chunks))
        .where(
            RAGDocument.source_type == selected[0],
            RAGDocument.source_id == normalized_id,
            RAGDocument.is_active.is_(True),
            RAGDocument.sanitized.is_(True),
            (
                RAGDocument.space_id.is_(None)
                if space_id is None
                else or_(
                    RAGDocument.space_id.is_(None),
                    RAGDocument.space_id == space_id,
                )
            ),
        )
        .order_by(RAGDocument.indexed_at.desc())
        .limit(1)
    )
    if document is None:
        return None
    return {
        "document_id": str(document.id),
        "source_type": document.source_type,
        "source_id": document.source_id,
        "source_version": document.source_version,
        "logical_key": document.logical_key,
        "title": document.title,
        "canonical_route": document.canonical_route,
        "domain": document.domain,
        "tlp": normalize_tlp(document.tlp),
        "space_id": str(document.space_id) if document.space_id else None,
        "legal_sensitive": bool(document.legal_sensitive),
        "sanitized": bool(document.sanitized),
        "content_hash": document.content_hash,
        "source_updated_at": document.source_updated_at,
        "indexed_at": document.indexed_at,
        "metadata": dict(document.metadata_ or {}),
        "chunk_count": len(document.chunks),
        "chunks_truncated": len(document.chunks) > 50,
        "chunks": [
            {
                "id": str(chunk.id),
                "ordinal": chunk.ordinal,
                "content": chunk.content,
                "content_hash": chunk.content_hash,
                "token_count": chunk.token_count,
                "embedding_status": chunk.embedding_status,
            }
            for chunk in sorted(document.chunks, key=lambda item: item.ordinal)[:50]
        ],
    }


async def _collect_attack_techniques(db: AsyncSession) -> list[SourceRecord]:
    rows = (
        await db.execute(
            select(Technique, AttackVersion)
            .options(
                selectinload(Technique.tactics),
                selectinload(Technique.group_usages).selectinload(
                    AptGroupTechnique.group
                ),
            )
            .join(AttackVersion, AttackVersion.id == Technique.version_id)
            .where(
                AttackVersion.is_latest.is_(True), Technique.is_deprecated.is_(False)
            )
            .order_by(Technique.domain, Technique.attack_id)
        )
    ).all()
    records: list[SourceRecord] = []
    for technique, attack_version in rows:
        tactic_ids = _safe_values([tactic.attack_id for tactic in technique.tactics])
        tactic_names = _safe_values([tactic.name for tactic in technique.tactics])
        actor_ids = _safe_values(
            [usage.group.attack_id for usage in technique.group_usages if usage.group]
        )
        actor_names = _safe_values(
            [usage.group.name for usage in technique.group_usages if usage.group]
        )
        actor_usage = _safe_values(
            [
                _compose_sections(
                    (
                        (
                            "Actor",
                            (
                                f"{usage.group.attack_id} — {usage.group.name}"
                                if usage.group
                                else ""
                            ),
                        ),
                        ("Stored ATT&CK usage", usage.use_description),
                    )
                )
                for usage in technique.group_usages
                if usage.group
            ]
        )
        records.append(
            SourceRecord(
                source_type="attack_technique",
                source_id=technique.attack_id,
                source_version=_attack_source_version(
                    technique.domain, attack_version.version
                ),
                logical_key=technique.attack_id,
                title=f"{technique.attack_id} — {technique.name}",
                body=_compose_sections(
                    (
                        ("Description", technique.description),
                        ("Parent technique", technique.parent_attack_id),
                        ("Platforms", _safe_values(technique.platforms)),
                        ("Data sources", _safe_values(technique.data_sources)),
                        ("Tactics", tactic_names),
                        ("Detection", technique.detection),
                        ("Used by actors", actor_usage),
                    )
                ),
                canonical_route=f"/navigator?technique={quote(technique.attack_id)}",
                domain=technique.domain,
                tlp="TLP:CLEAR",
                source_updated_at=attack_version.ingested_at,
                metadata={
                    "attack_id": technique.attack_id,
                    "stix_id": technique.stix_id,
                    "is_subtechnique": bool(technique.is_subtechnique),
                    "parent_attack_id": technique.parent_attack_id or "",
                    "platforms": _safe_values(technique.platforms),
                    "data_sources": _safe_values(technique.data_sources),
                    "tactic_ids": tactic_ids,
                    "tactics": tactic_names,
                    "actor_ids": actor_ids,
                    "actor_names": actor_names,
                },
            )
        )
    return records


async def _collect_attack_groups(db: AsyncSession) -> list[SourceRecord]:
    rows = (
        await db.execute(
            select(AptGroup, AttackVersion)
            .options(
                selectinload(AptGroup.technique_usages).selectinload(
                    AptGroupTechnique.technique
                ),
                selectinload(AptGroup.campaigns),
            )
            .join(AttackVersion, AttackVersion.id == AptGroup.version_id)
            .where(AttackVersion.is_latest.is_(True))
            .order_by(AptGroup.domain, AptGroup.attack_id)
        )
    ).all()
    records: list[SourceRecord] = []
    for group, attack_version in rows:
        technique_usages = [
            usage
            for usage in group.technique_usages
            if usage.technique and not usage.technique.is_deprecated
        ]
        technique_ids = _safe_values(
            [usage.technique.attack_id for usage in technique_usages]
        )
        technique_names = _safe_values(
            [usage.technique.name for usage in technique_usages]
        )
        campaign_ids = _safe_values(
            [campaign.attack_id for campaign in group.campaigns]
        )
        campaign_names = _safe_values([campaign.name for campaign in group.campaigns])
        usage_evidence = _safe_values(
            [
                _compose_sections(
                    (
                        (
                            "Technique",
                            f"{usage.technique.attack_id} — {usage.technique.name}",
                        ),
                        ("Stored ATT&CK usage", usage.use_description),
                    )
                )
                for usage in technique_usages
            ]
        )
        records.append(
            SourceRecord(
                source_type="attack_group",
                source_id=group.attack_id,
                source_version=_attack_source_version(
                    group.domain, attack_version.version or group.attack_version
                ),
                logical_key=group.attack_id,
                title=f"{group.attack_id} — {group.name}",
                body=_compose_sections(
                    (
                        ("Description", group.description),
                        ("Aliases", _safe_values(group.aliases)),
                        ("Techniques", usage_evidence),
                        (
                            "Attributed campaigns",
                            [
                                f"{campaign.attack_id} — {campaign.name}"
                                for campaign in group.campaigns
                            ],
                        ),
                        ("Created", group.created),
                        ("Modified", group.modified),
                    )
                ),
                canonical_route=f"/apt?group={quote(group.attack_id)}",
                domain=group.domain,
                tlp="TLP:CLEAR",
                source_updated_at=attack_version.ingested_at,
                metadata={
                    "attack_id": group.attack_id,
                    "stix_id": group.stix_id,
                    "aliases": _safe_values(group.aliases),
                    "technique_ids": technique_ids,
                    "technique_names": technique_names,
                    "campaign_ids": campaign_ids,
                    "campaign_names": campaign_names,
                },
            )
        )
    return records


async def _collect_attack_campaigns(db: AsyncSession) -> list[SourceRecord]:
    rows = (
        await db.execute(
            select(Campaign, AttackVersion)
            .options(
                selectinload(Campaign.technique_usages).selectinload(
                    CampaignTechnique.technique
                ),
                selectinload(Campaign.groups),
            )
            .join(AttackVersion, AttackVersion.id == Campaign.version_id)
            .where(AttackVersion.is_latest.is_(True))
            .order_by(Campaign.domain, Campaign.attack_id)
        )
    ).all()
    records: list[SourceRecord] = []
    for campaign, attack_version in rows:
        technique_usages = [
            usage
            for usage in campaign.technique_usages
            if usage.technique and not usage.technique.is_deprecated
        ]
        technique_ids = _safe_values(
            [usage.technique.attack_id for usage in technique_usages]
        )
        technique_names = _safe_values(
            [usage.technique.name for usage in technique_usages]
        )
        group_ids = _safe_values([group.attack_id for group in campaign.groups])
        group_names = _safe_values([group.name for group in campaign.groups])
        usage_evidence = _safe_values(
            [
                _compose_sections(
                    (
                        (
                            "Technique",
                            f"{usage.technique.attack_id} — {usage.technique.name}",
                        ),
                        ("Stored ATT&CK usage", usage.use_description),
                    )
                )
                for usage in technique_usages
            ]
        )
        records.append(
            SourceRecord(
                source_type="attack_campaign",
                source_id=campaign.attack_id,
                source_version=_attack_source_version(
                    campaign.domain, attack_version.version
                ),
                logical_key=campaign.attack_id,
                title=f"{campaign.attack_id} — {campaign.name}",
                body=_compose_sections(
                    (
                        ("Description", campaign.description),
                        (
                            "Attributed actors",
                            [
                                f"{group.attack_id} — {group.name}"
                                for group in campaign.groups
                            ],
                        ),
                        ("Techniques", usage_evidence),
                        ("First seen", campaign.first_seen),
                        ("Last seen", campaign.last_seen),
                    )
                ),
                canonical_route=f"/apt?campaign={quote(campaign.attack_id)}&tab=campaigns",
                domain=campaign.domain,
                tlp="TLP:CLEAR",
                source_updated_at=attack_version.ingested_at,
                metadata={
                    "attack_id": campaign.attack_id,
                    "stix_id": campaign.stix_id,
                    "technique_ids": technique_ids,
                    "technique_names": technique_names,
                    "group_ids": group_ids,
                    "group_names": group_names,
                },
            )
        )
    return records


async def _collect_actor_intel(db: AsyncSession) -> list[SourceRecord]:
    """Index stored sector/region/technology observations without raw feed payloads."""

    rows = list(
        (
            await db.execute(
                select(ActorIntelObservation).order_by(
                    ActorIntelObservation.actor_name,
                    ActorIntelObservation.observation_type,
                    ActorIntelObservation.id,
                )
            )
        )
        .scalars()
        .all()
    )
    records: list[SourceRecord] = []
    for observation in rows:
        actor_id = str(observation.actor_attack_id or "").strip()
        actor_label = (
            f"{actor_id} — {observation.actor_name}"
            if actor_id
            else observation.actor_name
        )
        records.append(
            SourceRecord(
                source_type="actor_intel",
                source_id=str(observation.id),
                source_version="current",
                logical_key=f"actor-observation:{observation.id}",
                title=f"{actor_label}: {observation.observation_type} — {observation.value}"[
                    :700
                ],
                body=_compose_sections(
                    (
                        ("Actor", actor_label),
                        ("Observation type", observation.observation_type),
                        ("Observed value", observation.value),
                        ("Confidence", observation.confidence),
                        ("First seen", observation.first_seen),
                        ("Last seen", observation.last_seen),
                        ("Available source evidence", observation.evidence),
                        ("Source", observation.source_id),
                        (
                            "Source reference",
                            _safe_source_reference(observation.source_url),
                        ),
                    )
                ),
                canonical_route=(
                    f"/apt?group={quote(actor_id)}&tab=overview"
                    if actor_id
                    else "/sector-intel"
                ),
                # IntelSource has no per-observation distribution marking. Keep
                # these records local-only unless a future ingestion path stores
                # and validates explicit TLP metadata.
                tlp="TLP:AMBER+STRICT",
                source_updated_at=observation.created_at,
                metadata={
                    "actor_attack_id": actor_id,
                    "actor_name": observation.actor_name,
                    "actor_ids": [actor_id] if actor_id else [],
                    "actor_names": [observation.actor_name],
                    "observation_type": observation.observation_type,
                    "observation_value": observation.value,
                    "normalized_value": observation.normalized_value,
                    "confidence": int(observation.confidence or 0),
                    "source_id": observation.source_id,
                    "source_reference": _safe_source_reference(observation.source_url),
                },
            )
        )
    return records


async def _collect_iocs(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (
            await db.execute(
                select(IOCIndicator)
                .options(selectinload(IOCIndicator.actor_links))
                .order_by(IOCIndicator.id)
            )
        )
        .scalars()
        .all()
    )
    records: list[SourceRecord] = []
    for indicator in rows:
        if not str(indicator.value or "").strip():
            continue
        actor_ids = _safe_values(
            [link.actor_attack_id for link in indicator.actor_links]
        )
        actor_names = _safe_values([link.actor_name for link in indicator.actor_links])
        actor_evidence = _safe_values(
            [
                _compose_sections(
                    (
                        ("Actor", f"{link.actor_attack_id} — {link.actor_name}"),
                        ("Relationship", link.relationship_type),
                        ("Confidence", link.confidence),
                        ("Source", link.source_id),
                        ("Available source evidence", link.evidence),
                    )
                )
                for link in indicator.actor_links
            ]
        )
        records.append(
            SourceRecord(
                source_type="ioc",
                source_id=str(indicator.id),
                source_version="current",
                # Exact observable lookup uses the indexed logical key. Indicator
                # type remains explicit in title/body/metadata.
                logical_key=str(indicator.value).casefold()[:500],
                title=f"{indicator.indicator_type}: {indicator.value}"[:700],
                body=_compose_sections(
                    (
                        ("Indicator", indicator.value),
                        ("Type", indicator.indicator_type),
                        ("Description", indicator.description),
                        ("Malware family", indicator.malware_family),
                        ("Campaign", indicator.campaign),
                        ("ATT&CK techniques", _safe_values(indicator.technique_ids)),
                        ("Linked actors", actor_evidence),
                        ("Tags", _safe_values(indicator.tags)),
                        ("First seen", indicator.first_seen),
                        ("Last seen", indicator.last_seen),
                        ("Confidence", indicator.confidence),
                        ("Source", indicator.source_id),
                    )
                ),
                canonical_route=f"/ioc-library/{indicator.id}",
                # Unknown/malformed markings fail closed. Valid legacy labels such
                # as "clear" remain accepted by normalize_tlp.
                tlp=normalize_tlp(indicator.tlp),
                source_updated_at=indicator.updated_at,
                metadata={
                    "indicator_type": indicator.indicator_type,
                    "indicator_value": indicator.value,
                    "indicator_refs": [f"ioc-record-{indicator.id}"],
                    "source_id": indicator.source_id,
                    "confidence": int(indicator.confidence or 0),
                    "malware_family": indicator.malware_family or "",
                    "campaign": indicator.campaign or "",
                    "technique_ids": _safe_values(indicator.technique_ids),
                    "actor_ids": actor_ids,
                    "actor_names": actor_names,
                    "tags": _safe_values(indicator.tags),
                    "first_seen": indicator.first_seen or "",
                    "last_seen": indicator.last_seen or "",
                },
            )
        )
    return records


async def _collect_cves(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (
            await db.execute(
                select(CVERecord)
                .options(
                    selectinload(CVERecord.technique_links),
                    selectinload(CVERecord.ioc_links).selectinload(
                        CVEIOCLink.indicator
                    ),
                    selectinload(CVERecord.actor_links),
                )
                .order_by(CVERecord.cve_id)
            )
        )
        .scalars()
        .all()
    )
    records: list[SourceRecord] = []
    for cve in rows:
        if not str(cve.cve_id or "").strip():
            continue
        technique_ids = _safe_values([link.attack_id for link in cve.technique_links])
        actor_ids = _safe_values([link.actor_attack_id for link in cve.actor_links])
        actor_names = _safe_values([link.actor_name for link in cve.actor_links])
        indicator_refs = _safe_values(
            [f"ioc-record-{link.indicator_id}" for link in cve.ioc_links]
        )
        linked_ioc_tlps: list[str] = []
        unresolved_relationship_provenance = bool(cve.actor_links)
        for link in cve.ioc_links:
            if link.indicator is None:
                unresolved_relationship_provenance = True
                continue
            linked_ioc_tlps.append(normalize_tlp(link.indicator.tlp))
        if unresolved_relationship_provenance:
            # Actor relationships do not currently retain the originating IOC
            # identifier or its handling marking. Missing IOC rows are equally
            # unverifiable. Keep their evidence local until that provenance is
            # represented explicitly instead of assuming it is public.
            linked_ioc_tlps.append("TLP:AMBER+STRICT")
        relationship_evidence_is_sensitive = bool(cve.ioc_links or cve.actor_links)
        effective_tlp = _strictest_tlp(linked_ioc_tlps)
        technique_evidence = _safe_values(
            [
                _compose_sections(
                    (
                        ("Technique", link.attack_id),
                        ("Relationship", link.relationship_type),
                        ("Confidence", link.confidence),
                        ("Source", link.source_id),
                        ("Available source evidence", link.evidence),
                    )
                )
                for link in cve.technique_links
            ]
        )
        actor_evidence = _safe_values(
            [
                _compose_sections(
                    (
                        ("Actor", f"{link.actor_attack_id} — {link.actor_name}"),
                        ("Relationship", link.relationship_type),
                        ("Confidence", link.confidence),
                        ("Source", link.source_id),
                        ("Available source evidence", link.evidence),
                    )
                )
                for link in cve.actor_links
            ]
        )
        ioc_evidence = _safe_values(
            [
                _compose_sections(
                    (
                        ("Indicator record", f"ioc-record-{link.indicator_id}"),
                        ("Relationship", link.relationship_type),
                        ("Confidence", link.confidence),
                        ("Source", link.source_id),
                        ("Available source evidence", link.evidence),
                    )
                )
                for link in cve.ioc_links
            ]
        )
        records.append(
            SourceRecord(
                source_type="cve",
                source_id=cve.cve_id,
                source_version="current",
                logical_key=cve.cve_id,
                title=f"{cve.cve_id} — {cve.cvss_severity or 'unrated'}",
                body=_compose_sections(
                    (
                        ("Description", cve.description),
                        ("Status", cve.vuln_status),
                        ("CVSS score", cve.cvss_score),
                        ("CVSS severity", cve.cvss_severity),
                        ("CVSS vector", cve.cvss_vector),
                        ("CWEs", _safe_values(cve.cwe_ids)),
                        ("Affected CPEs", _safe_values(cve.cpe_matches)),
                        ("Known exploited", bool(cve.known_exploited)),
                        ("Linked ATT&CK techniques", technique_evidence),
                        ("Linked actors", actor_evidence),
                        ("Linked indicator records", ioc_evidence),
                        ("KEV due date", cve.kev_due_date),
                        ("KEV action", cve.kev_required_action),
                        ("Published", cve.published),
                        ("Last modified", cve.last_modified),
                        ("Tags", _safe_values(cve.tags)),
                    )
                ),
                canonical_route=f"/cve?search={quote(cve.cve_id)}",
                tlp=effective_tlp,
                # Relationship evidence may contain restricted observables or
                # analyst narrative, but the current link schema has no dedicated
                # legal-sensitivity flag. Fail closed until it does.
                legal_sensitive=relationship_evidence_is_sensitive,
                source_updated_at=cve.updated_at,
                metadata={
                    "cve_id": cve.cve_id,
                    "source_id": cve.source_id or "",
                    "cvss_score": cve.cvss_score or "",
                    "cvss_severity": cve.cvss_severity or "",
                    "known_exploited": bool(cve.known_exploited),
                    "technique_ids": technique_ids,
                    "actor_ids": actor_ids,
                    "actor_names": actor_names,
                    "indicator_refs": indicator_refs,
                    "cwe_ids": _safe_values(cve.cwe_ids),
                    "cpe_matches": _safe_values(cve.cpe_matches),
                    "tags": _safe_values(cve.tags),
                },
            )
        )
    return records


async def _collect_analysis_reports(db: AsyncSession) -> list[SourceRecord]:
    intake_rows = list((await db.execute(select(ReportIntake))).scalars().all())
    intakes_by_session: dict[str, ReportIntake] = {}
    for intake in intake_rows:
        if not isinstance(intake, ReportIntake):
            continue
        session_id = str((intake.provenance or {}).get("analysis_session_id") or "")
        if not session_id and intake.analyst_notes:
            try:
                notes = json.loads(intake.analyst_notes)
                session_id = str(notes.get("analysis_session_id") or "")
            except (TypeError, ValueError, json.JSONDecodeError):
                session_id = ""
        if session_id:
            intakes_by_session[session_id] = intake
    rows = (
        await db.execute(
            select(AnalysisSession, AnalysisResult)
            .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
            .where(AnalysisSession.status == "completed")
            .order_by(AnalysisSession.created_at, AnalysisSession.id)
        )
    ).all()
    records: list[SourceRecord] = []
    for report, result in rows:
        intake = intakes_by_session.get(str(report.id))
        technique_ids = _extract_named_values(
            result.extracted_techniques if result else [], ("attack_id", "technique_id")
        )
        actor_ids = _extract_named_values(
            result.apt_matches if result else [],
            ("group_attack_id", "attack_id", "name"),
        )
        title = str(
            report.name or report.filename or f"Analysis report {report.id}"
        ).strip()
        body = _compose_sections(
            (
                ("Summary", result.summary if result else ""),
                ("Source report", report.source_text),
                ("ATT&CK techniques", technique_ids),
                ("Actor matches", actor_ids),
                ("Normalized tags", _safe_values(intake.tags if intake else [])),
                (
                    "Extracted indicators",
                    _safe_values([
                        f"{item.get('indicator_type') or item.get('type')}: {item.get('value')}"
                        for item in (intake.indicators if intake else [])
                        if isinstance(item, dict) and item.get("value")
                    ]),
                ),
            )
        )
        if not body:
            continue
        records.append(
            SourceRecord(
                source_type="analysis_report",
                source_id=str(report.id),
                source_version="current",
                logical_key=str(report.id),
                title=title[:700],
                body=body,
                canonical_route=f"/analyze/{report.id}/report",
                domain=report.domain,
                tlp=report.tlp,
                source_updated_at=report.updated_at,
                metadata={
                    "input_type": report.input_type,
                    "filename": _basename(report.filename),
                    "technique_ids": technique_ids,
                    "actor_ids": actor_ids,
                    "tags": _safe_values(intake.tags if intake else []),
                },
                sanitized=True,
            )
        )
    return records


async def _collect_knowledge(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (await db.execute(select(KnowledgeArticle).order_by(KnowledgeArticle.id)))
        .scalars()
        .all()
    )
    return [
        SourceRecord(
            source_type="knowledge",
            source_id=str(article.id),
            source_version="current",
            logical_key=article.external_id or str(article.id),
            title=str(article.title or article.external_id)[:700],
            body=_compose_sections(
                (
                    ("Summary", article.summary),
                    ("Article", article.body),
                    ("Category", article.category),
                    ("Tags", _safe_values(article.tags)),
                )
            ),
            canonical_route=f"/knowledge?article={article.id}",
            tlp="TLP:CLEAR",
            source_updated_at=article.created_at,
            metadata={
                "category": article.category,
                "external_id": article.external_id,
                "tags": _safe_values(article.tags),
                "published_at": _iso(article.published_at),
            },
        )
        for article in rows
        if str(article.title or article.external_id or "").strip()
    ]


async def _collect_threat_signals(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (
            await db.execute(
                select(ThreatSignal).order_by(ThreatSignal.created_at, ThreatSignal.id)
            )
        )
        .scalars()
        .all()
    )
    records: list[SourceRecord] = []
    for signal in rows:
        ioc_values = _extract_named_values(
            signal.iocs, ("value", "indicator", "observable")
        )
        records.append(
            SourceRecord(
                source_type="threat_signal",
                source_id=str(signal.id),
                source_version="current",
                logical_key=str(signal.id),
                title=signal.title[:700],
                body=_compose_sections(
                    (
                        ("Description", signal.description),
                        ("Signal type", signal.signal_type),
                        ("Status", signal.status),
                        ("Severity", signal.severity),
                        ("Confidence", signal.confidence),
                        ("CVEs", _safe_values(signal.cve_ids)),
                        ("ATT&CK techniques", _safe_values(signal.technique_ids)),
                        ("IOCs", ioc_values),
                        ("Actors", _safe_values(signal.actors)),
                        ("Sectors", _safe_values(signal.sectors)),
                        ("Tags", _safe_values(signal.tags)),
                        ("Source", signal.source_name),
                    )
                ),
                canonical_route=f"/threat-radar?signal={signal.id}",
                tlp=signal.tlp,
                source_updated_at=signal.updated_at,
                metadata={
                    "signal_type": signal.signal_type,
                    "status": signal.status,
                    "severity": signal.severity,
                    "confidence": int(signal.confidence or 0),
                    "cve_ids": _safe_values(signal.cve_ids),
                    "technique_ids": _safe_values(signal.technique_ids),
                    "iocs": ioc_values,
                    "actors": _safe_values(signal.actors),
                    "sectors": _safe_values(signal.sectors),
                    "tags": _safe_values(signal.tags),
                },
                legal_sensitive=bool(signal.legal_sensitive),
                sanitized=True,
            )
        )
    return records


async def _collect_threat_hunts(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (
            await db.execute(
                select(ThreatHuntRequest).order_by(
                    ThreatHuntRequest.created_at, ThreatHuntRequest.id
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        SourceRecord(
            source_type="threat_hunt",
            source_id=str(hunt.id),
            source_version="current",
            logical_key=str(hunt.id),
            title=hunt.title[:700],
            body=_compose_sections(
                (
                    ("Hypothesis", hunt.hypothesis),
                    ("Description", hunt.description),
                    ("Scope", hunt.scope),
                    ("Status", hunt.status),
                    ("Priority", hunt.priority),
                    ("ATT&CK techniques", _safe_values(hunt.technique_ids)),
                    ("Tactics", _safe_values(hunt.tactics)),
                    ("Telemetry", _safe_values(hunt.telemetry)),
                    ("Required fields", _safe_values(hunt.required_fields)),
                    ("Query language", hunt.query_language),
                    ("Query", hunt.query_text),
                    ("Expected evidence", hunt.expected_evidence),
                    ("False-positive notes", hunt.false_positive_notes),
                    ("Assumptions", hunt.assumptions),
                    ("Result summary", hunt.result_summary),
                    ("Disposition", hunt.disposition),
                    ("Tags", _safe_values(hunt.tags)),
                )
            ),
            canonical_route=f"/threat-hunting/{hunt.id}",
            tlp=hunt.tlp,
            source_updated_at=hunt.updated_at,
            metadata={
                "status": hunt.status,
                "priority": hunt.priority,
                "disposition": hunt.disposition,
                "technique_ids": _safe_values(hunt.technique_ids),
                "tactics": _safe_values(hunt.tactics),
                "telemetry": _safe_values(hunt.telemetry),
                "tags": _safe_values(hunt.tags),
                "archived": hunt.archived_at is not None,
            },
            legal_sensitive=True,
            sanitized=True,
        )
        for hunt in rows
        if str(hunt.title or "").strip()
    ]


async def _collect_evidence_nodes(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (
            await db.execute(
                select(EvidenceGraphNode).order_by(
                    EvidenceGraphNode.created_at, EvidenceGraphNode.id
                )
            )
        )
        .scalars()
        .all()
    )
    return [
        SourceRecord(
            source_type="evidence_node",
            source_id=str(node.id),
            source_version="current",
            logical_key=str(node.id),
            title=node.title[:700],
            body=_compose_sections(
                (
                    ("Node type", node.node_type),
                    ("Description", node.description),
                    ("Normalized summary", node.normalized_summary),
                    ("Statement", node.statement),
                    ("Behavior", node.behavior_description),
                    ("Observable pattern", node.observable_pattern),
                    ("ATT&CK technique", node.technique_id),
                    ("Technique name", node.technique_name),
                    ("Tactic", node.tactic),
                    ("Mapping rationale", node.mapping_rationale),
                    ("Data source", node.data_source),
                    ("Data component", node.data_component),
                    ("Required fields", _safe_values(node.required_fields)),
                    ("Detection hypothesis", node.detection_hypothesis),
                    ("Detection type", node.detection_type),
                    ("Expected false positives", node.expected_false_positives),
                    ("Scenario", node.scenario_description),
                    ("Expected telemetry", node.expected_telemetry),
                    ("Expected detection outcome", node.expected_detection_outcome),
                    ("Decision", node.decision),
                    ("Rationale", node.rationale),
                    ("Review status", node.review_status),
                    ("Tags", _safe_values(node.tags)),
                )
            ),
            canonical_route=f"/evidence-graph?node={node.id}",
            tlp="TLP:AMBER+STRICT",
            source_updated_at=node.updated_at,
            metadata={
                "node_type": node.node_type,
                "source_type": node.source_type,
                "source_ref": _safe_source_reference(node.source_ref),
                "technique_id": node.technique_id,
                "tactic": node.tactic,
                "confidence": int(node.confidence or 0),
                "review_status": node.review_status,
                "status": node.status,
                "tags": _safe_values(node.tags),
            },
            legal_sensitive=True,
            sanitized=True,
        )
        for node in rows
        if str(node.title or "").strip()
    ]


async def _collect_assets(db: AsyncSession) -> list[SourceRecord]:
    rows = list(
        (
            await db.execute(
                select(AssetRegistryItem).order_by(
                    AssetRegistryItem.last_seen_at, AssetRegistryItem.id
                )
            )
        )
        .scalars()
        .all()
    )
    records = [
        SourceRecord(
            source_type="asset",
            source_id=str(asset.id),
            source_version="current",
            logical_key=asset.fingerprint or str(asset.id),
            title=asset.name[:700],
            body=_compose_sections(
                (
                    ("Inventory ID", asset.inventory_asset_id),
                    ("Asset type", asset.asset_type),
                    ("Environment", asset.environment),
                    ("Owner", asset.owner),
                    ("Exposure", asset.exposure),
                    ("Criticality", asset.criticality),
                    ("IP addresses", _safe_values(asset.ip_addresses)),
                    ("Domains", _safe_values(asset.domains)),
                    ("Ports", _safe_values(asset.ports)),
                    ("Technologies", _safe_values(asset.technologies)),
                    ("Products", _safe_values(asset.products)),
                    ("Suppliers", _safe_values(asset.suppliers)),
                    ("Dependencies", _safe_values(asset.dependencies)),
                    ("ATT&CK techniques", _safe_values(asset.technique_ids)),
                    ("Risk", f"{asset.risk_level} ({asset.risk_score})"),
                    ("Tags", _safe_values(asset.tags)),
                )
            ),
            canonical_route=f"/asset-surface?asset={asset.id}",
            tlp="TLP:AMBER+STRICT",
            source_updated_at=asset.last_seen_at,
            metadata={
                "inventory_asset_id": asset.inventory_asset_id,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "exposure": asset.exposure,
                "criticality": asset.criticality,
                "technologies": _safe_values(asset.technologies),
                "products": _safe_values(asset.products),
                "suppliers": _safe_values(asset.suppliers),
                "dependencies": _safe_values(asset.dependencies),
                "technique_ids": _safe_values(asset.technique_ids),
                "risk_score": int(asset.risk_score or 0),
                "risk_level": asset.risk_level,
                "tags": _safe_values(asset.tags),
            },
            legal_sensitive=True,
            sanitized=True,
        )
        for asset in rows
        if str(asset.name or "").strip()
    ]
    space_assets = list(
        (
            await db.execute(
                select(ThreatSpaceAsset).order_by(
                    ThreatSpaceAsset.space_id,
                    ThreatSpaceAsset.updated_at,
                    ThreatSpaceAsset.id,
                )
            )
        )
        .scalars()
        .all()
    )
    records.extend(
        SourceRecord(
            source_type="asset",
            source_id=f"space:{asset.space_id}:{asset.id}",
            source_version="current",
            logical_key=f"{asset.space_id}:{asset.asset_id}"[:500],
            title=asset.name[:700],
            body=_compose_sections(
                (
                    ("Company space", asset.space_id),
                    ("Inventory ID", asset.asset_id),
                    ("Asset type", asset.asset_type),
                    ("Environment", asset.environment),
                    ("Owner", asset.owner),
                    ("Exposure", asset.exposure),
                    ("Criticality", asset.criticality),
                    ("IP addresses", _safe_values(asset.ip_addresses)),
                    ("Domains", _safe_values(asset.domains)),
                    ("Technologies", _safe_values(asset.technologies)),
                    ("Products", _safe_values(asset.products)),
                    ("Components", _safe_values(asset.components)),
                    ("Tags", _safe_values(asset.tags)),
                )
            ),
            canonical_route=f"/threat-radar/assets/{asset.space_id}/{asset.id}",
            tlp="TLP:AMBER+STRICT",
            source_updated_at=asset.updated_at,
            metadata={
                "company_space_id": str(asset.space_id),
                "inventory_asset_id": asset.asset_id,
                "asset_type": asset.asset_type,
                "environment": asset.environment,
                "exposure": asset.exposure,
                "criticality": asset.criticality,
                "technologies": _safe_values(asset.technologies),
                "products": _safe_values(asset.products),
                "components": _safe_values(asset.components),
                "tags": _safe_values(asset.tags),
            },
            space_id=asset.space_id,
            legal_sensitive=True,
            sanitized=True,
        )
        for asset in space_assets
        if str(asset.name or "").strip()
    )
    return records


async def _load_existing_documents(
    db: AsyncSession, source_types: Sequence[str]
) -> list[RAGDocument]:
    if not source_types:
        return []
    rows = await db.execute(
        select(RAGDocument)
        .options(selectinload(RAGDocument.chunks))
        .where(RAGDocument.source_type.in_(source_types))
        .order_by(
            RAGDocument.source_type, RAGDocument.source_id, RAGDocument.source_version
        )
    )
    return list(rows.scalars().all())


def _new_document(record: SourceRecord, now: datetime) -> RAGDocument:
    document = RAGDocument()
    _apply_record(document, record, now)
    document.created_at = now
    document.chunks = []
    return document


def _apply_record(
    document: RAGDocument, record: SourceRecord, indexed_at: datetime | None
) -> None:
    document.source_type = record.source_type
    document.source_id = record.source_id
    document.source_version = record.source_version
    document.logical_key = record.logical_key
    document.title = record.title
    document.canonical_route = record.canonical_route
    document.domain = record.domain
    document.tlp = record.tlp
    document.content_hash = record.content_hash
    document.source_updated_at = record.source_updated_at
    document.metadata_ = dict(record.metadata)
    document.space_id = record.space_id
    document.legal_sensitive = record.legal_sensitive
    document.sanitized = record.sanitized
    document.is_active = True
    if indexed_at is not None:
        document.indexed_at = indexed_at


def _document_needs_update(document: RAGDocument, record: SourceRecord) -> bool:
    """Detect content, provenance, policy, route, and ownership changes."""

    return any(
        (
            document.content_hash != record.content_hash,
            document.logical_key != record.logical_key,
            document.title != record.title,
            document.canonical_route != record.canonical_route,
            document.domain != record.domain,
            document.tlp != record.tlp,
            document.space_id != record.space_id,
            bool(document.legal_sensitive) != record.legal_sensitive,
            bool(document.sanitized) != record.sanitized,
            dict(document.metadata_ or {}) != dict(record.metadata),
            _iso(document.source_updated_at) != _iso(record.source_updated_at),
            not document.is_active,
        )
    )


def _reconcile_document_chunks(
    document: RAGDocument,
    record: SourceRecord,
    *,
    embedding_requested: bool = True,
) -> int:
    """Incrementally update derived chunks while preserving stable chunk IDs.

    Stable IDs keep persisted citation/proposal provenance valid when source
    content has not changed.  Existing rows are updated in place by ordinal,
    which also avoids a delete/insert ordering race on ``(document_id,
    ordinal)``.  Embeddings are retained only when their source text and model
    contract are unchanged.
    """

    desired = chunk_text(record.rendered_text) or [record.title]
    existing_by_ordinal = {chunk.ordinal: chunk for chunk in document.chunks}
    retained: list[RAGChunk] = []
    changed = 0

    for ordinal, content in enumerate(desired):
        content_hash = checksum(content)
        metadata = {
            "source_type": record.source_type,
            "source_id": record.source_id,
            "source_version": record.source_version,
            "ordinal": ordinal,
        }
        chunk = existing_by_ordinal.pop(ordinal, None)
        if chunk is None:
            chunk = RAGChunk(document=document, ordinal=ordinal)
            changed += 1
        elif chunk.content_hash != content_hash or chunk.content != content:
            # The citation freshness check binds both chunk ID and content
            # hash, so changing source text is detected without rotating IDs.
            chunk.embedding = None
            chunk.embedding_provider = ""
            chunk.embedding_model = ""
            chunk.embedding_dimensions = None
            changed += 1

        chunk.ordinal = ordinal
        chunk.content = content
        chunk.content_hash = content_hash
        chunk.token_count = len(_TOKEN_RE.findall(content))
        chunk.metadata_ = metadata

        if chunk.embedding is None:
            chunk.embedding_status = (
                "pending" if embedding_requested else "not_requested"
            )
            chunk.embedding_error = ""
        elif embedding_requested and _embedding_needed(chunk):
            chunk.embedding_status = "pending"
            chunk.embedding_error = ""
        retained.append(chunk)

    # Replacing the relationship list marks surplus rows as delete-orphans.
    # No retained ordinal is inserted twice, so PostgreSQL's uniqueness
    # constraint remains satisfied without a corpus-wide delete.
    changed += len(existing_by_ordinal)
    document.chunks = retained
    return changed


def _embedding_needed(chunk: RAGChunk) -> bool:
    return (
        chunk.embedding is None
        or chunk.embedding_status != "complete"
        or chunk.embedding_provider != settings.rag_embedding_provider
        or chunk.embedding_model != settings.rag_embedding_model
        or chunk.embedding_dimensions != settings.rag_embedding_dimensions
    )


async def _embed_chunks(
    chunks: Sequence[RAGChunk],
    *,
    heartbeat: Callable[[], Awaitable[None]] | None = None,
) -> tuple[int, int]:
    try:
        adapter = create_embedding_adapter()
    except Exception:
        for chunk in chunks:
            chunk.embedding = None
            chunk.embedding_status = "failed"
            chunk.embedding_error = "embedding_provider_unavailable"
        return 0, len(chunks)

    allowed: list[RAGChunk] = []
    blocked = 0
    for chunk in chunks:
        document = chunk.document
        if adapter.is_remote and (
            document.legal_sensitive
            or normalize_tlp(document.tlp) in _REMOTE_BLOCKED_TLPS
        ):
            chunk.embedding = None
            chunk.embedding_status = "blocked"
            chunk.embedding_error = "cloud_policy_blocked"
            blocked += 1
        else:
            allowed.append(chunk)

    created = 0
    failed = blocked
    batch_size = max(1, min(256, int(settings.rag_embedding_batch_size)))
    for start in range(0, len(allowed), batch_size):
        batch = allowed[start : start + batch_size]
        try:
            vectors = await adapter.embed_texts([chunk.content for chunk in batch])
            for chunk, vector in zip(batch, vectors, strict=True):
                chunk.embedding = vector
                chunk.embedding_provider = adapter.provider
                chunk.embedding_model = adapter.model
                chunk.embedding_dimensions = adapter.dimensions
                chunk.embedding_status = "complete"
                chunk.embedding_error = ""
                created += 1
        except Exception:
            for chunk in batch:
                chunk.embedding = None
                chunk.embedding_provider = adapter.provider
                chunk.embedding_model = adapter.model
                chunk.embedding_dimensions = adapter.dimensions
                chunk.embedding_status = "failed"
                chunk.embedding_error = "embedding_request_failed"
                failed += 1
        if heartbeat is not None:
            await heartbeat()
    return created, failed


def _search_filters(
    source_types: Sequence[str],
    domain: str,
    space_id: UUID | None = None,
) -> list[Any]:
    filters: list[Any] = [
        RAGDocument.is_active.is_(True),
        RAGDocument.sanitized.is_(True),
    ]
    if source_types:
        filters.append(RAGDocument.source_type.in_(source_types))
    else:
        filters.append(False)
    if domain:
        # Domain scopes versioned ATT&CK/report records without excluding
        # global IOC, CVE, asset, evidence, and business-context sources.
        filters.append(or_(RAGDocument.domain == "", RAGDocument.domain == domain))
    # Space-owned material is opt-in. Without an explicit company-space
    # selection, retrieval is limited to deployment-wide records. With one,
    # global reference intelligence and only that space's private records are
    # visible to the query.
    if space_id is None:
        filters.append(RAGDocument.space_id.is_(None))
    else:
        filters.append(
            or_(
                RAGDocument.space_id.is_(None),
                RAGDocument.space_id == space_id,
            )
        )
    return filters


async def _exact_candidates(
    db: AsyncSession,
    query: str,
    source_types: Sequence[str],
    domain: str,
    limit: int,
    *,
    space_id: UUID | None = None,
) -> list[_Candidate]:
    identifiers = extract_exact_identifiers(query)
    if not identifiers:
        # Arbitrary `%free text%` ILIKE scans over every chunk are not an exact
        # lookup and become an authenticated database-DoS primitive at scale.
        # Natural language is handled by the indexed TSVECTOR path instead.
        return []
    # Identifiers are normalized by extract_exact_identifiers and collector
    # logical keys. These equality predicates use B-tree indexes; arbitrary
    # title/chunk substring scans belong to the indexed FTS path.
    normalized_identifiers = identifiers[:12]
    rows = (
        await db.execute(
            select(RAGChunk, RAGDocument)
            .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
            .where(
                *_search_filters(source_types, domain, space_id),
                RAGChunk.ordinal == 0,
                or_(
                    RAGDocument.source_id.in_(normalized_identifiers),
                    RAGDocument.logical_key.in_(normalized_identifiers),
                ),
            )
            .order_by(RAGDocument.indexed_at.desc(), RAGChunk.ordinal)
            .limit(limit)
        )
    ).all()
    return [
        _Candidate(chunk=chunk, document=document, signals={"exact"})
        for chunk, document in rows
    ]


async def _fts_candidates(
    db: AsyncSession,
    query: str,
    source_types: Sequence[str],
    domain: str,
    limit: int,
    *,
    profile_query: str = "",
    signal: str = "fts",
    natural_language_fallback: bool = True,
    space_id: UUID | None = None,
) -> list[_Candidate]:
    broad_query = _lexical_fallback_query(query) if natural_language_fallback else ""
    combined_query = f"({query}) OR ({broad_query})" if broad_query else query
    if profile_query:
        # Profile terms are OR alternatives, never mandatory terms. This lets
        # generic requests such as "relevant to my business" retrieve local
        # regional, sector, product, and crown-jewel evidence.
        combined_query = f"({combined_query}) OR ({profile_query})"
    ts_query = func.websearch_to_tsquery("simple", combined_query)
    rank = func.ts_rank_cd(RAGChunk.search_vector, ts_query)
    rows = (
        await db.execute(
            select(RAGChunk, RAGDocument, rank.label("rank"))
            .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
            .where(
                *_search_filters(source_types, domain, space_id),
                RAGChunk.search_vector.op("@@")(ts_query),
            )
            .order_by(rank.desc(), RAGDocument.indexed_at.desc())
            # Chunk ranking precedes document deduplication. Bounded
            # over-fetching prevents a long report from consuming the entire
            # result window while retaining the GIN-backed FTS plan.
            .limit(min(1_000, max(limit, limit * 8)))
        )
    ).all()
    return _dedupe_ranked_rows(rows, signal=signal, limit=limit)


async def _vector_candidates(
    db: AsyncSession,
    query_embedding: Sequence[float],
    source_types: Sequence[str],
    domain: str,
    limit: int,
    *,
    space_id: UUID | None = None,
) -> list[_Candidate]:
    distance = RAGChunk.embedding.cosine_distance(list(query_embedding))
    rows = (
        await db.execute(
            select(RAGChunk, RAGDocument, distance.label("distance"))
            .join(RAGDocument, RAGDocument.id == RAGChunk.document_id)
            .where(
                *_search_filters(source_types, domain, space_id),
                RAGChunk.embedding.is_not(None),
                RAGChunk.embedding_status == "complete",
                RAGChunk.embedding_provider == settings.rag_embedding_provider,
                RAGChunk.embedding_model == settings.rag_embedding_model,
                RAGChunk.embedding_dimensions == settings.rag_embedding_dimensions,
                distance <= settings.rag_vector_max_cosine_distance,
            )
            .order_by(distance.asc())
            .limit(min(1_000, max(limit, limit * 4)))
        )
    ).all()
    return _dedupe_ranked_rows(rows, signal="vector", limit=limit)


def _dedupe_ranked_rows(
    rows: Sequence[tuple[RAGChunk, RAGDocument, Any]],
    *,
    signal: str,
    limit: int,
) -> list[_Candidate]:
    """Keep the best-ranked chunk per document without changing row order."""

    output: list[_Candidate] = []
    seen: set[str] = set()
    for chunk, document, _score in rows:
        document_id = str(document.id)
        if document_id in seen:
            continue
        seen.add(document_id)
        output.append(_Candidate(chunk=chunk, document=document, signals={signal}))
        if len(output) >= limit:
            break
    return output


def extract_exact_identifiers(query: str) -> list[str]:
    """Extract stable CTI identifiers and common observables from a query."""

    found: list[str] = []
    found.extend(match.group(0).upper() for match in _CVE_ID_RE.finditer(query))
    found.extend(match.group(0).upper() for match in _ATTACK_ID_RE.finditer(query))
    found.extend(match.group(0).lower() for match in _HASH_RE.finditer(query))
    for token in re.findall(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])", query):
        try:
            found.append(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    found.extend(match.group(0).lower() for match in _DOMAIN_RE.finditer(query))
    return list(dict.fromkeys(found))[:12]


def _relationship_target_types(query: str, selected: Sequence[str]) -> tuple[str, ...]:
    """Return explicit entity targets for a bounded, one-hop graph expansion."""

    normalized = _search_normalize(query)
    requested: set[str] = set()
    patterns: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
        (
            ("ioc", "iocs", "indicator", "indicators", "observable", "observables"),
            ("ioc",),
        ),
        (("cve", "cves", "vulnerability", "vulnerabilities"), ("cve",)),
        (
            ("ttp", "ttps", "technique", "techniques", "navigator", "attack layer"),
            ("attack_technique",),
        ),
        (("campaign", "campaigns", "operation", "operations"), ("attack_campaign",)),
        (
            ("actor", "actors", "apt", "group", "groups"),
            ("attack_group", "actor_intel"),
        ),
    )
    for terms, source_types in patterns:
        if any(_contains_term(normalized, term) for term in terms):
            requested.update(source_types)
    return tuple(source_type for source_type in selected if source_type in requested)


def _relationship_search_query(candidates: Sequence[_Candidate]) -> str:
    """Build an allowlisted OR query from stored relationship metadata only."""

    terms: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        metadata = candidate.document.metadata_ or {}
        for key in sorted(_RELATIONSHIP_METADATA_KEYS):
            if key not in metadata:
                continue
            for raw in _safe_values(metadata.get(key), limit=20):
                term = (
                    normalize_text(raw)[:160]
                    .replace('"', " ")
                    .replace("\\", " ")
                    .strip()
                )
                normalized = term.casefold()
                if len(term) < 2 or normalized in seen:
                    continue
                seen.add(normalized)
                terms.append(f'"{term}"')
                if len(terms) >= _RELATIONSHIP_QUERY_TERM_LIMIT:
                    return " OR ".join(terms)
    return " OR ".join(terms)


def _unique_document_ids(candidates: Sequence[_Candidate]) -> list[str]:
    return list(dict.fromkeys(str(candidate.document.id) for candidate in candidates))


def _merge_candidates(
    rankings: Mapping[str, Sequence[_Candidate]],
    fused: Mapping[str, float],
) -> dict[str, _Candidate]:
    merged: dict[str, _Candidate] = {}
    for mode, rows in rankings.items():
        seen_in_mode: set[str] = set()
        rank = 0
        for candidate in rows:
            identifier = str(candidate.document.id)
            if identifier in seen_in_mode:
                continue
            seen_in_mode.add(identifier)
            rank += 1
            contribution = _RRF_WEIGHTS.get(mode, 1.0) / (60 + rank)
            current = merged.get(identifier)
            if current is None:
                candidate.fused_score = fused.get(identifier, 0.0)
                candidate.mode_scores[mode] = contribution
                merged[identifier] = candidate
            else:
                best_existing = max(current.mode_scores.values(), default=-1.0)
                if contribution > best_existing:
                    current.chunk = candidate.chunk
                    current.document = candidate.document
                current.signals.update(candidate.signals)
                current.mode_scores[mode] = contribution
    return merged


def _candidate_to_item(candidate: _Candidate, query: str) -> SearchItem:
    score = candidate.fused_score + candidate.profile_score * 0.02
    signals = set(candidate.signals)
    if candidate.profile_score > 0:
        signals.add("business_context")
    document = candidate.document
    return SearchItem(
        document_id=str(document.id),
        chunk_id=str(candidate.chunk.id),
        source_type=document.source_type,
        source_id=document.source_id,
        source_version=document.source_version,
        logical_key=document.logical_key,
        title=document.title,
        canonical_route=document.canonical_route,
        domain=document.domain,
        tlp=normalize_tlp(document.tlp),
        legal_sensitive=bool(document.legal_sensitive),
        excerpt=_excerpt(candidate.chunk.content, query),
        score=round(score, 8),
        lexical_score=round(candidate.mode_scores.get("fts", 0.0), 8),
        vector_score=round(candidate.mode_scores.get("vector", 0.0), 8),
        exact_match="exact" in candidate.signals,
        retrieval_signals=tuple(sorted(signals)),
        content_hash=candidate.chunk.content_hash,
        source_updated_at=document.source_updated_at,
        indexed_at=document.indexed_at,
        metadata=dict(document.metadata_ or {}),
    )


def _excerpt(content: str, query: str, limit: int = 600) -> str:
    if len(content) <= limit:
        return content
    lowered = content.casefold()
    identifiers = extract_exact_identifiers(query)
    search_terms = identifiers or [
        token
        for token in _TOKEN_RE.findall(query)
        if len(token) >= 3 and token.casefold() not in _EXCERPT_STOPWORDS
    ]
    positions = [lowered.find(token.casefold()) for token in search_terms[:50] if token]
    positions = [position for position in positions if position >= 0]
    center = min(positions) if positions else 0
    start = max(0, center - limit // 3)
    end = min(len(content), start + limit)
    if end - start < limit:
        start = max(0, end - limit)
    excerpt = content[start:end]
    return f"{'…' if start else ''}{excerpt}{'…' if end < len(content) else ''}"


def _client_context(profile: ClientProfile) -> ClientContext:
    return ClientContext(
        name=normalize_text(profile.name),
        sector=normalize_text(profile.sector),
        region=normalize_text(profile.region),
        technologies=tuple(_safe_values(profile.technologies)),
        crown_jewels=tuple(_safe_values(profile.crown_jewels)),
    )


async def load_business_context(
    db: AsyncSession,
    *,
    client_profile_id: int | None = None,
    company_space_id: UUID | None = None,
) -> BusinessContext | None:
    """Load authoritative business context from the running local database."""

    if client_profile_id is not None and company_space_id is not None:
        raise ValueError("Select either a client profile or a company space, not both")
    if client_profile_id is not None:
        profile = await db.get(ClientProfile, client_profile_id)
        if profile is None:
            raise ValueError("client profile was not found")
        context = _client_context(profile)
        payload = {
            "context_type": "client_profile",
            "profile_id": profile.id,
            "name": context.name,
            "sector": context.sector,
            "region": context.region,
            "technologies": list(context.technologies),
            "crown_jewels": list(context.crown_jewels),
        }
        return BusinessContext(
            kind="client_profile",
            identifier=str(profile.id),
            context=context,
            checksum=checksum(payload),
            payload=payload,
        )
    if company_space_id is None:
        return None

    space = await db.get(ThreatCompanySpace, company_space_id)
    if space is None:
        raise ValueError("company space was not found")
    assets = list(
        (
            await db.execute(
                select(ThreatSpaceAsset)
                .where(ThreatSpaceAsset.space_id == space.id)
                .order_by(ThreatSpaceAsset.updated_at.desc(), ThreatSpaceAsset.id)
                .limit(2_000)
            )
        )
        .scalars()
        .all()
    )
    technologies = _safe_values(
        [
            value
            for asset in assets
            for value in (
                *(asset.technologies or []),
                *(asset.products or []),
                *(asset.components or []),
            )
        ]
    )
    settings_payload = space.settings if isinstance(space.settings, Mapping) else {}
    crown_jewels = _safe_values(
        [
            *(
                settings_payload.get("crown_jewels", [])
                if isinstance(settings_payload.get("crown_jewels", []), list)
                else []
            ),
            *[
                asset.name
                for asset in assets
                if str(asset.criticality or "").casefold() in {"critical", "high"}
            ],
        ]
    )
    context = ClientContext(
        name=normalize_text(space.name),
        sector=normalize_text(space.sector),
        region=normalize_text(space.region),
        technologies=tuple(technologies[:100]),
        crown_jewels=tuple(crown_jewels[:100]),
    )
    payload = {
        "context_type": "company_space",
        "company_space_id": str(space.id),
        "name": context.name,
        "sector": context.sector,
        "region": context.region,
        "technologies": list(context.technologies),
        "crown_jewels": list(context.crown_jewels),
        "asset_count": len(assets),
        "updated_at": _iso(space.updated_at),
    }
    return BusinessContext(
        kind="company_space",
        identifier=str(space.id),
        context=context,
        checksum=checksum(payload),
        payload=payload,
    )


def _profile_search_query(context: ClientContext) -> str:
    """Build a bounded OR query from a selected, server-side business profile."""

    candidates = (
        context.region,
        context.sector,
        *context.technologies,
        *context.crown_jewels,
    )
    terms: list[str] = []
    seen: set[str] = set()
    for raw in candidates:
        term = normalize_text(raw)[:120].replace('"', " ").replace("\\", " ").strip()
        normalized = term.casefold()
        if not term or normalized in seen:
            continue
        seen.add(normalized)
        terms.append(f'"{term}"')
        if len(terms) >= _PROFILE_QUERY_TERM_LIMIT:
            break
    return " OR ".join(terms)


def _lexical_fallback_query(query: str) -> str:
    """Return bounded meaningful terms for natural-language CTI questions."""

    terms: list[str] = []
    seen: set[str] = set()
    for raw in _TOKEN_RE.findall(query):
        term = raw.strip(".+-/:")[:80]
        normalized = term.casefold()
        if len(term) < 3 or normalized in _EXCERPT_STOPWORDS or normalized in seen:
            continue
        seen.add(normalized)
        terms.append(f'"{term.replace(chr(34), " ")}"')
        if len(terms) >= 16:
            break
    return " OR ".join(terms)


def _embedding_query(query: str, context: ClientContext | None) -> str:
    if context is None:
        return query
    terms = [
        context.region,
        context.sector,
        *context.technologies[:10],
        *context.crown_jewels[:10],
    ]
    suffix = "; ".join(value for value in _safe_values(terms) if value)[:1_500]
    return f"{query}\nBusiness relevance context: {suffix}" if suffix else query


def _contains_term(normalized_haystack: str, term: str) -> bool:
    haystack = f" {re.sub(r'[^\w+#-]+', ' ', normalized_haystack).strip()} "
    needle = re.sub(r"[^\w+#-]+", " ", str(term or "").casefold()).strip()
    return bool(needle and f" {needle} " in haystack)


def _search_normalize(value: Any) -> str:
    return re.sub(r"[^\w.+#/-]+", " ", str(value or "").casefold()).strip()


def _metadata_search_text(metadata: Mapping[str, Any] | None) -> str:
    values: list[str] = []
    for value in (metadata or {}).values():
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            values.append(str(value))
        elif isinstance(value, list):
            values.extend(_safe_values(value))
    return " ".join(values)


def _validate_source_types(source_types: Sequence[str] | None) -> tuple[str, ...]:
    # API/task request models use an empty list to mean "all configured
    # sources". Preserve that contract so the default reindex is not a no-op.
    if source_types is None or not source_types:
        return SUPPORTED_SOURCE_TYPES
    if isinstance(source_types, str):
        source_types = [source_types]
    selected = tuple(
        dict.fromkeys(str(item).strip() for item in source_types if str(item).strip())
    )
    unsupported = sorted(set(selected) - set(SUPPORTED_SOURCE_TYPES))
    if unsupported:
        raise ValueError(f"Unsupported RAG source types: {', '.join(unsupported)}")
    return tuple(
        source_type for source_type in SUPPORTED_SOURCE_TYPES if source_type in selected
    )


def _safe_values(values: Any, *, limit: int = _MAX_METADATA_LIST) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, int, float, bool)):
        iterable: Iterable[Any] = [values]
    elif isinstance(values, (list, tuple, set)):
        iterable = sorted(values, key=str) if isinstance(values, set) else values
    else:
        return []
    output: list[str] = []
    seen: set[str] = set()
    for value in iterable:
        if isinstance(value, bool):
            text = "true" if value else "false"
        elif isinstance(value, (str, int, float)):
            text = normalize_text(value)[:1_000]
        else:
            continue
        key = text.casefold()
        if text and key not in seen:
            output.append(text)
            seen.add(key)
        if len(output) >= limit:
            break
    return output


def _extract_named_values(rows: Any, keys: Sequence[str]) -> list[str]:
    if not isinstance(rows, list):
        return []
    values: list[Any] = []
    for row in rows[:_MAX_METADATA_LIST]:
        if not isinstance(row, dict):
            continue
        for key in keys:
            value = row.get(key)
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                values.append(value)
                break
    return _safe_values(values)


def _safe_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for raw_key, value in metadata.items():
        key = str(raw_key)[:120]
        if isinstance(value, bool) or value is None:
            safe[key] = value
        elif isinstance(value, str):
            safe[key] = normalize_text(value)[:2_000]
        elif isinstance(value, int):
            safe[key] = value
        elif isinstance(value, float) and math.isfinite(value):
            safe[key] = value
        elif isinstance(value, (list, tuple, set)):
            safe[key] = _safe_values(value)
        elif isinstance(value, (datetime, UUID)):
            safe[key] = _json_default(value)
    return safe


def _compose_sections(sections: Iterable[tuple[str, Any]]) -> str:
    output: list[str] = []
    for label, raw_value in sections:
        if isinstance(raw_value, (list, tuple, set)):
            value = ", ".join(_safe_values(raw_value))
        elif isinstance(raw_value, bool):
            value = "yes" if raw_value else "no"
        elif raw_value is None:
            value = ""
        else:
            value = normalize_text(raw_value)
        if value:
            output.append(f"{label}: {value}")
    return "\n\n".join(output)


def _basename(value: str | None) -> str:
    normalized = str(value or "").replace("\\", "/").split("?")[0].split("#")[0]
    return normalized.rsplit("/", 1)[-1][:500]


def _safe_source_reference(value: Any) -> str:
    reference = normalize_text(value)[:1_000]
    if not reference:
        return ""
    if reference.lower().startswith(("http://", "https://")):
        try:
            parsed = urlsplit(reference)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return "invalid-source-ref"
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            if parsed.port:
                host = f"{host}:{parsed.port}"
            return urlunsplit((parsed.scheme, host, parsed.path, "", ""))[:500]
        except (TypeError, ValueError):
            return "invalid-source-ref"
    if "/" in reference or "\\" in reference:
        return _basename(reference)
    return reference[:500]


def _attack_source_version(domain: str, version: Any) -> str:
    normalized_domain = str(domain or "unknown").strip() or "unknown"
    normalized_version = str(version or "current").strip() or "current"
    return f"{normalized_domain}:{normalized_version}"[:120]


def _iso(value: datetime | None) -> str:
    return value.isoformat() if value else ""


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"Unsupported checksum value: {type(value).__name__}")


def _response_value(item: Any, key: str, default: Any) -> Any:
    if isinstance(item, Mapping):
        return item.get(key, default)
    return getattr(item, key, default)


def _index_run_dict(run: RAGIndexRun) -> dict[str, Any]:
    return {
        "id": str(run.id),
        "status": run.status,
        "source_types": list(run.source_types or []),
        "include_embeddings": bool(run.include_embeddings),
        "documents_seen": int(run.documents_seen or 0),
        "documents_created": int(run.documents_created or 0),
        "documents_updated": int(run.documents_updated or 0),
        "documents_removed": int(run.documents_removed or 0),
        "chunks_created": int(run.chunks_created or 0),
        "embeddings_created": int(run.embeddings_created or 0),
        "embeddings_failed": int(run.embeddings_failed or 0),
        "failure_summary": run.failure_summary or "",
        "created_by": run.created_by,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "created_at": run.created_at,
    }
