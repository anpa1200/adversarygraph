"""Integration contracts for governed unified-intelligence RAG routes.

The corpus, model provider, and worker queue are deliberately replaced with
deterministic seams.  Route validation, authorization, citation binding,
provenance persistence, and Navigator confirmation controls remain real.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient

from app.api.routes import rag as rag_routes
from app.core.config import settings
from app.models.analysis import UserLayer
from app.models.attack import AttackVersion
from app.models.pipeline import AuditEvent
from app.models.rag import RAGAssistance, RAGIndexRun, RAGNavigatorProposal
from app.models.sector import ClientProfile
from app.services import rag as rag_service
from app.services import threat_hunting_ai as governed_ai
from app.services.auth import TeamUser, current_user
from tests import conftest


CHUNK_ID = "8e59e63d-741a-4fe6-abf8-6a5ab596b28c"
DOCUMENT_ID = "c00bed5d-e0d4-44d7-bcd0-243ad67792ef"
CONTENT_HASH = "4" * 64


@pytest.fixture(autouse=True)
def _rag_defaults(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "rag_enabled", True)
    monkeypatch.setattr(settings, "rag_embedding_enabled", True)
    monkeypatch.setattr(settings, "rag_max_context_chars", 20_000)
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", False)
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "local_llm_model", "test-local-model")
    monkeypatch.setattr(
        governed_ai,
        "probe_local_provider_readiness",
        AsyncMock(return_value=governed_ai.LocalProviderReadiness(
            "ready",
            "Local AI endpoint is reachable and the configured model is available.",
        )),
    )
    monkeypatch.setattr(
        rag_routes,
        "_proposal_sources_current",
        AsyncMock(return_value=True),
    )


def _item(
    *,
    source_type: str = "ioc",
    source_id: str = "203.0.113.10",
    title: str = "Reviewed command-and-control indicator",
    excerpt: str = "203.0.113.10 was observed with PowerShell T1059.001 activity.",
    canonical_route: str = "/ioc?value=203.0.113.10",
    tlp: str = "TLP:AMBER",
    legal_sensitive: bool = False,
) -> rag_service.SearchItem:
    timestamp = datetime(2026, 7, 18, 12, 30, tzinfo=timezone.utc)
    return rag_service.SearchItem(
        document_id=DOCUMENT_ID,
        chunk_id=CHUNK_ID,
        source_type=source_type,
        source_id=source_id,
        source_version="feed-2026-07-18",
        logical_key=source_id,
        title=title,
        canonical_route=canonical_route,
        domain="enterprise-attack",
        tlp=tlp,
        legal_sensitive=legal_sensitive,
        excerpt=excerpt,
        score=0.91,
        lexical_score=0.72,
        vector_score=0.83,
        exact_match=True,
        retrieval_signals=("exact", "fts", "vector"),
        content_hash=CONTENT_HASH,
        source_updated_at=timestamp,
        indexed_at=timestamp,
        metadata={"technique_ids": ["T1059.001"], "confidence": 85},
    )


def _result(*items: rag_service.SearchItem) -> rag_service.SearchResponse:
    return rag_service.SearchResponse(
        items=tuple(items),
        retrieval_mode="hybrid",
        warnings=("Vector ranking was combined with exact and lexical evidence.",),
        corpus_indexed_at=datetime(2026, 7, 18, 12, 31, tzinfo=timezone.utc),
    )


def _objects(model):
    return [
        value
        for (stored_model, _), value in conftest._mock_session._objects.items()
        if stored_model is model
    ]


def _proposal(
    *,
    created_by: str = "local",
    status: str = "suggested",
    attack_version: str = "19.1",
    expires_at: datetime | None = None,
    checksum: str = "a" * 64,
) -> RAGNavigatorProposal:
    proposal = RAGNavigatorProposal(
        id=uuid4(),
        assistance_id=uuid4(),
        status=status,
        name="Evidence-backed PowerShell layer",
        domain="enterprise-attack",
        attack_version=attack_version,
        technique_ids=["T1059.001"],
        rationale="The cited source explicitly contains T1059.001.",
        source_refs=[{
            "source_ref": "S1",
            "source_type": "ioc",
            "chunk_id": CHUNK_ID,
            "content_hash": CONTENT_HASH,
        }],
        proposal_checksum=checksum,
        created_by=created_by,
        expires_at=expires_at
        or datetime.now(timezone.utc) + timedelta(minutes=20),
    )
    conftest._mock_session.add(proposal)
    return proposal


def _attack_version(version: str = "19.1") -> AttackVersion:
    row = AttackVersion(
        id=19,
        domain="enterprise-attack",
        version=version,
        is_latest=True,
    )
    conftest._mock_session.add(row)
    return row


async def test_rag_provider_route_exposes_runtime_availability(client: AsyncClient):
    response = await client.get("/api/rag/providers")

    assert response.status_code == 200
    local = next(row for row in response.json() if row["id"] == "local")
    assert local["configured"] is True
    assert local["available"] is True
    assert local["status"] == "ready"


async def test_rag_route_permission_boundaries(
    app,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    async def viewer_user():
        return TeamUser(name="viewer", roles=["viewer"], permissions=["read"])

    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(
        rag_service,
        "get_index_status",
        AsyncMock(return_value={"documents_sanitized": 1, "chunks_embedded": 1}),
    )
    search = AsyncMock(return_value=_result(_item()))
    entity = AsyncMock(return_value={"source_type": "ioc", "source_id": "one"})
    monkeypatch.setattr(rag_service, "hybrid_search", search)
    monkeypatch.setattr(rag_service, "get_indexed_entity", entity)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = viewer_user
    try:
        status = await client.get("/api/rag/status")
        profiles = await client.get("/api/rag/profiles")
        search_response = await client.post("/api/rag/search", json={"query": "one"})
        entity_response = await client.get("/api/rag/entity/ioc/one")
        reindex = await client.post("/api/rag/reindex", json={})
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert status.status_code == 200
    assert profiles.status_code == 403
    assert search_response.status_code == 403
    assert entity_response.status_code == 403
    assert reindex.status_code == 403
    search.assert_not_awaited()
    entity.assert_not_awaited()


@pytest.mark.parametrize("endpoint", ["search", "reindex"])
async def test_source_type_allowlist_is_enforced_before_service_call(
    endpoint: str,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    service = AsyncMock(return_value=_result())
    monkeypatch.setattr(rag_service, "hybrid_search", service)
    payload = {"source_types": ["ioc", "arbitrary_private_table"]}
    if endpoint == "search":
        payload["query"] = "reviewed evidence"

    response = await client.post(f"/api/rag/{endpoint}", json=payload)

    assert response.status_code == 422
    assert "Unsupported RAG source types" in response.text
    service.assert_not_awaited()


async def test_search_contract_preserves_canonical_route_and_filters(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    search = AsyncMock(return_value=_result(_item()))
    monkeypatch.setattr(rag_service, "hybrid_search", search)

    response = await client.post("/api/rag/search", json={
        "query": "find IOC relevant for my business",
        "source_types": ["ioc", "ioc", "cve"],
        "domain": "enterprise-attack",
        "limit": 7,
    })

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["query"] == "find IOC relevant for my business"
    assert body["retrieval_mode"] == "hybrid"
    assert body["corpus_indexed_at"] == "2026-07-18T12:31:00+00:00"
    assert body["items"][0] == {
        "chunk_id": CHUNK_ID,
        "document_id": DOCUMENT_ID,
        "source_type": "ioc",
        "source_id": "203.0.113.10",
        "source_version": "feed-2026-07-18",
        "logical_key": "203.0.113.10",
        "title": "Reviewed command-and-control indicator",
        "excerpt": "203.0.113.10 was observed with PowerShell T1059.001 activity.",
        "route": "/ioc?value=203.0.113.10",
        "domain": "enterprise-attack",
        "tlp": "TLP:AMBER",
        "legal_sensitive": False,
        "score": 0.91,
        "lexical_score": 0.72,
        "vector_score": 0.83,
        "exact_match": True,
        "verified": True,
        "retrieval_signals": ["exact", "fts", "vector"],
        "metadata": {"technique_ids": ["T1059.001"], "confidence": 85},
        "content_hash": CONTENT_HASH,
        "source_updated_at": "2026-07-18T12:30:00+00:00",
        "indexed_at": "2026-07-18T12:30:00+00:00",
    }
    assert any("No saved client profile" in warning for warning in body["warnings"])
    search.assert_awaited_once_with(
        conftest._mock_session,
        "find IOC relevant for my business",
        source_types=["ioc", "cve"],
        domain="enterprise-attack",
        client_profile_id=None,
        limit=7,
    )


async def test_search_rejects_unknown_attack_domain_before_retrieval(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    service = AsyncMock(return_value=_result())
    monkeypatch.setattr(rag_service, "hybrid_search", service)

    response = await client.post("/api/rag/search", json={
        "query": "review evidence",
        "domain": "arbitrary-prompt-domain",
    })

    assert response.status_code == 422
    service.assert_not_awaited()


async def test_profiles_and_path_entity_return_only_route_contract(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    conftest._mock_session.add(ClientProfile(
        id=7,
        name="Israel technology company",
        sector="technology",
        region="Israel",
        technologies=["Kubernetes", "Microsoft 365"],
        crown_jewels=["source code"],
    ))
    indexed_entity = AsyncMock(return_value={
        "source_type": "analysis_report",
        "source_id": "reports/2026/incident-7",
        "title": "Sanitized incident report",
        "route": "/analysis/reports/7",
        "tlp": "TLP:AMBER+STRICT",
    })
    monkeypatch.setattr(rag_service, "get_indexed_entity", indexed_entity)

    profiles = await client.get("/api/rag/profiles")
    entity = await client.get(
        "/api/rag/entity/analysis_report/reports/2026/incident-7"
    )
    unknown = await client.get("/api/rag/entity/raw_database/secret")

    assert profiles.status_code == 200
    assert profiles.json() == [{
        "id": 7,
        "name": "Israel technology company",
        "sector": "technology",
        "region": "Israel",
        "technologies": ["Kubernetes", "Microsoft 365"],
        "crown_jewels": ["source code"],
    }]
    assert entity.status_code == 200
    assert entity.json()["source_id"] == "reports/2026/incident-7"
    indexed_entity.assert_awaited_once_with(
        conftest._mock_session,
        "analysis_report",
        "reports/2026/incident-7",
    )
    assert unknown.status_code == 404


async def test_empty_retrieval_prevents_any_ai_provider_call(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(rag_service, "hybrid_search", AsyncMock(return_value=_result()))
    provider = AsyncMock(side_effect=AssertionError("provider must not be called"))
    monkeypatch.setattr(governed_ai, "complete", provider)

    response = await client.post("/api/rag/assist", json={
        "query": "find relevant indicators",
        "provider": "local",
    })

    assert response.status_code == 409
    assert "No indexed evidence matched" in response.text
    provider.assert_not_awaited()
    assert _objects(RAGAssistance) == []


@pytest.mark.parametrize(
    ("provider_output", "message"),
    [
        ("not JSON", "malformed JSON"),
        (
            json.dumps({
                "answer": "A claim carrying the wrong marker [S2]",
                "cited_source_ids": ["S1"],
                "relevant_source_ids": ["S1"],
                "cautions": [],
                "navigator_proposal": None,
            }),
            "citation markers",
        ),
    ],
)
async def test_malformed_or_citation_invalid_ai_output_maps_to_502(
    provider_output: str,
    message: str,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(rag_service, "hybrid_search", AsyncMock(return_value=_result(_item())))
    monkeypatch.setattr(
        governed_ai,
        "create_adapter",
        MagicMock(return_value=SimpleNamespace(model="test-local-model")),
    )
    monkeypatch.setattr(governed_ai, "complete", AsyncMock(return_value=provider_output))

    response = await client.post("/api/rag/assist", json={
        "query": "what is relevant?",
        "provider": "local",
    })

    assert response.status_code == 502
    assert message in response.text
    assert _objects(RAGAssistance) == []


async def test_legal_sensitive_source_is_blocked_from_cloud_even_if_tlp_is_clear(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    monkeypatch.setattr(
        rag_service,
        "hybrid_search",
        AsyncMock(return_value=_result(_item(tlp="TLP:CLEAR", legal_sensitive=True))),
    )
    provider = AsyncMock(side_effect=AssertionError("restricted evidence must not leave the host"))
    monkeypatch.setattr(governed_ai, "complete", provider)

    response = await client.post("/api/rag/assist", json={
        "query": "summarize this source",
        "provider": "openai",
        "cloud_processing_acknowledged": True,
    })

    assert response.status_code == 403
    assert "TLP:AMBER+STRICT" in response.text
    provider.assert_not_awaited()
    assert _objects(RAGAssistance) == []


async def test_restricted_cve_relationship_evidence_is_blocked_from_cloud(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    monkeypatch.setattr(
        rag_service,
        "hybrid_search",
        AsyncMock(return_value=_result(_item(
            source_type="cve",
            source_id="CVE-2026-23456",
            title="CVE with restricted IOC relationship evidence",
            canonical_route="/cve?search=CVE-2026-23456",
            tlp="TLP:RED",
            legal_sensitive=True,
        ))),
    )
    provider = AsyncMock(
        side_effect=AssertionError("restricted CVE evidence must not leave the host")
    )
    monkeypatch.setattr(governed_ai, "complete", provider)

    response = await client.post("/api/rag/assist", json={
        "query": "summarize this CVE relationship evidence",
        "provider": "openai",
        "cloud_processing_acknowledged": True,
    })

    assert response.status_code == 403
    assert "TLP:RED" in response.text
    provider.assert_not_awaited()
    assert _objects(RAGAssistance) == []


async def test_malformed_tlp_is_blocked_from_remote_generation(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    monkeypatch.setattr(
        rag_service,
        "hybrid_search",
        AsyncMock(return_value=_result(_item(tlp="unknown-upstream-marking"))),
    )
    provider = AsyncMock(
        side_effect=AssertionError("restricted evidence must not leave the host")
    )
    monkeypatch.setattr(governed_ai, "complete", provider)

    response = await client.post("/api/rag/assist", json={
        "query": "summarize this source",
        "provider": "openai",
        "cloud_processing_acknowledged": True,
    })

    assert response.status_code == 403
    assert "TLP:AMBER+STRICT" in response.text
    provider.assert_not_awaited()


async def test_remote_provider_attempt_is_audited_before_timeout(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(
        rag_service,
        "hybrid_search",
        AsyncMock(return_value=_result(_item(tlp="TLP:CLEAR"))),
    )
    monkeypatch.setattr(
        governed_ai,
        "create_adapter",
        MagicMock(return_value=SimpleNamespace(model="remote-test-model")),
    )
    monkeypatch.setattr(
        governed_ai,
        "complete",
        AsyncMock(side_effect=governed_ai.AIProviderTimeoutError()),
    )

    response = await client.post("/api/rag/assist", json={
        "query": "summarize the evidence",
        "provider": "openai",
        "cloud_processing_acknowledged": True,
    })

    assert response.status_code == 504
    audits = _objects(AuditEvent)
    assert len(audits) == 1
    assert audits[0].action == "rag.assist.remote_attempt"
    assert audits[0].details["source_count"] == 1
    assert _objects(RAGAssistance) == []


async def test_successful_cited_assistance_persists_provenance_and_proposal_only(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _attack_version()
    source = _item()
    monkeypatch.setattr(rag_service, "hybrid_search", AsyncMock(return_value=_result(source)))
    monkeypatch.setattr(
        governed_ai,
        "create_adapter",
        MagicMock(return_value=SimpleNamespace(model="test-local-model")),
    )
    provider_output = json.dumps({
        "answer": "The reviewed indicator is associated with PowerShell activity [S1].",
        "cited_source_ids": ["S1"],
        "relevant_source_ids": ["S1"],
        "cautions": ["Relevance does not establish targeting or compromise."],
        "navigator_proposal": {
            "name": "Reviewed PowerShell evidence",
            "technique_ids": ["T1059.001"],
            "rationale": "T1059.001 appears verbatim in the cited evidence.",
        },
    })
    monkeypatch.setattr(governed_ai, "complete", AsyncMock(return_value=provider_output))
    monkeypatch.setattr(
        governed_ai,
        "verify_technique_ids",
        AsyncMock(return_value=(["T1059.001"], [])),
    )
    monkeypatch.setattr(rag_routes, "_stale_source_refs", AsyncMock(return_value=False))

    response = await client.post("/api/rag/assist", json={
        "query": "paste on Navigator all relevant TTPs",
        "provider": "local",
        "source_types": ["ioc"],
        "domain": "enterprise-attack",
    })

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["effective_tlp"] == "TLP:AMBER"
    assert body["requires_human_review"] is True
    assert "did not change Navigator state" in body["execution_boundary"]
    assert body["citations"] == [{
        "source_ref": "S1",
        "source_type": "ioc",
        "source_id": "203.0.113.10",
        "title": "Reviewed command-and-control indicator",
        "excerpt": "203.0.113.10 was observed with PowerShell T1059.001 activity.",
        "route": "/ioc?value=203.0.113.10",
        "tlp": "TLP:AMBER",
        "legal_sensitive": False,
        "score": 0.91,
        "verified": True,
    }]
    assert body["navigator_proposal"]["technique_ids"] == ["T1059.001"]
    assert body["navigator_proposal"]["requires_confirmation"] is True

    assistance = _objects(RAGAssistance)[0]
    assert assistance.created_by == "local"
    assert assistance.provider == "local"
    assert assistance.model == "test-local-model"
    assert assistance.retrieval_mode == "hybrid"
    assert assistance.prompt_version == "unified-intelligence-rag-v1"
    assert len(assistance.query_checksum) == 64
    assert len(assistance.output_checksum) == 64
    assert assistance.filters == {
        "source_types": ["ioc"],
        "domain": "enterprise-attack",
        "attack_version": None,
        "client_profile_id": None,
        "limit": 12,
    }
    assert assistance.source_refs[0]["source_ref"] == "S1"
    assert assistance.source_refs[0]["excerpt_hash"] != CONTENT_HASH
    proposal = _objects(RAGNavigatorProposal)[0]
    assert proposal.assistance_id == assistance.id
    assert proposal.status == "suggested"
    assert proposal.source_refs == assistance.source_refs
    audits = _objects(AuditEvent)
    assert len(audits) == 1
    assert audits[0].action == "rag.assist.suggest"
    assert audits[0].details["proposal_created"] is True
    assert audits[0].details["source_count"] == 1
    assert _objects(UserLayer) == []


async def test_assistance_rejects_source_hash_changed_during_provider_call(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(rag_service, "hybrid_search", AsyncMock(return_value=_result(_item())))
    monkeypatch.setattr(
        governed_ai,
        "create_adapter",
        MagicMock(return_value=SimpleNamespace(model="test-local-model")),
    )
    monkeypatch.setattr(
        governed_ai,
        "complete",
        AsyncMock(return_value=json.dumps({
            "answer": "The evidence contains an indicator [S1].",
            "cited_source_ids": ["S1"],
            "relevant_source_ids": ["S1"],
            "cautions": [],
            "navigator_proposal": None,
        })),
    )
    monkeypatch.setattr(rag_routes, "_stale_source_refs", AsyncMock(return_value=True))

    response = await client.post("/api/rag/assist", json={
        "query": "summarize the indicator",
        "provider": "local",
    })

    assert response.status_code == 409
    assert "changed while the answer was generated" in response.text
    assert _objects(RAGAssistance) == []
    assert _objects(AuditEvent) == []


async def test_proposal_owner_is_enforced(
    app,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    proposal = _proposal(created_by="another-analyst")

    async def analyst_user():
        return TeamUser(
            name="current-analyst",
            roles=["analyst"],
            permissions=["read", "run_analysis"],
        )

    monkeypatch.setattr(settings, "auth_enabled", True)
    previous = app.dependency_overrides.get(current_user)
    app.dependency_overrides[current_user] = analyst_user
    try:
        response = await client.post(
            f"/api/rag/proposals/{proposal.id}/confirm",
            json={"proposal_checksum": proposal.proposal_checksum, "mode": "add"},
        )
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 403
    assert proposal.status == "suggested"


async def test_proposal_checksum_and_expiry_are_enforced(client: AsyncClient):
    checksum_proposal = _proposal()
    checksum_response = await client.post(
        f"/api/rag/proposals/{checksum_proposal.id}/confirm",
        json={"proposal_checksum": "b" * 64, "mode": "add"},
    )
    assert checksum_response.status_code == 409
    assert "checksum" in checksum_response.text
    assert checksum_proposal.status == "suggested"

    expired = _proposal(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    expired_response = await client.post(
        f"/api/rag/proposals/{expired.id}/confirm",
        json={"proposal_checksum": expired.proposal_checksum, "mode": "add"},
    )
    assert expired_response.status_code == 409
    assert "expired" in expired_response.text
    assert expired.status == "expired"


async def test_proposal_confirmation_rejects_withdrawn_or_changed_evidence(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    proposal = _proposal()
    monkeypatch.setattr(
        rag_routes,
        "_proposal_sources_current",
        AsyncMock(return_value=False),
    )

    response = await client.post(
        f"/api/rag/proposals/{proposal.id}/confirm",
        json={"proposal_checksum": proposal.proposal_checksum, "mode": "add"},
    )

    assert response.status_code == 409
    assert "evidence changed or was withdrawn" in response.text
    assert proposal.status == "suggested"


async def test_proposal_confirmation_obeys_operator_kill_switch(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    proposal = _proposal()
    monkeypatch.setattr(settings, "rag_enabled", False)

    response = await client.post(
        f"/api/rag/proposals/{proposal.id}/confirm",
        json={"proposal_checksum": proposal.proposal_checksum, "mode": "add"},
    )

    assert response.status_code == 503
    assert "disabled by the operator" in response.text
    assert proposal.status == "suggested"


async def test_proposal_catalog_version_and_technique_revalidation_are_enforced(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _attack_version("19.1")
    stale_catalog = _proposal(attack_version="18.0")
    stale_response = await client.post(
        f"/api/rag/proposals/{stale_catalog.id}/confirm",
        json={"proposal_checksum": stale_catalog.proposal_checksum, "mode": "replace"},
    )
    assert stale_response.status_code == 409
    assert "catalog changed" in stale_response.text

    removed_technique = _proposal(attack_version="19.1")
    monkeypatch.setattr(
        governed_ai,
        "verify_technique_ids",
        AsyncMock(return_value=([], ["Technique was removed from the local catalog."])),
    )
    removed_response = await client.post(
        f"/api/rag/proposals/{removed_technique.id}/confirm",
        json={"proposal_checksum": removed_technique.proposal_checksum, "mode": "add"},
    )
    assert removed_response.status_code == 409
    assert "no longer matches" in removed_response.text
    assert removed_technique.status == "suggested"


async def test_proposal_confirmation_is_one_time_and_never_saves_a_layer(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _attack_version()
    proposal = _proposal()
    verifier = AsyncMock(return_value=(["T1059.001"], []))
    monkeypatch.setattr(governed_ai, "verify_technique_ids", verifier)
    payload = {"proposal_checksum": proposal.proposal_checksum, "mode": "replace"}

    first = await client.post(f"/api/rag/proposals/{proposal.id}/confirm", json=payload)
    second = await client.post(f"/api/rag/proposals/{proposal.id}/confirm", json=payload)

    assert first.status_code == 200, first.text
    assert first.json() == {
        "proposal_id": str(proposal.id),
        "status": "confirmed",
        "mode": "replace",
        "domain": "enterprise-attack",
        "attack_version": "19.1",
        "technique_ids": ["T1059.001"],
        "warnings": [],
        "persisted": False,
        "message": "Proposal confirmed for client-side Navigator preview/application; no saved layer was created.",
    }
    assert proposal.confirmed_by == "local"
    assert proposal.confirmation_mode == "replace"
    assert proposal.confirmed_at is not None
    assert second.status_code == 409
    assert "already confirmed" in second.text
    assert verifier.await_count == 1
    assert _objects(UserLayer) == []
    audits = _objects(AuditEvent)
    assert len(audits) == 1
    assert audits[0].action == "rag.navigator.confirm"


async def test_reindex_fails_closed_when_disabled(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "rag_enabled", False)

    response = await client.post("/api/rag/reindex", json={"source_types": ["ioc"]})

    assert response.status_code == 503
    assert "disabled by the operator" in response.text
    assert _objects(RAGIndexRun) == []


async def test_reindex_queue_failure_preserves_redispatchable_state_and_is_sanitized(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.tasks.rag import reconcile_rag

    queue = MagicMock(side_effect=RuntimeError("redis://user:secret@internal.example"))
    monkeypatch.setattr(reconcile_rag, "delay", queue)

    response = await client.post("/api/rag/reindex", json={
        "source_types": ["ioc", "cve"],
        "include_embeddings": False,
    })

    assert response.status_code == 503
    assert response.json()["detail"] == "RAG index worker queue is unavailable"
    assert "secret" not in response.text
    run = _objects(RAGIndexRun)[0]
    assert run.status == "queued"
    assert run.source_types == ["ioc", "cve"]
    assert run.include_embeddings is False
    assert not run.failure_summary
    assert run.completed_at is None
    queue.assert_called_once_with(str(run.id))
    audits = _objects(AuditEvent)
    assert len(audits) == 1
    assert audits[0].action == "rag.index.queue"


async def test_reindex_reuses_an_active_run_without_double_queueing(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.tasks.rag import reconcile_rag

    active = RAGIndexRun(
        id=uuid4(),
        status="running",
        source_types=["ioc"],
        include_embeddings=False,
        created_by="scheduler",
        heartbeat_at=datetime.now(timezone.utc),
    )
    conftest._mock_session.add(active)
    queue = MagicMock()
    monkeypatch.setattr(reconcile_rag, "delay", queue)

    response = await client.post("/api/rag/reindex", json={})

    assert response.status_code == 202
    assert response.json() == {
        "run_id": str(active.id),
        "status": "running",
        "deduplicated": True,
    }
    queue.assert_not_called()
    assert _objects(RAGIndexRun) == [active]


async def test_reindex_redispatches_an_existing_queued_run(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.tasks.rag import reconcile_rag

    active = RAGIndexRun(
        id=uuid4(),
        status="queued",
        source_types=["ioc"],
        include_embeddings=False,
        created_by="scheduler",
    )
    conftest._mock_session.add(active)
    queue = MagicMock()
    monkeypatch.setattr(reconcile_rag, "delay", queue)

    response = await client.post("/api/rag/reindex", json={})

    assert response.status_code == 202
    assert response.json() == {
        "run_id": str(active.id),
        "status": "queued",
        "deduplicated": True,
        "redispatched": True,
    }
    queue.assert_called_once_with(str(active.id))
    audits = _objects(AuditEvent)
    assert len(audits) == 1
    assert audits[0].action == "rag.index.redispatch"


async def test_reindex_redispatches_a_stale_running_run(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.tasks.rag import reconcile_rag

    active = RAGIndexRun(
        id=uuid4(),
        status="running",
        source_types=["ioc"],
        include_embeddings=False,
        created_by="scheduler",
        attempt_count=2,
        heartbeat_at=datetime.now(timezone.utc) - timedelta(hours=3),
    )
    conftest._mock_session.add(active)
    queue = MagicMock()
    monkeypatch.setattr(reconcile_rag, "delay", queue)

    response = await client.post("/api/rag/reindex", json={})

    assert response.status_code == 202
    assert response.json()["redispatched"] is True
    queue.assert_called_once_with(str(active.id))


async def test_index_run_endpoints_expose_recovery_state(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    heartbeat = datetime.now(timezone.utc)
    run = RAGIndexRun(
        id=uuid4(),
        status="running",
        source_types=["ioc"],
        include_embeddings=False,
        created_by="scheduler",
        attempt_count=3,
        heartbeat_at=heartbeat,
    )
    conftest._mock_session.add(run)
    monkeypatch.setattr(
        rag_service,
        "get_index_status",
        AsyncMock(return_value={"documents_sanitized": 1, "latest_run": {"id": str(run.id)}}),
    )

    status_response = await client.get("/api/rag/status")
    runs_response = await client.get("/api/rag/index-runs")

    assert status_response.status_code == 200
    assert status_response.json()["latest_run"]["attempt_count"] == 3
    status_heartbeat = datetime.fromisoformat(
        status_response.json()["latest_run"]["heartbeat_at"].replace("Z", "+00:00")
    )
    assert status_heartbeat == heartbeat
    assert runs_response.status_code == 200
    assert runs_response.json()[0]["attempt_count"] == 3
    assert runs_response.json()[0]["heartbeat_at"] == heartbeat.isoformat()
