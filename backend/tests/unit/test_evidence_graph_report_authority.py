from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.analysis import AnalysisSession
from app.models.evidence_graph import EvidenceGraphEdge, EvidenceGraphNode
from app.models.operations import ReportIntake
from app.models.rag import RAGChunk, RAGDocument
from app.services import evidence_graph as graph
from app.services import rag


class _LookupDB:
    def __init__(self, values=None):
        self.values = values or {}
        self.lookups = []

    async def get(self, model, identifier):
        self.lookups.append((model, identifier))
        return self.values.get((model, identifier))


class _ScalarRows:
    def __init__(self, rows):
        self.rows = list(rows)

    def scalars(self):
        return self

    def all(self):
        return self.rows


class _ExecuteDB:
    def __init__(self, *row_sets):
        self.row_sets = list(row_sets)

    async def execute(self, _statement):
        return _ScalarRows(self.row_sets.pop(0))


class _IndexedEntityDB(_ExecuteDB):
    def __init__(self, document, *row_sets):
        super().__init__(*row_sets)
        self.document = document

    async def scalar(self, _statement):
        return self.document


def _session(session_id):
    return AnalysisSession(
        id=session_id,
        status="completed",
        name="Unreviewed mutable title",
        input_type="text",
        llm_provider="local",
        model="test",
        domain="enterprise-attack",
        source_text="UNREVIEWED RAW SOURCE MUST NOT ENTER THE GRAPH",
    )


def _promotion(session_id, *, targets=None):
    review_id = uuid4()
    return SimpleNamespace(
        id=uuid4(),
        session_id=session_id,
        review_id=review_id,
        review_revision=3,
        manifest_checksum="a" * 64,
        targets=targets or ["canonical_intelligence", "rag"],
        manifest={
            "accepted_claims": [
                {
                    "claim_key": "accepted-procedure",
                    "claim_type": "procedure",
                    "status": "accepted",
                    "object": "PowerShell",
                    "statement": "Reviewed PowerShell execution was observed.",
                    "evidence_text": "Reviewed PowerShell execution was observed.",
                    "attack_id": "T1059.001",
                    "metadata": {"confidence": 88, "tactic": "execution"},
                },
                {
                    "claim_key": "rejected-procedure",
                    "claim_type": "procedure",
                    "status": "rejected",
                    "object": "Rejected technique",
                    "statement": "REJECTED CLAIM MUST NOT ENTER THE GRAPH",
                    "attack_id": "T9999",
                    "metadata": {"confidence": 99},
                },
            ]
        },
    )


def _node(*, metadata=None, source_type=""):
    return EvidenceGraphNode(
        id=uuid4(),
        node_type="evidence",
        title="Evidence",
        source_type=source_type,
        metadata_json=metadata or {},
    )


def _edge(source_id, target_id, *, metadata=None):
    return EvidenceGraphEdge(
        id=uuid4(),
        source_node_id=source_id,
        target_node_id=target_id,
        edge_type="SUPPORTS",
        metadata_json=metadata or {},
    )


def _document(node, *, metadata=None):
    return RAGDocument(
        id=uuid4(),
        source_type="evidence_node",
        source_id=str(node.id),
        source_version="current",
        logical_key=str(node.id),
        title=node.title,
        content_hash="b" * 64,
        metadata_=metadata or {},
    )


@pytest.mark.asyncio
async def test_report_identifier_requires_uuid_before_database_lookup():
    db = _LookupDB()

    with pytest.raises(HTTPException) as exc_info:
        await graph.graph_from_report(db, "not-a-uuid", "analyst")

    assert exc_info.value.status_code == 422
    assert db.lookups == []


@pytest.mark.asyncio
async def test_report_identifier_resolves_session_and_linked_intake_alias():
    session_id = uuid4()
    intake_id = uuid4()
    session = _session(session_id)
    intake = ReportIntake(
        id=intake_id,
        analysis_session_id=session_id,
        title="Unreviewed intake title",
        summary="UNREVIEWED INTAKE SUMMARY",
        technique_ids=["T9999"],
    )
    db = _LookupDB(
        {
            (AnalysisSession, session_id): session,
            (ReportIntake, intake_id): intake,
        }
    )

    assert await graph._resolve_report_session_id(db, session_id) == session_id
    assert await graph._resolve_report_session_id(db, intake_id) == session_id


@pytest.mark.asyncio
async def test_report_identifier_fails_closed_for_unknown_unlinked_and_ambiguous_ids():
    unknown_id = uuid4()
    with pytest.raises(HTTPException) as unknown:
        await graph._resolve_report_session_id(_LookupDB(), unknown_id)
    assert unknown.value.status_code == 404

    unlinked_id = uuid4()
    unlinked = ReportIntake(id=unlinked_id, title="Unlinked")
    with pytest.raises(HTTPException) as unlinked_error:
        await graph._resolve_report_session_id(
            _LookupDB({(ReportIntake, unlinked_id): unlinked}),
            unlinked_id,
        )
    assert unlinked_error.value.status_code == 409

    ambiguous_id = uuid4()
    conflicting_session_id = uuid4()
    with pytest.raises(HTTPException) as ambiguous:
        await graph._resolve_report_session_id(
            _LookupDB(
                {
                    (AnalysisSession, ambiguous_id): _session(ambiguous_id),
                    (ReportIntake, ambiguous_id): ReportIntake(
                        id=ambiguous_id,
                        analysis_session_id=conflicting_session_id,
                        title="Conflicting alias",
                    ),
                }
            ),
            ambiguous_id,
        )
    assert ambiguous.value.status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("authority_state", ["unpromoted", "stale", "revoked"])
async def test_report_import_requires_active_current_authority_before_writes(
    monkeypatch,
    authority_state,
):
    session_id = uuid4()
    db = _LookupDB({(AnalysisSession, session_id): _session(session_id)})
    writes = []

    async def inactive(_db, checked_session_id):
        assert checked_session_id == session_id
        return None

    async def unexpected_write(*args, **kwargs):
        writes.append((args, kwargs))
        raise AssertionError("authority failure must precede graph writes")

    monkeypatch.setattr(graph, "active_promotion", inactive)
    monkeypatch.setattr(graph, "create_node", unexpected_write)

    with pytest.raises(HTTPException) as exc_info:
        await graph.graph_from_report(db, session_id, "analyst")

    assert exc_info.value.status_code == 409, authority_state
    assert writes == []


@pytest.mark.asyncio
async def test_report_import_requires_canonical_intelligence_target(monkeypatch):
    session_id = uuid4()
    db = _LookupDB({(AnalysisSession, session_id): _session(session_id)})
    promotion = _promotion(session_id, targets=["rag"])

    async def active(_db, _session_id):
        return promotion

    monkeypatch.setattr(graph, "active_promotion", active)

    with pytest.raises(HTTPException) as exc_info:
        await graph.graph_from_report(db, session_id, "analyst")

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_report_import_materializes_only_accepted_manifest_claims(monkeypatch):
    session_id = uuid4()
    db = _LookupDB({(AnalysisSession, session_id): _session(session_id)})
    promotion = _promotion(session_id)
    node_payloads = []
    edge_payloads = []

    async def active(_db, checked_session_id):
        assert checked_session_id == session_id
        return promotion

    async def create_node(_db, payload, actor, *, allow_report_origin=False):
        assert actor == "analyst"
        assert allow_report_origin is True
        node_payloads.append(payload)
        return EvidenceGraphNode(id=uuid4(), created_by=actor, **payload)

    async def create_edge(_db, payload, actor, *, allow_report_origin=False):
        assert actor == "analyst"
        assert allow_report_origin is True
        edge_payloads.append(payload)
        return EvidenceGraphEdge(id=uuid4(), created_by=actor, **payload)

    monkeypatch.setattr(graph, "active_promotion", active)
    monkeypatch.setattr(graph, "create_node", create_node)
    monkeypatch.setattr(graph, "create_edge", create_edge)

    result = await graph.graph_from_report(db, session_id, "analyst")

    assert result["nodes_created"] == 4
    assert result["edges_created"] == 3
    serialized = str(node_payloads) + str(edge_payloads)
    assert "Reviewed PowerShell execution was observed" in serialized
    assert "T1059.001" in serialized
    assert "REJECTED CLAIM" not in serialized
    assert "T9999" not in serialized
    assert "UNREVIEWED RAW SOURCE" not in serialized
    assert "Unreviewed mutable title" not in serialized
    assert all(item["review_status"] == "analyst_reviewed" for item in node_payloads)
    assert all(item["review_status"] == "analyst_reviewed" for item in edge_payloads)
    for payload in [*node_payloads, *edge_payloads]:
        provenance = payload["metadata_json"]
        assert provenance["analysis_session_id"] == str(session_id)
        assert provenance["promotion_id"] == str(promotion.id)
        assert provenance["review_id"] == str(promotion.review_id)
        assert provenance["review_revision"] == promotion.review_revision
        assert provenance["promotion_manifest_checksum"] == promotion.manifest_checksum


def test_generic_graph_mutations_cannot_claim_report_provenance():
    for hostile_source_type in (
        graph.REPORT_GRAPH_SOURCE_TYPE,
        " Uploaded_Report ",
        "UPLOADED_REPORT",
    ):
        with pytest.raises(HTTPException) as node_error:
            graph.validate_node_payload(
                {
                    "node_type": "evidence",
                    "title": "Forged report",
                    "source_type": hostile_source_type,
                }
            )
        assert node_error.value.status_code == 409

    for hostile_origin in (
        graph.REPORT_GRAPH_ORIGIN,
        " From-Report ",
        "FROM-REPORT",
    ):
        with pytest.raises(HTTPException) as edge_error:
            graph.validate_edge_payload(
                {
                    "source_node_id": str(uuid4()),
                    "target_node_id": str(uuid4()),
                    "edge_type": "SUPPORTS",
                    "metadata_json": {"origin": hostile_origin},
                }
            )
        assert edge_error.value.status_code == 409


@pytest.mark.asyncio
async def test_report_provenance_is_immutable_even_when_legacy_metadata_is_missing():
    node = _node(source_type=graph.REPORT_GRAPH_SOURCE_TYPE)
    db = _LookupDB({(EvidenceGraphNode, node.id): node})

    with pytest.raises(HTTPException) as exc_info:
        await graph.update_node(db, str(node.id), {"ai_generated": False})

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_report_graph_rows_require_matching_live_promotion_provenance(monkeypatch):
    session_id = uuid4()
    promotion = _promotion(session_id)
    provenance = graph._report_graph_provenance(session_id, promotion)
    valid = _node(metadata=provenance, source_type=graph.REPORT_GRAPH_SOURCE_TYPE)
    stale = _node(
        metadata={**provenance, "promotion_manifest_checksum": "c" * 64},
        source_type=graph.REPORT_GRAPH_SOURCE_TYPE,
    )
    legacy = _node(source_type=graph.REPORT_GRAPH_SOURCE_TYPE)
    independent = _node()

    async def active(_db, _session_id):
        return promotion

    monkeypatch.setattr(graph, "active_promotion", active)
    authorized = await graph.authorized_report_graph_node_ids(
        _LookupDB(),
        [valid, stale, legacy, independent],
        target="canonical_intelligence",
    )
    assert authorized == {valid.id, independent.id}

    valid_edge = _edge(valid.id, valid.id, metadata=provenance)
    stale_edge = _edge(valid.id, valid.id, metadata={**provenance, "promotion_id": str(uuid4())})
    edge_ids = await graph.authorized_report_graph_edge_ids(
        _LookupDB(),
        [valid_edge, stale_edge],
        target="canonical_intelligence",
    )
    assert edge_ids == {valid_edge.id}

    async def revoked(_db, _session_id):
        return None

    monkeypatch.setattr(graph, "active_promotion", revoked)
    assert await graph.authorized_report_graph_node_ids(
        _LookupDB(),
        [valid, independent],
        target="canonical_intelligence",
    ) == {independent.id}


@pytest.mark.asyncio
async def test_rag_revalidates_live_report_graph_authority_and_cached_provenance(
    monkeypatch,
):
    session_id = uuid4()
    promotion = _promotion(session_id)
    provenance = graph._report_graph_provenance(session_id, promotion)
    report_node = _node(
        metadata=provenance,
        source_type=graph.REPORT_GRAPH_SOURCE_TYPE,
    )
    independent_node = _node()
    report_document = _document(report_node, metadata=provenance)
    legacy_cached_document = _document(report_node)
    independent_document = _document(independent_node)

    async def active(_db, _session_id):
        return promotion

    monkeypatch.setattr(graph, "active_promotion", active)
    allowed = await rag._authorized_document_ids(
        _ExecuteDB([report_node, independent_node]),
        [report_document, legacy_cached_document, independent_document],
    )
    assert allowed == {str(report_document.id), str(independent_document.id)}

    async def revoked(_db, _session_id):
        return None

    monkeypatch.setattr(graph, "active_promotion", revoked)
    allowed_after_revocation = await rag._authorized_document_ids(
        _ExecuteDB([report_node, independent_node]),
        [report_document, independent_document],
    )
    assert allowed_after_revocation == {str(independent_document.id)}


@pytest.mark.asyncio
async def test_rag_direct_entity_read_rejects_revoked_report_graph_document(
    monkeypatch,
):
    session_id = uuid4()
    promotion = _promotion(session_id)
    provenance = graph._report_graph_provenance(session_id, promotion)
    report_node = _node(
        metadata=provenance,
        source_type=graph.REPORT_GRAPH_SOURCE_TYPE,
    )
    document = _document(report_node, metadata=provenance)
    document.chunks = []

    async def revoked(_db, _session_id):
        return None

    monkeypatch.setattr(graph, "active_promotion", revoked)

    assert (
        await rag.get_indexed_entity(
            _IndexedEntityDB(document, [report_node]),
            "evidence_node",
            str(report_node.id),
        )
        is None
    )


@pytest.mark.asyncio
async def test_rag_relationship_candidates_reject_revoked_report_graph_document(
    monkeypatch,
):
    session_id = uuid4()
    promotion = _promotion(session_id)
    provenance = graph._report_graph_provenance(session_id, promotion)
    report_node = _node(
        metadata=provenance,
        source_type=graph.REPORT_GRAPH_SOURCE_TYPE,
    )
    independent_node = _node()
    report_document = _document(report_node, metadata=provenance)
    independent_document = _document(independent_node)
    report_candidate = rag._Candidate(
        document=report_document,
        chunk=RAGChunk(
            id=uuid4(),
            document_id=report_document.id,
            ordinal=0,
            content="Revoked report fact",
            content_hash="c" * 64,
        ),
        signals={"relationship"},
    )
    independent_candidate = rag._Candidate(
        document=independent_document,
        chunk=RAGChunk(
            id=uuid4(),
            document_id=independent_document.id,
            ordinal=0,
            content="Independent evidence",
            content_hash="d" * 64,
        ),
        signals={"relationship"},
    )

    async def revoked(_db, _session_id):
        return None

    monkeypatch.setattr(graph, "active_promotion", revoked)
    filtered = await rag._filter_authoritative_candidates(
        _ExecuteDB([report_node, independent_node]),
        [report_candidate, independent_candidate],
    )

    assert filtered == [independent_candidate]
