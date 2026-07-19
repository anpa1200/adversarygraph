from __future__ import annotations

import json
import math
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.cve import CVEActorLink, CVEIOCLink, CVERecord, CVETechniqueLink
from app.models.ioc import IOCActorLink, IOCIndicator
from app.models.rag import RAGChunk, RAGDocument, RAGIndexRun
from app.models.sector import ActorIntelObservation
from app.services import rag


def _record(*, body: str = "PowerShell execution was observed.", source_id: str = "T1059.001") -> rag.SourceRecord:
    return rag.SourceRecord(
        source_type="attack_technique",
        source_id=source_id,
        source_version="enterprise-attack:18.1",
        logical_key=source_id,
        title=f"{source_id} — PowerShell",
        body=body,
        canonical_route=f"/navigator?technique={source_id}",
        domain="enterprise-attack",
        tlp="TLP:CLEAR",
        metadata={"attack_id": source_id, "platforms": ["Windows"]},
    )


class _Result:
    def __init__(self, rows):
        self._rows = list(rows)

    def all(self):
        return self._rows

    def scalars(self):
        return self


class _ExecuteDB:
    def __init__(self, rows):
        self.rows = rows
        self.last_statement = None

    async def execute(self, statement):
        self.last_statement = statement
        return _Result(self.rows)


class _ReconcileDB:
    def __init__(self):
        self.added = []
        self.flushes = 0
        self.commits = 0

    def add(self, value):
        if hasattr(value, "id") and value.id is None:
            value.id = uuid4()
        self.added.append(value)

    async def flush(self):
        self.flushes += 1

    async def commit(self):
        self.commits += 1


class _SearchDB:
    async def scalar(self, _statement):
        return rag.datetime(2026, 7, 19, tzinfo=rag.timezone.utc)


class _FakeEmbeddings:
    def __init__(self, data):
        self.data = data
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(data=self.data)


def test_normalize_tlp_accepts_legacy_aliases_and_fails_closed():
    assert rag.normalize_tlp("clear") == "TLP:CLEAR"
    assert rag.normalize_tlp("TLP:WHITE") == "TLP:CLEAR"
    assert rag.normalize_tlp("amber-strict") == "TLP:AMBER+STRICT"
    assert rag.normalize_tlp("not-a-marking") == "TLP:AMBER+STRICT"
    assert rag.normalize_tlp(None, default="TLP:GREEN") == "TLP:GREEN"


def test_empty_source_selection_means_full_reconciliation():
    assert rag._validate_source_types(None) == rag.SUPPORTED_SOURCE_TYPES
    assert rag._validate_source_types([]) == rag.SUPPORTED_SOURCE_TYPES
    assert rag._validate_source_types(["ioc", "ioc", "cve"]) == ("ioc", "cve")


def test_checksum_is_canonical_for_mapping_order_and_sensitive_to_content():
    assert rag.checksum({"b": 2, "a": 1}) == rag.checksum({"a": 1, "b": 2})
    assert rag.checksum("alpha") == rag.checksum(b"alpha")
    assert rag.checksum("alpha") != rag.checksum("alpha ")
    assert len(rag.checksum({"a": 1})) == 64


def test_chunk_text_is_deterministic_bounded_and_overlapping():
    text = " ".join(f"word-{index}" for index in range(160))

    first = rag.chunk_text(text, max_chars=180, overlap_chars=30)
    second = rag.chunk_text(text, max_chars=180, overlap_chars=30)

    assert first == second
    assert len(first) > 2
    assert all(0 < len(chunk) <= 180 for chunk in first)
    assert first[0][-12:].strip() in first[1]


@pytest.mark.parametrize(
    ("maximum", "overlap"),
    [(127, 0), (256, -1), (256, 256), (256, 300)],
)
def test_chunk_text_rejects_unsafe_boundaries(maximum: int, overlap: int):
    with pytest.raises(ValueError):
        rag.chunk_text("source text", max_chars=maximum, overlap_chars=overlap)


def test_source_record_rejects_unsanitized_content_and_drops_nested_metadata():
    with pytest.raises(ValueError, match="Unsanitized"):
        rag.SourceRecord(
            source_type="knowledge",
            source_id="1",
            source_version="current",
            logical_key="article-1",
            title="Unsafe article",
            body="body",
            sanitized=False,
        )

    record = rag.SourceRecord(
        source_type="knowledge",
        source_id="1",
        source_version="current",
        logical_key="article-1",
        title="Safe article",
        body="body",
        metadata={"category": "guide", "raw": {"password": "secret"}, "tags": ["hunting", {"token": "secret"}]},
    )
    serialized = json.dumps(record.metadata)

    assert record.metadata == {"category": "guide", "tags": ["hunting"]}
    assert "secret" not in serialized


def test_source_record_hash_covers_governance_and_normalized_content():
    baseline = _record(body="Line one.\r\n\r\nLine two.")
    same = _record(body="Line one.\n\nLine two.")
    restricted = rag.SourceRecord(
        source_type=baseline.source_type,
        source_id=baseline.source_id,
        source_version=baseline.source_version,
        logical_key=baseline.logical_key,
        title=baseline.title,
        body=baseline.body,
        domain=baseline.domain,
        tlp="TLP:AMBER",
        metadata=baseline.metadata,
    )

    assert baseline.content_hash == same.content_hash
    assert baseline.content_hash != restricted.content_hash


def test_reciprocal_rank_fusion_rewards_cross_mode_results_and_deduplicates():
    scores = rag.reciprocal_rank_fusion(
        {"exact": ["a", "a", "b"], "fts": ["b", "c", "a"], "vector": ["c", "b"]},
        weights={"exact": 2.0, "fts": 1.0, "vector": 1.0},
    )

    assert scores["b"] > scores["a"]
    assert scores["b"] > scores["c"]
    assert math.isclose(scores["a"], 2 / 61 + 1 / 63)


def test_reciprocal_rank_fusion_rejects_bad_parameters():
    with pytest.raises(ValueError):
        rag.reciprocal_rank_fusion({"fts": ["a"]}, k=0)
    with pytest.raises(ValueError):
        rag.reciprocal_rank_fusion({"fts": ["a"]}, weights={"fts": math.nan})


def test_ranked_chunk_rows_keep_only_best_chunk_per_document():
    first_document = RAGDocument(id=uuid4(), source_type="knowledge")
    second_document = RAGDocument(id=uuid4(), source_type="ioc")
    first_best = RAGChunk(id=uuid4(), document=first_document, ordinal=2)
    first_worse = RAGChunk(id=uuid4(), document=first_document, ordinal=5)
    second = RAGChunk(id=uuid4(), document=second_document, ordinal=0)

    candidates = rag._dedupe_ranked_rows(
        [
            (first_best, first_document, 0.9),
            (first_worse, first_document, 0.8),
            (second, second_document, 0.7),
        ],
        signal="fts",
        limit=10,
    )

    assert [candidate.chunk.id for candidate in candidates] == [first_best.id, second.id]


def test_candidate_merge_keeps_chunk_from_strongest_rank_contribution():
    document = RAGDocument(id=uuid4(), source_type="ioc")
    weak_chunk = RAGChunk(id=uuid4(), document=document, ordinal=0)
    strong_chunk = RAGChunk(id=uuid4(), document=document, ordinal=1)
    vector_candidate = rag._Candidate(
        chunk=weak_chunk,
        document=document,
        signals={"vector"},
    )
    exact_candidate = rag._Candidate(
        chunk=strong_chunk,
        document=document,
        signals={"exact"},
    )
    identifier = str(document.id)

    merged = rag._merge_candidates(
        {"vector": [vector_candidate], "exact": [exact_candidate]},
        {identifier: 3 / 61},
    )[identifier]

    assert merged.chunk.id == strong_chunk.id
    assert merged.signals == {"vector", "exact"}


def test_business_context_rerank_matches_region_sector_technology_and_crown_jewel():
    context = rag.ClientContext(
        name="Example Israel Tech",
        sector="technology",
        region="Israel",
        technologies=("Microsoft Azure", "Kubernetes"),
        crown_jewels=("source code",),
    )

    relevant = rag.business_relevance_score(
        "The campaign targets technology companies in Israel using Microsoft Azure and Kubernetes to reach source code.",
        context,
    )
    unrelated = rag.business_relevance_score("Retail organizations in Brazil using point-of-sale systems.", context)

    assert relevant == 1.0
    assert unrelated == 0.0


def test_business_profile_expands_lexical_and_private_embedding_queries():
    context = rag.ClientContext(
        name="Israel technology company",
        sector="technology",
        region="Israel",
        technologies=("Microsoft 365", "Kubernetes"),
        crown_jewels=("source code",),
    )

    lexical = rag._profile_search_query(context)
    embedding = rag._embedding_query("find relevant IOCs", context)

    assert '"Israel"' in lexical
    assert '"Microsoft 365"' in lexical
    assert "Business relevance context" in embedding
    assert "source code" in embedding


def test_natural_language_fallback_drops_generic_words_and_keeps_scope():
    query = rag._lexical_fallback_query(
        "Find me IOCs relevant for my business: Israel technology company"
    )

    assert '"Israel"' in query
    assert '"technology"' in query
    assert '"find"' not in query.lower()
    assert '"business"' not in query.lower()


def test_relationship_target_detection_is_explicit_and_respects_source_filters():
    selected = ("actor_intel", "ioc", "cve", "attack_technique")

    assert rag._relationship_target_types(
        "Find IOCs relevant to our business", selected
    ) == ("ioc",)
    assert rag._relationship_target_types(
        "Paste all relevant TTPs on Navigator", selected
    ) == ("attack_technique",)
    assert rag._relationship_target_types("Summarize the evidence", selected) == ()


def test_relationship_query_uses_only_allowlisted_reviewed_metadata():
    document = RAGDocument(
        id=uuid4(),
        source_type="actor_intel",
        source_id="17",
        source_version="current",
        logical_key="actor-observation:17",
        title="Example actor",
        tlp="TLP:AMBER+STRICT",
        sanitized=True,
        content_hash="a" * 64,
        metadata_={
            "actor_ids": ["G0123"],
            "actor_names": ["Example Actor"],
            "observation_value": "Israel",
            "raw": "must-not-be-used",
        },
        is_active=True,
    )
    chunk = RAGChunk(
        id=uuid4(),
        document=document,
        ordinal=0,
        content="Untrusted arbitrary body value",
        content_hash="b" * 64,
        token_count=4,
    )

    query = rag._relationship_search_query([rag._Candidate(chunk=chunk, document=document)])

    assert '"G0123"' in query
    assert '"Example Actor"' in query
    assert "Israel" not in query
    assert "must-not-be-used" not in query


@pytest.mark.asyncio
async def test_hybrid_search_expands_business_actor_evidence_to_linked_iocs(
    monkeypatch: pytest.MonkeyPatch,
):
    actor_document = RAGDocument(
        id=uuid4(),
        source_type="actor_intel",
        source_id="17",
        source_version="current",
        logical_key="actor-observation:17",
        title="G0123 — Example Actor: victim-region — Israel",
        tlp="TLP:AMBER+STRICT",
        sanitized=True,
        content_hash="a" * 64,
        metadata_={"actor_ids": ["G0123"], "actor_names": ["Example Actor"]},
        is_active=True,
    )
    actor_chunk = RAGChunk(
        id=uuid4(),
        document=actor_document,
        ordinal=0,
        content="Reviewed victim region: Israel; sector: technology.",
        content_hash="b" * 64,
        token_count=7,
    )
    ioc_document = RAGDocument(
        id=uuid4(),
        source_type="ioc",
        source_id="9",
        source_version="current",
        logical_key="198.51.100.9",
        title="ipv4: 198.51.100.9",
        tlp="TLP:CLEAR",
        sanitized=True,
        content_hash="c" * 64,
        metadata_={"actor_ids": ["G0123"], "actor_names": ["Example Actor"]},
        is_active=True,
    )
    ioc_chunk = RAGChunk(
        id=uuid4(),
        document=ioc_document,
        ordinal=0,
        content="Reviewed actor relationship: G0123 — Example Actor.",
        content_hash="d" * 64,
        token_count=7,
    )
    relationship_calls: list[tuple[str, tuple[str, ...]]] = []

    async def exact(*_args, **_kwargs):
        return []

    async def fts(_db, query, source_types, _domain, _limit, **kwargs):
        signal = kwargs.get("signal", "fts")
        if signal == "relationship":
            relationship_calls.append((query, tuple(source_types)))
            return [rag._Candidate(
                chunk=ioc_chunk,
                document=ioc_document,
                signals={"relationship"},
            )]
        return [rag._Candidate(chunk=actor_chunk, document=actor_document, signals={"fts"})]

    monkeypatch.setattr(settings, "rag_embedding_enabled", False)
    monkeypatch.setattr(rag, "_exact_candidates", exact)
    monkeypatch.setattr(rag, "_fts_candidates", fts)

    response = await rag.hybrid_search(
        _SearchDB(),  # type: ignore[arg-type]
        "Find IOCs relevant for an Israel technology company",
        source_types=["actor_intel", "ioc"],
        limit=12,
    )

    assert relationship_calls == [('\"G0123\" OR \"Example Actor\"', ("ioc",))]
    linked_ioc = next(item for item in response.items if item.source_type == "ioc")
    assert "relationship" in linked_ioc.retrieval_signals
    assert "relationship" in response.retrieval_mode
    assert any("relationship expansion" in warning.lower() for warning in response.warnings)


def test_exact_identifier_extraction_is_ordered_validated_and_deduplicated():
    identifiers = rag.extract_exact_identifiers(
        "Check cve-2025-12345 with T1566.001 on 203.0.113.7 and evil.example; "
        "ignore 999.999.999.999 and repeat CVE-2025-12345."
    )

    assert identifiers == ["CVE-2025-12345", "T1566.001", "203.0.113.7", "evil.example"]


@pytest.mark.asyncio
async def test_exact_lookup_uses_indexed_equality_without_chunk_substring_scan():
    db = _ExecuteDB([])

    await rag._exact_candidates(
        db,
        "Check deadbeefdeadbeefdeadbeefdeadbeef",
        ["ioc"],
        "",
        20,
    )
    sql = str(db.last_statement).lower()

    assert "rag_documents.logical_key in" in sql
    assert "rag_chunks.content like" not in sql
    assert "ilike" not in sql


def test_source_reference_removes_credentials_queries_fragments_and_local_paths():
    assert rag._safe_source_reference("https://user:secret@example.test:8443/report?token=secret#part") == (
        "https://example.test:8443/report"
    )
    assert rag._safe_source_reference("/home/analyst/private/report.txt") == "report.txt"
    assert rag._safe_source_reference("evidence-record-17") == "evidence-record-17"


@pytest.mark.asyncio
async def test_embedding_adapter_preserves_provider_indexes_and_validates_dimensions():
    embeddings = _FakeEmbeddings(
        [
            SimpleNamespace(index=1, embedding=[0.0, 2.0, 0.0]),
            SimpleNamespace(index=0, embedding=[1.0, 0.0, 0.0]),
        ]
    )
    adapter = rag.OpenAICompatibleEmbeddingAdapter(
        provider="local",
        model="test-embed",
        dimensions=3,
        client=SimpleNamespace(embeddings=embeddings),
    )

    vectors = await adapter.embed_texts(["first", "second"])

    assert vectors == [[1.0, 0.0, 0.0], [0.0, 2.0, 0.0]]
    assert embeddings.calls == [{"model": "test-embed", "input": ["first", "second"]}]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vector",
    ([1.0, 2.0], [1.0, math.nan, 0.0], [0.0, 0.0, 0.0], [1.0, True, 0.0]),
)
async def test_embedding_adapter_rejects_invalid_vectors(vector):
    adapter = rag.OpenAICompatibleEmbeddingAdapter(
        provider="local",
        model="test-embed",
        dimensions=3,
        client=SimpleNamespace(embeddings=_FakeEmbeddings([SimpleNamespace(index=0, embedding=vector)])),
    )

    with pytest.raises(rag.EmbeddingValidationError):
        await adapter.embed_query("query")


def test_openai_embeddings_respect_cloud_processing_gate(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", False)

    with pytest.raises(rag.EmbeddingConfigurationError, match="disabled"):
        rag.OpenAICompatibleEmbeddingAdapter(
            provider="openai",
            model="text-embedding-3-small",
            dimensions=3,
            client=SimpleNamespace(),
        )


@pytest.mark.asyncio
async def test_remote_embedding_blocks_legal_sensitive_chunks(monkeypatch: pytest.MonkeyPatch):
    class _RemoteAdapter:
        provider = "openai"
        model = "test"
        dimensions = 3
        is_remote = True

        async def embed_texts(self, _texts):
            raise AssertionError("restricted chunks must not reach a remote provider")

    document = RAGDocument(
        id=uuid4(),
        source_type="asset",
        source_id="asset-1",
        source_version="current",
        logical_key="asset-1",
        title="Production asset",
        domain="",
        tlp="TLP:AMBER+STRICT",
        space_id=None,
        legal_sensitive=True,
        sanitized=True,
        content_hash="a" * 64,
        metadata_={},
        is_active=True,
    )
    chunk = RAGChunk(
        id=uuid4(),
        document=document,
        ordinal=0,
        content="Private production asset details",
        content_hash="b" * 64,
        token_count=4,
    )
    monkeypatch.setattr(rag, "create_embedding_adapter", lambda: _RemoteAdapter())

    created, failed = await rag._embed_chunks([chunk])

    assert (created, failed) == (0, 1)
    assert chunk.embedding_status == "blocked"
    assert chunk.embedding_error == "cloud_policy_blocked"


@pytest.mark.asyncio
async def test_ioc_collector_uses_allowlist_and_never_copies_raw_json():
    indicator = IOCIndicator(
        id=7,
        value="203.0.113.8",
        indicator_type="ipv4",
        source_id="feed",
        source_url="https://feed.example/item/7",
        first_seen="2026-01-01",
        last_seen="2026-01-02",
        confidence=85,
        tlp="clear",
        malware_family="ExampleRAT",
        campaign="Example Campaign",
        technique_ids=["T1071.001"],
        description="Observed command-and-control address.",
        tags=["c2"],
        raw={"api_token": "must-not-be-indexed"},
    )

    records = await rag.collect_source_records(_ExecuteDB([indicator]), ["ioc"])
    corpus_text = records[0].rendered_text + json.dumps(records[0].metadata)

    assert len(records) == 1
    assert records[0].tlp == "TLP:CLEAR"
    assert records[0].logical_key == "203.0.113.8"
    assert "must-not-be-indexed" not in corpus_text
    assert "raw" not in records[0].metadata


@pytest.mark.asyncio
async def test_ioc_collector_preserves_reviewed_actor_relationship_evidence():
    indicator = IOCIndicator(
        id=9,
        value="198.51.100.9",
        indicator_type="ipv4",
        source_id="feed",
        tlp="clear",
        description="Reviewed observable.",
    )
    indicator.actor_links = [IOCActorLink(
        indicator_id=9,
        actor_attack_id="G0123",
        actor_name="Example Actor",
        source_id="reviewed-feed",
        relationship_type="attributed-to",
        confidence=88,
        evidence="Analyst-reviewed campaign report.",
    )]

    records = await rag.collect_source_records(_ExecuteDB([indicator]), ["ioc"])

    assert records[0].metadata["actor_ids"] == ["G0123"]
    assert records[0].metadata["actor_names"] == ["Example Actor"]
    assert "Analyst-reviewed campaign report" in records[0].rendered_text
    assert records[0].metadata["indicator_refs"] == ["ioc-record-9"]


@pytest.mark.asyncio
async def test_cve_collector_preserves_reviewed_graph_links_without_raw_payload():
    cve = CVERecord(
        id=3,
        cve_id="CVE-2026-12345",
        description="Example vulnerability.",
        raw={"provider_secret": "must-not-be-indexed"},
    )
    cve.technique_links = [CVETechniqueLink(
        cve_id=cve.cve_id,
        attack_id="T1190",
        source_id="reviewed-feed",
        confidence=90,
        evidence="Exploitation evidence.",
    )]
    cve.actor_links = [CVEActorLink(
        cve_id=cve.cve_id,
        actor_attack_id="G0123",
        actor_name="Example Actor",
        source_id="reviewed-feed",
        confidence=80,
        evidence="Actor usage report.",
    )]
    cve.ioc_links = [CVEIOCLink(
        cve_id=cve.cve_id,
        indicator_id=9,
        source_id="reviewed-feed",
        confidence=75,
        evidence="Observed during exploitation.",
    )]

    records = await rag.collect_source_records(_ExecuteDB([cve]), ["cve"])
    serialized = records[0].rendered_text + json.dumps(records[0].metadata)

    assert records[0].metadata["technique_ids"] == ["T1190"]
    assert records[0].metadata["actor_ids"] == ["G0123"]
    assert records[0].metadata["indicator_refs"] == ["ioc-record-9"]
    assert "Exploitation evidence" in serialized
    assert "provider_secret" not in serialized
    assert "must-not-be-indexed" not in serialized


@pytest.mark.asyncio
async def test_cve_collector_inherits_strictest_linked_ioc_marking():
    cve = CVERecord(id=4, cve_id="CVE-2026-23456", description="Linked IOC test.")
    green_indicator = IOCIndicator(
        id=10,
        value="198.51.100.10",
        indicator_type="ipv4",
        source_id="green-feed",
        tlp="green",
    )
    red_indicator = IOCIndicator(
        id=11,
        value="198.51.100.11",
        indicator_type="ipv4",
        source_id="restricted-feed",
        tlp="TLP:RED",
    )
    cve.ioc_links = [
        CVEIOCLink(
            cve_id=cve.cve_id,
            indicator_id=green_indicator.id,
            indicator=green_indicator,
            source_id="green-feed",
            evidence="Publicly shareable relationship evidence.",
        ),
        CVEIOCLink(
            cve_id=cve.cve_id,
            indicator_id=red_indicator.id,
            indicator=red_indicator,
            source_id="restricted-feed",
            evidence="Restricted relationship evidence.",
        ),
    ]
    cve.technique_links = []
    cve.actor_links = []

    records = await rag.collect_source_records(_ExecuteDB([cve]), ["cve"])

    assert records[0].tlp == "TLP:RED"
    assert records[0].legal_sensitive is True


@pytest.mark.asyncio
async def test_cve_collector_fails_closed_for_unresolved_relationship_provenance():
    cve = CVERecord(id=5, cve_id="CVE-2026-34567", description="Actor link test.")
    cve.technique_links = []
    cve.ioc_links = []
    cve.actor_links = [CVEActorLink(
        cve_id=cve.cve_id,
        actor_attack_id="G0999",
        actor_name="Unresolved Example Actor",
        source_id="derived-correlation",
        evidence="Derived relationship without an originating IOC reference.",
    )]

    records = await rag.collect_source_records(_ExecuteDB([cve]), ["cve"])

    assert records[0].tlp == "TLP:AMBER+STRICT"
    assert records[0].legal_sensitive is True


@pytest.mark.asyncio
async def test_actor_intel_collector_indexes_business_context_and_fails_closed():
    observation = ActorIntelObservation(
        id=17,
        source_id="misp-galaxy",
        actor_attack_id="G0123",
        actor_name="Example Actor",
        observation_type="victim-region",
        value="Israel",
        normalized_value="israel",
        confidence=82,
        evidence="Reviewed public threat reporting.",
        source_url="https://user:secret@example.test/report?token=secret",
        raw={"api_key": "must-not-be-indexed"},
    )

    records = await rag.collect_source_records(_ExecuteDB([observation]), ["actor_intel"])
    serialized = records[0].rendered_text + json.dumps(records[0].metadata)

    assert records[0].tlp == "TLP:AMBER+STRICT"
    assert records[0].metadata["actor_ids"] == ["G0123"]
    assert records[0].canonical_route == "/apt?group=G0123&tab=overview"
    assert "Israel" in records[0].rendered_text
    assert "https://example.test/report" in serialized
    assert "secret" not in serialized
    assert "must-not-be-indexed" not in serialized


@pytest.mark.asyncio
async def test_ioc_collector_fails_closed_for_unknown_tlp_marking():
    indicator = IOCIndicator(
        id=8,
        value="198.51.100.8",
        indicator_type="ipv4",
        source_id="feed",
        tlp="share-with-anyone-maybe",
        description="Malformed upstream marking must never become cloud eligible.",
    )

    records = await rag.collect_source_records(_ExecuteDB([indicator]), ["ioc"])

    assert records[0].tlp == "TLP:AMBER+STRICT"


@pytest.mark.asyncio
async def test_report_collector_omits_raw_provider_response():
    report_id = uuid4()
    session = AnalysisSession(
        id=report_id,
        status="completed",
        name="Incident report",
        input_type="text",
        filename="/private/path/report.txt",
        llm_provider="local",
        model="model",
        domain="enterprise-attack",
        tlp="TLP:AMBER",
        source_text="PowerShell was observed on the endpoint.",
    )
    result = AnalysisResult(
        session_id=report_id,
        extracted_techniques=[{"attack_id": "T1059.001", "hidden": "do-not-copy"}],
        apt_matches=[{"group_attack_id": "G0016"}],
        summary="Endpoint execution report.",
        raw_response="provider-secret-response",
    )

    records = await rag.collect_source_records(_ExecuteDB([(session, result)]), ["analysis_report"])
    serialized = records[0].rendered_text + json.dumps(records[0].metadata)

    assert records[0].metadata["filename"] == "report.txt"
    assert records[0].metadata["technique_ids"] == ["T1059.001"]
    assert "provider-secret-response" not in serialized
    assert "do-not-copy" not in serialized


@pytest.mark.asyncio
async def test_reconciliation_is_idempotent_and_reuses_unchanged_chunks(monkeypatch: pytest.MonkeyPatch):
    db = _ReconcileDB()
    run = RAGIndexRun(created_by="test")
    source = _record()
    existing = []

    async def collect(_db, _types):
        return [source]

    async def load(_db, _types):
        return existing

    monkeypatch.setattr(rag, "collect_source_records", collect)
    monkeypatch.setattr(rag, "_load_existing_documents", load)
    monkeypatch.setattr(settings, "rag_embedding_enabled", False)

    first = await rag.reconcile_corpus(db, run, ["attack_technique"], include_embeddings=False)
    document = next(value for value in db.added if isinstance(value, RAGDocument))
    original_chunks = tuple(document.chunks)
    existing.append(document)
    second = await rag.reconcile_corpus(db, run, ["attack_technique"], include_embeddings=False)

    assert first.documents_created == 1
    assert first.chunks_created == len(original_chunks) > 0
    assert second.documents_created == 0
    assert second.documents_updated == 0
    assert second.chunks_created == 0
    assert tuple(document.chunks) == original_chunks
    assert document.is_active is True


@pytest.mark.asyncio
async def test_reconciliation_tombstones_disappeared_source(monkeypatch: pytest.MonkeyPatch):
    db = _ReconcileDB()
    document = rag._new_document(_record(), rag.datetime.now(rag.timezone.utc))
    document.id = uuid4()
    document.is_active = True

    async def collect(_db, _types):
        return []

    async def load(_db, _types):
        return [document]

    monkeypatch.setattr(rag, "collect_source_records", collect)
    monkeypatch.setattr(rag, "_load_existing_documents", load)
    monkeypatch.setattr(settings, "rag_embedding_enabled", False)

    result = await rag.reconcile_corpus(db, RAGIndexRun(created_by="test"), ["attack_technique"], include_embeddings=False)

    assert result.documents_removed == 1
    assert document.is_active is False


def test_search_response_is_strictly_json_serializable():
    response = rag.SearchResponse(items=(), retrieval_mode="exact+fts", warnings=("warning",), corpus_indexed_at=None)

    assert json.dumps(response.to_dict())
    assert response.to_dict() == {
        "items": [],
        "retrieval_mode": "exact+fts",
        "warnings": ["warning"],
        "corpus_indexed_at": None,
    }


def test_search_item_payload_preserves_route_governance_and_mode_evidence():
    now = rag.datetime.now(rag.timezone.utc)
    document = RAGDocument(
        id=uuid4(),
        source_type="threat_hunt",
        source_id="hunt-1",
        source_version="current",
        logical_key="hunt-1",
        title="PowerShell hunt",
        canonical_route="/threat-hunting/hunt-1",
        domain="enterprise-attack",
        tlp="TLP:AMBER+STRICT",
        space_id=None,
        legal_sensitive=True,
        sanitized=True,
        content_hash="a" * 64,
        metadata_={"technique_ids": ["T1059.001"]},
        is_active=True,
        indexed_at=now,
    )
    chunk = RAGChunk(
        id=uuid4(),
        document=document,
        ordinal=0,
        content="T1059.001 PowerShell hunt evidence",
        content_hash="b" * 64,
        token_count=4,
    )
    candidate = rag._Candidate(
        chunk=chunk,
        document=document,
        signals={"exact", "fts"},
        mode_scores={"exact": 2 / 61, "fts": 1.25 / 61},
        fused_score=3.25 / 61,
    )

    payload = rag._candidate_to_item(candidate, "T1059.001").to_dict()

    assert payload["route"] == "/threat-hunting/hunt-1"
    assert payload["legal_sensitive"] is True
    assert payload["exact_match"] is True
    assert payload["lexical_score"] > 0
    assert payload["vector_score"] == 0
    assert payload["indexed_at"] == now.isoformat()
