import json

import pytest

from app.services import rag_ai


def _sources():
    return [
        rag_ai.PromptSource(
            ref="S1",
            source_type="technique",
            source_id="T1566",
            title="Phishing",
            excerpt="Adversaries may send phishing messages to gain access.",
            route="/navigator?technique=T1566",
            tlp="TLP:CLEAR",
            score=0.9,
            metadata={"technique_ids": ["T1566"]},
        )
    ]


def test_parse_output_is_strict_and_requires_exact_schema():
    parsed = rag_ai.parse_output(json.dumps({
        "answer": "Phishing may be relevant [S1].",
        "cited_source_ids": ["S1"],
        "relevant_source_ids": ["S1"],
        "cautions": [],
        "navigator_proposal": None,
    }))
    assert parsed.cited_source_ids == ["S1"]

    with pytest.raises(rag_ai.RAGOutputError):
        rag_ai.parse_output(json.dumps({
            "answer": "unsupported",
            "cited_source_ids": ["S1"],
            "relevant_source_ids": [],
            "cautions": [],
            "navigator_proposal": None,
            "tool_call": "apply layer",
        }))

    with pytest.raises(rag_ai.RAGOutputError, match="without Markdown fences"):
        rag_ai.parse_output(f"```json\n{json.dumps(parsed.model_dump())}\n```")


@pytest.mark.asyncio
async def test_sanitize_rejects_unverified_or_missing_citation_markers(monkeypatch):
    with pytest.raises(rag_ai.RAGOutputError, match="citation markers"):
        await rag_ai.sanitize_output(
            rag_ai.parse_output(json.dumps({
                "answer": "Claim [S2]",
                "cited_source_ids": ["S1"],
                "relevant_source_ids": [],
                "cautions": [],
                "navigator_proposal": None,
            })),
            sources=_sources(),
            domain="enterprise-attack",
            db=object(),
        )

    with pytest.raises(rag_ai.RAGOutputError, match="omitted"):
        await rag_ai.sanitize_output(
            rag_ai.parse_output(json.dumps({
                "answer": "Claim without marker",
                "cited_source_ids": ["S1"],
                "relevant_source_ids": [],
                "cautions": [],
                "navigator_proposal": None,
            })),
            sources=_sources(),
            domain="enterprise-attack",
            db=object(),
        )


@pytest.mark.asyncio
async def test_sanitize_locally_verifies_navigator_ids(monkeypatch):
    async def verify(_db, values, *, domain):
        assert domain == "enterprise-attack"
        return [value for value in values if value == "T1566"], ["removed one"]

    monkeypatch.setattr(rag_ai.governed_ai, "verify_technique_ids", verify)
    output, warnings = await rag_ai.sanitize_output(
        rag_ai.parse_output(json.dumps({
            "answer": "Use the cited behavior [S1].",
            "cited_source_ids": ["S1"],
            "relevant_source_ids": ["S1"],
            "cautions": [],
            "navigator_proposal": {
                "name": "Reviewed phishing behaviors",
                "technique_ids": ["T1566", "T9999"],
                "rationale": "The retrieved source supports phishing behavior.",
            },
        })),
        sources=_sources(),
        domain="enterprise-attack",
        db=object(),
    )
    assert output["navigator_proposal"]["technique_ids"] == ["T1566"]
    assert warnings == [
        "Removed 1 Navigator technique(s) not present in the cited evidence.",
        "removed one",
    ]


@pytest.mark.asyncio
async def test_navigator_proposal_can_only_use_ids_in_cited_evidence(monkeypatch):
    sources = [
        *_sources(),
        rag_ai.PromptSource(
            ref="S2",
            source_type="technique",
            source_id="T1059.001",
            title="PowerShell",
            excerpt="PowerShell execution maps to T1059.001.",
            route="/navigator?technique=T1059.001",
            tlp="TLP:CLEAR",
            score=0.8,
            metadata={"technique_ids": ["T1059.001"]},
        ),
    ]

    async def verify(_db, values, *, domain):
        assert domain == "enterprise-attack"
        assert values == []
        return [], []

    monkeypatch.setattr(rag_ai.governed_ai, "verify_technique_ids", verify)
    output, warnings = await rag_ai.sanitize_output(
        rag_ai.parse_output(json.dumps({
            "answer": "Only the phishing evidence is cited [S1].",
            "cited_source_ids": ["S1"],
            "relevant_source_ids": ["S1", "S2"],
            "cautions": [],
            "navigator_proposal": {
                "name": "Unsupported from uncited evidence",
                "technique_ids": ["T1059.001"],
                "rationale": "This ID appears only in S2.",
            },
        })),
        sources=sources,
        domain="enterprise-attack",
        db=object(),
    )

    assert output["navigator_proposal"] is None
    assert any("not present in the cited evidence" in warning for warning in warnings)


@pytest.mark.asyncio
async def test_declared_citations_must_exactly_match_answer_markers():
    sources = [
        *_sources(),
        rag_ai.PromptSource(
            ref="S2",
            source_type="cve",
            source_id="CVE-2026-12345",
            title="Example CVE",
            excerpt="An example vulnerability.",
            route="/cve?cve=CVE-2026-12345",
            tlp="TLP:CLEAR",
            score=0.7,
            metadata={},
        ),
    ]
    with pytest.raises(rag_ai.RAGOutputError, match="exactly match"):
        await rag_ai.sanitize_output(
            rag_ai.parse_output(json.dumps({
                "answer": "Only one source is used [S1].",
                "cited_source_ids": ["S1", "S2"],
                "relevant_source_ids": [],
                "cautions": [],
                "navigator_proposal": None,
            })),
            sources=sources,
            domain="enterprise-attack",
            db=object(),
        )


def test_build_sources_enforces_context_budget():
    sources, warnings = rag_ai.build_sources([
        {
            "source_type": "report",
            "source_id": "1",
            "title": "Long report",
            "excerpt": "x" * 8_000,
        }
    ], max_context_chars=4_000)
    _, prompt = rag_ai.rag_prompt(
        question="",
        domain="enterprise-attack",
        sources=sources,
        business_context=None,
    )
    assert len(sources[0].excerpt) < 4_000
    assert len(prompt) <= 4_000
    assert warnings


def test_context_budget_includes_question_profile_titles_and_metadata():
    question = "Which evidence is relevant?" * 50
    business_context = {
        "name": "Israel technology company",
        "sector": "technology",
        "region": "Israel",
        "technologies": ["Kubernetes"] * 100,
        "crown_jewels": ["source code"] * 100,
    }
    items = [
        {
            "source_type": "analysis_report",
            "source_id": str(index),
            "title": "T" * 700,
            "excerpt": "evidence " * 800,
            "metadata": {"products": ["product-name" * 10] * 50},
        }
        for index in range(20)
    ]
    sources, warnings = rag_ai.build_sources(
        items,
        max_context_chars=8_000,
        question=question,
        business_context=business_context,
    )
    _, prompt = rag_ai.rag_prompt(
        question=question,
        domain="enterprise-attack",
        sources=sources,
        business_context=business_context,
    )

    assert sources
    assert len(prompt) <= 8_000
    assert warnings
