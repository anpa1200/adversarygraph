from __future__ import annotations

import json

import pytest

from app.services.report_review_ai import _chunks, validate_ai_review_output


def _response(*, quote: str) -> str:
    return json.dumps(
        {
            "procedure_relevance": {
                "verdict": "supports_pass",
                "rationale": "The report describes a concrete behavior.",
                "evidence": [{"quote": quote}],
            },
            "procedure_claims": [
                {
                    "subject": "the adversary",
                    "action": "downloaded a payload",
                    "object": "payload.bin",
                    "context": "using PowerShell",
                    "attack_id": "T1059.001",
                    "quote": quote,
                }
            ],
            "actor_identification": {
                "verdict": "not_applicable",
                "basis": "none",
                "actor_name": "",
                "rationale": "No actor is named.",
                "evidence": [],
            },
            "publication_date_candidates": [],
        }
    )


def test_ai_evidence_binds_one_exact_source_span() -> None:
    quote = "The adversary downloaded payload.bin using PowerShell."
    source = f"Introduction.\n{quote}\nConclusion."

    advisory = validate_ai_review_output(_response(quote=quote), source, chunk_offset=200)

    claim = advisory["procedure_claims"][0]
    assert claim["evidence"]["quote"] == quote
    assert claim["evidence"]["start"] == 200 + source.index(quote)
    assert claim["evidence"]["end"] == claim["evidence"]["start"] + len(quote)


def test_ai_evidence_rejects_case_changed_or_ambiguous_quotes() -> None:
    quote = "The adversary downloaded payload.bin using PowerShell."

    case_changed = validate_ai_review_output(
        _response(quote=quote.lower()),
        quote,
    )
    repeated = validate_ai_review_output(
        _response(quote=quote),
        f"{quote}\n{quote}",
    )

    assert case_changed["procedure_claims"] == []
    assert case_changed["procedure_relevance"]["evidence"] == []
    assert repeated["procedure_claims"] == []
    assert repeated["procedure_relevance"]["evidence"] == []


def test_ai_output_rejects_trailing_or_prefixed_prose() -> None:
    quote = "The adversary downloaded payload.bin using PowerShell."

    with pytest.raises(ValueError, match="invalid structured output"):
        validate_ai_review_output(f"commentary\n{_response(quote=quote)}", quote)
    with pytest.raises(ValueError, match="invalid structured output"):
        validate_ai_review_output(f"{_response(quote=quote)}\ntrailing", quote)


def test_ai_chunking_covers_the_full_stored_report_limit() -> None:
    source = "x" * 120_000
    chunks = _chunks(source)

    assert len(chunks) == 5
    assert chunks[0][0] == 0
    assert chunks[-1][0] + len(chunks[-1][1]) == len(source)
