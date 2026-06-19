"""
Shared types and base class for all LLM adapters.

Each adapter receives plain text and returns an ExtractionResult
containing identified ATT&CK techniques + APT hints.
The structured response is enforced via a JSON schema in the system prompt —
no function-calling required, works with all three providers uniformly.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator


# ── Output schema ─────────────────────────────────────────────────────────────

@dataclass
class ExtractedTechnique:
    attack_id: str          # e.g. T1566.001
    name: str
    tactic: str             # kill-chain phase shortname
    confidence: float       # 0.0 – 1.0
    evidence: str           # verbatim snippet from the input text
    review_status: str = "suggested"  # suggested | accepted | rejected | needs-evidence
    evidence_start: int | None = None
    evidence_end: int | None = None
    evidence_source: str = "llm"


@dataclass
class ExtractionResult:
    techniques: list[ExtractedTechnique] = field(default_factory=list)
    apt_hints: list[str] = field(default_factory=list)   # group names the LLM mentions
    summary: str = ""
    raw_response: str = ""
    provider: str = ""
    model: str = ""


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior threat intelligence analyst specialising in MITRE ATT&CK and MITRE ATLAS.

Your task: read the provided incident report, investigation notes, or threat intelligence text
and extract every observable adversary behaviour, mapping each one to the most precise
technique or sub-technique in the requested framework/domain.

Return ONLY valid JSON — no markdown fences, no prose outside the JSON object.

Output schema:
{
  "techniques": [
    {
      "attack_id":  "T1566.001",
      "name":       "Spearphishing Attachment",
      "tactic":     "initial-access",
      "confidence": 0.92,
      "evidence":   "exact quoted phrase from the text",
      "review_status": "suggested",
      "evidence_start": 123,
      "evidence_end": 184,
      "evidence_source": "source-text"
    }
  ],
  "apt_hints": ["APT29", "Lazarus Group"],
  "summary":   "2-3 sentence TL;DR of the threat activity described"
}

Rules:
- For Enterprise, Mobile, or ICS ATT&CK domains, use official ATT&CK IDs (Txxxx or Txxxx.xxx).
- For the MITRE ATLAS domain, use official ATLAS IDs (AML.Txxxx or AML.Txxxx.xxx).
- Prefer sub-techniques when evidence is specific.
- confidence: 1.0 = explicitly stated, 0.7 = strongly implied, 0.4 = weakly implied.
- evidence: quote ≤ 120 chars from the source text supporting the mapping.
- review_status: always "suggested" for generated mappings.
- evidence_start/evidence_end: character offsets of the supporting evidence in the source text when you can identify them; null if unknown.
- evidence_source: use "source-text" when the evidence is directly quoted from the input, otherwise "llm".
- apt_hints: group names or aliases explicitly mentioned or strongly implied. Empty array if none.
- Include ALL techniques you can identify; do not truncate the list.
- tactic: use the framework kill-chain shortname (for example initial-access, execution, persistence, reconnaissance).
- If the text contains no detectable adversary behaviour, return empty arrays and explain in summary."""

USER_TEMPLATE = """Analyse the following text and extract technique mappings for this framework/domain:
{domain}

--- BEGIN TEXT ---
{text}
--- END TEXT ---"""


# ── Base adapter ──────────────────────────────────────────────────────────────

class LLMAdapter(ABC):
    """Common interface for cloud and local LLM adapters."""

    @property
    @abstractmethod
    def provider(self) -> str: ...

    @property
    @abstractmethod
    def model(self) -> str: ...

    @abstractmethod
    async def _raw_complete(self, system: str, user: str) -> str:
        """Return the full response text (non-streaming)."""
        ...

    @abstractmethod
    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        """Yield response text chunks as they arrive."""
        ...

    async def extract(self, text: str, domain: str = "enterprise-attack") -> ExtractionResult:
        """Run extraction and parse the structured JSON response."""
        user_msg = USER_TEMPLATE.format(domain=domain, text=text[:40_000])  # guard against huge inputs
        raw = await self._raw_complete(SYSTEM_PROMPT, user_msg)
        result = _parse_response(raw, self.provider, self.model)
        bind_evidence_spans(result, text[:40_000])
        return result

    async def stream_extract(self, text: str, domain: str = "enterprise-attack") -> AsyncIterator[str]:
        """Stream raw tokens; caller is responsible for buffering and parsing."""
        user_msg = USER_TEMPLATE.format(domain=domain, text=text[:40_000])
        async for chunk in self._stream_complete(SYSTEM_PROMPT, user_msg):
            yield chunk


# ── JSON parser (shared) ──────────────────────────────────────────────────────

def _parse_response(raw: str, provider: str, model: str) -> ExtractionResult:
    """Extract JSON from the LLM response and build an ExtractionResult."""
    text = raw.strip()

    # Strip markdown code fences if the model added them anyway
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try to decode the first complete JSON object from noisy output.
        # raw_decode stops at the end of the first object rather than
        # greedily consuming everything up to the last closing brace.
        try:
            start = text.index("{")
            data, _ = json.JSONDecoder().raw_decode(text, start)
        except (ValueError, json.JSONDecodeError):
            return ExtractionResult(raw_response=raw, provider=provider, model=model,
                                    summary="Failed to parse LLM response as JSON.")

    techniques = []
    for t in data.get("techniques", []):
        try:
            status = str(t.get("review_status", "suggested")).lower()
            if status not in {"suggested", "accepted", "rejected", "needs-evidence"}:
                status = "suggested"
            techniques.append(ExtractedTechnique(
                attack_id=str(t.get("attack_id", "")).upper(),
                name=str(t.get("name", "")),
                tactic=str(t.get("tactic", "")),
                confidence=float(t.get("confidence", 0.5)),
                evidence=str(t.get("evidence", ""))[:200],
                review_status=status,
                evidence_start=_optional_int(t.get("evidence_start")),
                evidence_end=_optional_int(t.get("evidence_end")),
                evidence_source=str(t.get("evidence_source", "llm"))[:80],
            ))
        except (TypeError, ValueError):
            continue

    return ExtractionResult(
        techniques=techniques,
        apt_hints=[str(h) for h in data.get("apt_hints", [])],
        summary=str(data.get("summary", "")),
        raw_response=raw,
        provider=provider,
        model=model,
    )


def _optional_int(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def bind_evidence_spans(result: ExtractionResult, source_text: str) -> ExtractionResult:
    """
    Best-effort evidence binding for generated mappings.

    Providers often omit offsets even when they quote source evidence. When the
    quoted evidence appears verbatim in the source text, bind character offsets
    locally so reviewers can distinguish source-backed mappings from weaker LLM
    paraphrases.
    """
    if not source_text:
        return result

    lowered = source_text.lower()
    for technique in result.techniques:
        if technique.evidence_start is not None and technique.evidence_end is not None:
            continue
        evidence = technique.evidence.strip().strip('"')
        if len(evidence) < 8:
            technique.evidence_source = technique.evidence_source or "llm"
            continue
        idx = lowered.find(evidence.lower())
        if idx >= 0:
            technique.evidence_start = idx
            technique.evidence_end = idx + len(evidence)
            technique.evidence_source = "source-text"
        elif not technique.evidence_source:
            technique.evidence_source = "llm"
    return result


def technique_to_record(technique: ExtractedTechnique) -> dict:
    """Serialize extracted technique records consistently for JSONB storage."""
    return {
        "attack_id": technique.attack_id,
        "name": technique.name,
        "tactic": technique.tactic,
        "confidence": technique.confidence,
        "evidence": technique.evidence,
        "review_status": technique.review_status,
        "evidence_start": technique.evidence_start,
        "evidence_end": technique.evidence_end,
        "evidence_source": technique.evidence_source,
    }
