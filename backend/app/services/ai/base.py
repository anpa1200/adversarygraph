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


@dataclass
class ExtractionResult:
    techniques: list[ExtractedTechnique] = field(default_factory=list)
    apt_hints: list[str] = field(default_factory=list)   # group names the LLM mentions
    summary: str = ""
    raw_response: str = ""
    provider: str = ""
    model: str = ""


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior threat intelligence analyst specialising in the MITRE ATT&CK framework.

Your task: read the provided incident report, investigation notes, or threat intelligence text
and extract every observable adversary behaviour, mapping each one to the most precise
ATT&CK technique or sub-technique.

Return ONLY valid JSON — no markdown fences, no prose outside the JSON object.

Output schema:
{
  "techniques": [
    {
      "attack_id":  "T1566.001",
      "name":       "Spearphishing Attachment",
      "tactic":     "initial-access",
      "confidence": 0.92,
      "evidence":   "exact quoted phrase or paraphrase from the text"
    }
  ],
  "apt_hints": ["APT29", "Lazarus Group"],
  "summary":   "2-3 sentence TL;DR of the threat activity described"
}

Rules:
- Use official ATT&CK IDs (Txxxx or Txxxx.xxx). Prefer sub-techniques when evidence is specific.
- confidence: 1.0 = explicitly stated, 0.7 = strongly implied, 0.4 = weakly implied.
- evidence: quote ≤ 120 chars from the source text supporting the mapping.
- apt_hints: group names or aliases explicitly mentioned or strongly implied. Empty array if none.
- Include ALL techniques you can identify; do not truncate the list.
- tactic: use the ATT&CK kill-chain shortname (e.g. initial-access, execution, persistence …).
- If the text contains no detectable adversary behaviour, return empty arrays and explain in summary."""

USER_TEMPLATE = """Analyse the following text and extract ATT&CK technique mappings.

--- BEGIN TEXT ---
{text}
--- END TEXT ---"""


# ── Base adapter ──────────────────────────────────────────────────────────────

class LLMAdapter(ABC):
    """Common interface for Claude, OpenAI, and Gemini adapters."""

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

    async def extract(self, text: str) -> ExtractionResult:
        """Run extraction and parse the structured JSON response."""
        user_msg = USER_TEMPLATE.format(text=text[:40_000])  # guard against huge inputs
        raw = await self._raw_complete(SYSTEM_PROMPT, user_msg)
        return _parse_response(raw, self.provider, self.model)

    async def stream_extract(self, text: str) -> AsyncIterator[str]:
        """Stream raw tokens; caller is responsible for buffering and parsing."""
        user_msg = USER_TEMPLATE.format(text=text[:40_000])
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
        # Try to pull the first JSON object out of noisy output
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
            except json.JSONDecodeError:
                return ExtractionResult(raw_response=raw, provider=provider, model=model,
                                        summary="Failed to parse LLM response as JSON.")
        else:
            return ExtractionResult(raw_response=raw, provider=provider, model=model,
                                    summary="Failed to parse LLM response as JSON.")

    techniques = []
    for t in data.get("techniques", []):
        try:
            techniques.append(ExtractedTechnique(
                attack_id=str(t.get("attack_id", "")).upper(),
                name=str(t.get("name", "")),
                tactic=str(t.get("tactic", "")),
                confidence=float(t.get("confidence", 0.5)),
                evidence=str(t.get("evidence", ""))[:200],
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
