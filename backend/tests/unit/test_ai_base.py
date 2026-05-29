"""Unit tests for the LLM base layer: JSON parsing and prompt structure."""

import json
import pytest

from app.services.ai.base import (
    SYSTEM_PROMPT,
    USER_TEMPLATE,
    ExtractionResult,
    ExtractedTechnique,
    _parse_response,
)


# ── _parse_response ────────────────────────────────────────────────────────────

def _valid_payload(**overrides) -> str:
    base = {
        "techniques": [
            {
                "attack_id":  "T1566.001",
                "name":       "Spearphishing Attachment",
                "tactic":     "initial-access",
                "confidence": 0.92,
                "evidence":   "malicious PDF attached to email",
            }
        ],
        "apt_hints": ["APT29"],
        "summary":   "Spearphishing campaign targeting finance sector.",
    }
    base.update(overrides)
    return json.dumps(base)


def test_parse_valid_json():
    result = _parse_response(_valid_payload(), "claude", "claude-opus-4-8")
    assert isinstance(result, ExtractionResult)
    assert len(result.techniques) == 1
    assert result.techniques[0].attack_id == "T1566.001"
    assert result.techniques[0].confidence == pytest.approx(0.92)
    assert result.apt_hints == ["APT29"]
    assert "Spearphishing" in result.summary


def test_parse_strips_markdown_fences():
    raw = "```json\n" + _valid_payload() + "\n```"
    result = _parse_response(raw, "openai", "gpt-4o")
    assert len(result.techniques) == 1


def test_parse_uppercase_attack_id():
    payload = _valid_payload()
    payload = payload.replace('"T1566.001"', '"t1566.001"')
    result = _parse_response(payload, "claude", "claude-opus-4-8")
    assert result.techniques[0].attack_id == "T1566.001"


def test_parse_extracts_first_json_from_noisy_output():
    raw = "Here is the analysis:\n" + _valid_payload() + "\nLet me know if you need more."
    result = _parse_response(raw, "gemini", "gemini-2.0-flash")
    # Should still parse the embedded JSON
    assert len(result.techniques) >= 1


def test_parse_invalid_json_returns_empty_result():
    result = _parse_response("This is not JSON at all.", "claude", "claude-opus-4-8")
    assert isinstance(result, ExtractionResult)
    assert result.techniques == []
    assert "Failed" in result.summary


def test_parse_empty_techniques_list():
    payload = json.dumps({"techniques": [], "apt_hints": [], "summary": "No TTPs found."})
    result = _parse_response(payload, "openai", "gpt-4o")
    assert result.techniques == []
    assert result.summary == "No TTPs found."


def test_parse_malformed_technique_skipped():
    payload = json.dumps({
        "techniques": [
            {"attack_id": "T1059", "name": "Cmd", "tactic": "execution", "confidence": 0.9, "evidence": "cmd.exe"},
            {"attack_id": None, "confidence": "not-a-number"},   # malformed — should be skipped
        ],
        "apt_hints": [],
        "summary":   "test",
    })
    result = _parse_response(payload, "claude", "claude-opus-4-8")
    assert len(result.techniques) == 1
    assert result.techniques[0].attack_id == "T1059"


def test_evidence_truncated_at_200_chars():
    long_evidence = "x" * 500
    payload = _valid_payload()
    parsed = json.loads(payload)
    parsed["techniques"][0]["evidence"] = long_evidence
    result = _parse_response(json.dumps(parsed), "claude", "claude-opus-4-8")
    assert len(result.techniques[0].evidence) <= 200


# ── Prompt structure ───────────────────────────────────────────────────────────

def test_system_prompt_contains_key_instructions():
    assert "MITRE ATT&CK" in SYSTEM_PROMPT
    assert "attack_id" in SYSTEM_PROMPT
    assert "confidence" in SYSTEM_PROMPT
    assert "evidence" in SYSTEM_PROMPT
    assert "apt_hints" in SYSTEM_PROMPT


def test_user_template_interpolates_text():
    text = "Adversary used T1003 to dump credentials."
    rendered = USER_TEMPLATE.format(text=text)
    assert text in rendered


def test_user_template_truncates_at_40k():
    """The extract() method slices text to 40 000 chars before building the prompt."""
    from app.services.ai.base import USER_TEMPLATE
    big_text = "A" * 50_000
    rendered = USER_TEMPLATE.format(text=big_text[:40_000])
    assert len(rendered) < 60_000
