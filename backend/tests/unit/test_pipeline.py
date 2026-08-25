import pytest
from unittest.mock import AsyncMock

from app.api.routes.pipeline import ingest_reports
from app.models.operations import ReportIntake
from app.services.atlas import normalize_atlas
from app.services.collection import extract_observables, misp_reports, stix_reports
from app.services import detections
from app.services.detections import generate_detection, generate_detection_with_ai, validate_detection


def test_extract_observables_deduplicates_and_validates_ipv4():
    values = extract_observables("CVE-2025-12345 at 8.8.8.8, 8.8.8.8, not 999.1.1.1")
    assert {(item["type"], item["normalized_value"]) for item in values} == {("cve", "cve-2025-12345"), ("ipv4", "8.8.8.8")}


def test_structured_import_normalizers():
    assert stix_reports({"objects": [{"type": "report", "name": "Test"}]})[0]["title"] == "Test"
    assert misp_reports({"Event": {"info": "MISP", "Attribute": [{"type": "domain", "value": "example.org"}]}})[0]["indicators"]
    assert normalize_atlas({"techniques": [{"id": "AML.T0001", "name": "Test"}]})["technique_count"] == 1


@pytest.mark.asyncio
async def test_report_ingestion_keeps_observables_candidate_only():
    class _Result:
        @staticmethod
        def scalar_one_or_none():
            return None

    class _Session:
        def __init__(self):
            self.execute = AsyncMock(return_value=_Result())
            self.added: list[object] = []

        def add(self, value):
            self.added.append(value)

    session = _Session()
    result = await ingest_reports(
        session,
        [
            {
                "title": "Candidate report",
                "url": "https://example.test/report",
                "summary": "Observed 8.8.8.8 in the report.",
                "indicators": [
                    {
                        "type": "ipv4",
                        "value": "8.8.8.8",
                        "normalized_value": "8.8.8.8",
                    }
                ],
            }
        ],
        "Example publisher",
        "manual report import",
    )

    assert result == {
        "items_created": 1,
        "observables_created": 0,
        "asset_retrohunt": None,
    }
    assert len(session.added) == 1
    assert isinstance(session.added[0], ReportIntake)
    assert session.added[0].indicators == [
        {
            "type": "ipv4",
            "value": "8.8.8.8",
            "normalized_value": "8.8.8.8",
        }
    ]


def test_detection_skeleton_is_valid_but_warns_about_placeholder():
    rule = generate_detection("PowerShell behavior", "T1059.001", "sigma", ["process_creation"])
    result = validate_detection("sigma", rule)
    assert result["valid"] is True
    assert result["warnings"]


def test_yaral_detection_skeleton_is_valid_but_warns_about_placeholder():
    rule = generate_detection("PowerShell Chronicle behavior", "T1059.001", "yaral", ["PROCESS_LAUNCH"])
    result = validate_detection("yaral", rule)
    assert result["valid"] is True
    assert result["warnings"]
    assert "$event.metadata.event_type" in rule


@pytest.mark.asyncio
async def test_ai_detection_generation_uses_adapter(monkeypatch):
    class FakeAdapter:
        provider = "local"
        model = "fake-model"

        async def _raw_complete(self, system: str, user: str) -> str:
            assert "Sigma" in user or "SIGMA" in user
            return """```yaml
title: AI Generated PowerShell
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
```"""

    monkeypatch.setattr(detections, "get_adapter", lambda provider, model=None: FakeAdapter())
    content, provider, model = await generate_detection_with_ai(
        "AI Generated PowerShell",
        "T1059.001",
        "sigma",
        ["process_creation"],
        context="PowerShell command execution",
        provider="local",
    )
    assert provider == "local"
    assert model == "fake-model"
    assert content.startswith("title: AI Generated PowerShell")
    assert validate_detection("sigma", content)["valid"] is True
