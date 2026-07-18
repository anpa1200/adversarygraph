import uuid

import pytest

from app.models.threat_radar import ThreatHuntRequest
from app.models.threat_radar import ThreatCase
from app.services.threat_radar import create_action


class RecordingSession:
    def __init__(self):
        self.rows = []

    def add(self, row):
        self.rows.append(row)


def test_threat_hunt_request_telemetry_sources_aliases_legacy_column():
    hunt = ThreatHuntRequest(
        case_id=None,
        title="Standalone hunt",
        hypothesis="A testable behavior may be visible in endpoint telemetry.",
        telemetry=["edr_process"],
    )

    assert hunt.telemetry_sources == ["edr_process"]

    hunt.telemetry_sources = ["identity_logs", "cloud_audit"]

    assert hunt.telemetry == ["identity_logs", "cloud_audit"]


@pytest.mark.asyncio
async def test_threat_radar_hunt_action_populates_canonical_context():
    case = ThreatCase(
        id=uuid.uuid4(),
        title="Exposed gateway exploitation",
        summary="Active exploitation may affect the production gateway.",
        priority="P1 High",
        tlp="TLP:CLEAR",
        product_context=[{"technique_ids": ["T1190"]}],
        tags=["exposure:internet", "customer-facing"],
    )
    session = RecordingSession()

    hunt = await create_action(session, case, "hunt", "hunt-analyst")

    assert isinstance(hunt, ThreatHuntRequest)
    assert hunt.case_id == case.id
    assert hunt.source_type == "threat_radar"
    assert hunt.source_ref == str(case.id)
    assert hunt.priority == "P1 High"
    assert hunt.tlp == "TLP:CLEAR"
    assert hunt.owner == "hunt-analyst"
    assert hunt.created_by == "hunt-analyst"
    assert hunt.telemetry_sources == hunt.telemetry
    assert "T1190" in hunt.technique_ids
    assert "web_access_logs" in hunt.telemetry_sources


@pytest.mark.asyncio
async def test_threat_radar_hunt_action_sanitizes_legacy_context():
    case = ThreatCase(
        id=uuid.uuid4(),
        title="x" * 600,
        summary="y" * 21_000,
        priority="urgent",
        tlp="internal-only",
        product_context=[{"technique_ids": ["T1190", "not-a-technique"]}],
        tags=["customer-facing", "T1059.001", " "],
    )
    session = RecordingSession()

    hunt = await create_action(session, case, "hunt", "analyst")

    assert len(hunt.title) == 500
    assert len(hunt.description) == 20_000
    assert hunt.priority == "P2 Medium"
    assert hunt.tlp == "TLP:RED"
    assert hunt.technique_ids == ["T1059.001", "T1190"]
    assert hunt.tags == ["customer-facing", "T1059.001"]
