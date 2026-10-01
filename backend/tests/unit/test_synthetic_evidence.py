import pytest

from app.services import synthetic_evidence


@pytest.mark.asyncio
async def test_adapter_rejects_when_disabled(monkeypatch):
    settings = synthetic_evidence.get_settings()
    monkeypatch.setattr(settings, "evidenceforge_enabled", False)
    with pytest.raises(synthetic_evidence.SyntheticEvidenceError, match="disabled"):
        await synthetic_evidence.status()
