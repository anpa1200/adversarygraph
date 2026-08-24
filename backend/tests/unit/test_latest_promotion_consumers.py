from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.models.asset_surface import AssetRegistryItem
from app.services import asset_intel, opencti_sync


class _Rows:
    def __init__(self, *, scalar_rows=None, tuple_rows=None):
        self._scalar_rows = list(scalar_rows or [])
        self._tuple_rows = list(tuple_rows or [])

    def scalars(self):
        return SimpleNamespace(all=lambda: list(self._scalar_rows))

    def all(self):
        return list(self._tuple_rows)


class _SequenceSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.added = []
        self.commits = 0

    async def execute(self, _statement):
        assert self._responses, "unexpected database query"
        return self._responses.pop(0)

    def add(self, value):
        self.added.append(value)

    async def commit(self):
        self.commits += 1

    def assert_drained(self):
        assert self._responses == []


def _active(mode: str, candidate):
    if mode == "newer_draft":
        return None
    if mode == "different_current_promotion":
        return SimpleNamespace(
            promotion=SimpleNamespace(
                id=uuid4(),
                targets=["canonical_intelligence", "exports"],
            )
        )
    return SimpleNamespace(promotion=candidate)


@pytest.mark.parametrize(
    ("latest_state", "expected_report_use"),
    [
        pytest.param("newer_draft", False, id="newer-draft-blocks-older-promotion"),
        pytest.param("different_current_promotion", False, id="stale-promotion-id-is-not-current"),
        pytest.param("exact_current_promotion", True, id="exact-current-promotion"),
    ],
)
async def test_asset_retrohunt_requires_exact_latest_promotion(
    monkeypatch,
    latest_state,
    expected_report_use,
):
    analysis_session_id = uuid4()
    candidate_promotion = SimpleNamespace(
        id=uuid4(),
        targets=["canonical_intelligence", "exports"],
    )
    report_session = SimpleNamespace(id=analysis_session_id)
    intake = SimpleNamespace(id=uuid4())
    selected_older_promotion_row = (
        intake,
        candidate_promotion,
        SimpleNamespace(state="promoted"),
        report_session,
        SimpleNamespace(),
    )
    asset = AssetRegistryItem(
        id=uuid4(),
        fingerprint="domain:portal.example.test",
        name="portal.example.test",
        asset_type="web-app",
        environment="production",
        exposure="internet",
        criticality="high",
        ip_addresses=[],
        domains=["portal.example.test"],
        ports=[443],
        technologies=[],
        products=[],
        suppliers=[],
        dependencies=[],
        technique_ids=[],
        tags=[],
        labels={},
        raw={},
    )
    session = _SequenceSession(
        [
            _Rows(scalar_rows=[asset]),
            _Rows(),
            _Rows(),
            _Rows(),
            _Rows(tuple_rows=[selected_older_promotion_row]),
            _Rows(),
            _Rows(),
        ]
    )
    authority = AsyncMock(return_value=_active(latest_state, candidate_promotion))
    match_report = Mock(return_value=None)
    monkeypatch.setattr(asset_intel, "get_active_report_promotion", authority)
    monkeypatch.setattr(asset_intel, "_match_report", match_report)

    await asset_intel.retrohunt_assets(session)

    authority.assert_awaited_once_with(session, analysis_session_id)
    assert match_report.call_count == int(expected_report_use)
    session.assert_drained()


@pytest.mark.parametrize(
    ("latest_state", "expected_report_push"),
    [
        pytest.param("newer_draft", False, id="newer-draft-blocks-older-promotion"),
        pytest.param("different_current_promotion", False, id="stale-promotion-id-is-not-current"),
        pytest.param("exact_current_promotion", True, id="exact-current-promotion"),
    ],
)
async def test_opencti_report_push_requires_exact_latest_promotion(
    monkeypatch,
    latest_state,
    expected_report_push,
):
    analysis_session_id = uuid4()
    candidate_promotion = SimpleNamespace(
        id=uuid4(),
        targets=["canonical_intelligence", "exports"],
    )
    report = SimpleNamespace(id=analysis_session_id)
    selected_older_promotion_row = (
        report,
        SimpleNamespace(),
        candidate_promotion,
        SimpleNamespace(state="promoted"),
        SimpleNamespace(),
    )
    session = _SequenceSession(
        [
            _Rows(),
            _Rows(tuple_rows=[selected_older_promotion_row]),
        ]
    )
    authority = AsyncMock(return_value=_active(latest_state, candidate_promotion))
    authorize_indicators = AsyncMock(return_value=set())
    graphql = AsyncMock(return_value={})
    mark_source = AsyncMock()
    serialize = Mock(return_value={"name": "reviewed report"})
    monkeypatch.setattr(opencti_sync, "_require_config", lambda: None)
    monkeypatch.setattr(opencti_sync, "get_active_report_promotion", authority)
    monkeypatch.setattr(
        opencti_sync,
        "authorized_report_promotion_indicator_ids",
        authorize_indicators,
    )
    monkeypatch.setattr(opencti_sync, "_analysis_session_to_report_input", serialize)
    monkeypatch.setattr(opencti_sync, "_graphql", graphql)
    monkeypatch.setattr(opencti_sync, "_mark_opencti_source", mark_source)

    result = await opencti_sync.push_to_opencti(session, limit=5)

    authority.assert_awaited_once_with(session, analysis_session_id)
    assert result["pushed_reports"] == int(expected_report_push)
    assert result["skipped"] == int(not expected_report_push)
    assert serialize.call_count == int(expected_report_push)
    assert graphql.await_count == int(expected_report_push)
    assert session.commits == 1
    session.assert_drained()
