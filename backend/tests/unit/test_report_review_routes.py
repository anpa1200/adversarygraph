from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.api.routes import report_review as route
from app.api.routes import analyze as analyze_route
from app.services.auth import TeamUser


class _DB:
    def __init__(self, promotion=None):
        self.promotion = promotion
        self.rollbacks = 0

    async def get(self, _model, _identifier):
        return self.promotion

    async def rollback(self):
        self.rollbacks += 1

    async def scalar(self, _statement):
        return None


def _user() -> TeamUser:
    return TeamUser(
        name="Independent Reviewer",
        roles=["security_admin"],
        user_id="reviewer-2",
        auth_source="local",
    )


@pytest.mark.asyncio
async def test_promote_materializes_before_commit_then_queues_rag(monkeypatch):
    session_id = uuid4()
    promotion = SimpleNamespace(
        id=uuid4(),
        targets=["canonical_intelligence", "rag"],
    )
    events: list[str] = []

    async def promote(*_args, **_kwargs):
        events.append("workflow")
        return SimpleNamespace(), promotion

    async def materialize(*_args, **_kwargs):
        events.append("materialize")
        return {"indicator_count": 1}

    async def retrohunt(*_args, **_kwargs):
        events.append("retrohunt")
        return {"assets_checked": 2}

    async def finish(*_args, **_kwargs):
        events.append("commit")
        return {"state": "promoted"}

    async def queue(*_args, **_kwargs):
        events.append("rag")
        return {"status": "queued", "queued": True}

    async def lock(*_args, **_kwargs):
        return SimpleNamespace(id=session_id)

    monkeypatch.setattr(route.reviews, "lock_review_source", lock)
    monkeypatch.setattr(route.reviews, "promote_review", promote)
    monkeypatch.setattr(route, "materialize_report_promotion", materialize)
    monkeypatch.setattr(route, "retrohunt_assets", retrohunt)
    monkeypatch.setattr(route, "_finish_mutation", finish)
    monkeypatch.setattr(route, "_queue_rag_refresh", queue)

    value = await route.promote_report_review(
        session_id,
        route.PromotionBody(expected_version=7, target="rag"),
        _DB(),
        _user(),
    )

    assert events == ["workflow", "materialize", "retrohunt", "commit", "rag"]
    assert value["state"] == "promoted"
    assert value["downstream_refresh"]["materialized"]["indicator_count"] == 1


@pytest.mark.asyncio
async def test_revoke_withdraws_before_commit_then_queues_cleanup(monkeypatch):
    session_id = uuid4()
    promotion = SimpleNamespace(
        id=uuid4(),
        targets=["canonical_intelligence", "rag"],
    )
    revocation = SimpleNamespace(id=uuid4(), promotion_id=promotion.id)
    events: list[str] = []

    async def revoke(*_args, **_kwargs):
        events.append("workflow")
        return SimpleNamespace(), revocation

    async def withdraw(*_args, **_kwargs):
        events.append("withdraw")
        return {"withdrawn_ioc_count": 1}

    async def retrohunt(*_args, **_kwargs):
        events.append("retrohunt")
        return {"assets_checked": 2}

    async def finish(*_args, **_kwargs):
        events.append("commit")
        return {"state": "revoked"}

    async def queue(*_args, **_kwargs):
        events.append("rag")
        return {"status": "queued", "queued": True}

    async def lock(*_args, **_kwargs):
        return SimpleNamespace(id=session_id)

    monkeypatch.setattr(route.reviews, "lock_review_source", lock)
    monkeypatch.setattr(route.reviews, "revoke_promotion", revoke)
    monkeypatch.setattr(route, "withdraw_report_promotion", withdraw)
    monkeypatch.setattr(route, "retrohunt_assets", retrohunt)
    monkeypatch.setattr(route, "_finish_mutation", finish)
    monkeypatch.setattr(route, "_queue_rag_refresh", queue)

    value = await route.revoke_report_promotion(
        session_id,
        route.ReasonBody(expected_version=8, reason="Source authenticity was disproven."),
        _DB(promotion),
        _user(),
    )

    assert events == ["workflow", "withdraw", "retrohunt", "commit", "rag"]
    assert value["state"] == "revoked"
    assert value["downstream_refresh"]["withdrawn"]["withdrawn_ioc_count"] == 1


@pytest.mark.asyncio
async def test_post_mutation_invalidation_still_finds_promotion_for_cleanup(monkeypatch):
    session_id = uuid4()
    promotion = SimpleNamespace(
        id=uuid4(),
        targets=["canonical_intelligence", "rag"],
    )
    calls: list[tuple[str, object]] = []

    async def active(_db, _session_id, *, verify_current=True):
        calls.append(("lookup", verify_current))
        return promotion

    async def withdraw(_db, value):
        calls.append(("withdraw", value.id))
        return {}

    async def retrohunt(_db):
        calls.append(("retrohunt", None))
        return {}

    async def invalidate(*_args, **_kwargs):
        calls.append(("invalidate", None))
        return SimpleNamespace(profile="external_cti")

    async def restart(*_args, **_kwargs):
        calls.append(("restart", None))

    monkeypatch.setattr(analyze_route, "active_promotion", active)
    monkeypatch.setattr(analyze_route, "withdraw_report_promotion", withdraw)
    monkeypatch.setattr("app.services.asset_intel.retrohunt_assets", retrohunt)
    monkeypatch.setattr(analyze_route, "invalidate_review", invalidate)
    monkeypatch.setattr(analyze_route, "_start_review_with_preflight", restart)

    refresh_rag = await analyze_route._restart_review_after_change(
        _DB(),
        session_id,
        _user(),
        reason="source_changed",
    )

    assert refresh_rag is True
    assert calls == [
        ("lookup", False),
        ("withdraw", promotion.id),
        ("retrohunt", None),
        ("invalidate", None),
        ("restart", None),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        analyze_route.ReportEditRequest(publisher="Updated Publisher"),
        analyze_route.ReportEditRequest(source_text="Original source text"),
        analyze_route.ReportEditRequest(source_url=""),
    ],
)
async def test_partial_linked_report_edits_initialize_source_change_flags(
    monkeypatch,
    body,
):
    session_id = uuid4()
    session = SimpleNamespace(
        id=session_id,
        status="completed",
        name="Report",
        source_text="Original source text",
        source_provenance={},
        filename=None,
        tlp="TLP:AMBER+STRICT",
    )
    result = SimpleNamespace(summary="Original summary")
    intake = SimpleNamespace(
        title="Report",
        url="",
        publisher="Original Publisher",
        summary="Original summary",
        provenance={},
    )

    class EditDB:
        commits = 0

        async def scalar(self, _statement):
            return result

        async def commit(self):
            self.commits += 1

    db = EditDB()

    async def lock(*_args, **_kwargs):
        return session

    async def find_intake(*_args, **_kwargs):
        return intake

    async def restart(*_args, **_kwargs):
        return False

    async def no_op(*_args, **_kwargs):
        return None

    async def response(*_args, **_kwargs):
        return {"session_id": str(session_id)}

    monkeypatch.setattr(analyze_route, "lock_review_source", lock)
    monkeypatch.setattr(analyze_route, "_find_report_intake_for_session", find_intake)
    monkeypatch.setattr(analyze_route, "_restart_review_after_change", restart)
    monkeypatch.setattr(analyze_route, "audit", no_op)
    monkeypatch.setattr(analyze_route, "_queue_report_review_rag_refresh", no_op)
    monkeypatch.setattr(analyze_route, "linked_report", response)

    value = await analyze_route.edit_linked_report(
        str(session_id),
        body,
        db,
        _user(),
    )

    assert value == {"session_id": str(session_id)}
    assert db.commits == 1


@pytest.mark.asyncio
async def test_remote_ai_failure_keeps_durable_egress_attempt_and_outcome(
    monkeypatch,
):
    from app.services import report_review_ai

    session_id = uuid4()
    review_id = uuid4()
    audit_actions: list[str] = []

    class AuditDB:
        commits = 0
        rollbacks = 0

        async def commit(self):
            self.commits += 1

        async def rollback(self):
            self.rollbacks += 1

    db = AuditDB()

    async def assessment(*_args, **_kwargs):
        return {
            "id": str(review_id),
            "state": "draft",
            "version": 3,
            "revision": 1,
            "source_checksum": "a" * 64,
            "analysis_checksum": "b" * 64,
        }

    async def context(*_args, **_kwargs):
        return SimpleNamespace(
            source_text="Protected report source text",
            session=SimpleNamespace(tlp="TLP:AMBER+STRICT"),
        )

    async def provider_failure(*_args, **_kwargs):
        raise RuntimeError("provider unavailable")

    async def capture_audit(_db, _user, action, *_args, **_kwargs):
        audit_actions.append(action)

    monkeypatch.setattr(route.reviews, "assessment", assessment)
    monkeypatch.setattr(route.reviews, "load_review_context", context)
    monkeypatch.setattr(
        report_review_ai,
        "generate_ai_review_suggestions",
        provider_failure,
    )
    monkeypatch.setattr(route, "audit", capture_audit)

    with pytest.raises(RuntimeError, match="provider unavailable"):
        await route.assist_report_review(
            session_id,
            route.AIAssistBody(
                expected_version=3,
                provider="openai",
                cloud_processing_acknowledged=True,
            ),
            db,
            _user(),
        )

    assert audit_actions == [
        "report_review.ai_egress.attempt",
        "report_review.ai_egress.failed",
    ]
    assert db.commits == 2
    assert db.rollbacks == 1
