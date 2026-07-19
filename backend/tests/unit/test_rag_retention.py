from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.pipeline import AuditEvent
from app.services import rag_retention
from app.tasks import rag_retention as retention_tasks
from app.tasks.celery_app import celery_app


class _ReturnedRows:
    def __init__(self, values):
        self.values = list(values)

    def scalars(self):
        return self

    def all(self):
        return self.values


class _RetentionSession:
    def __init__(self, *, document_ids=(), assistance_ids=()):
        self.responses = {
            "rag_documents": list(document_ids),
            "rag_assistance": list(assistance_ids),
        }
        self.statements = []
        self.added = []

    async def execute(self, statement):
        self.statements.append(statement)
        return _ReturnedRows(self.responses[statement.table.name])

    def add(self, value):
        self.added.append(value)


@pytest.mark.asyncio
async def test_retention_batch_deletes_bounded_eligible_rows_and_audits_cutoffs():
    now = datetime(2026, 7, 19, 6, 0, tzinfo=timezone.utc)
    session = _RetentionSession(
        document_ids=[uuid4(), uuid4()],
        assistance_ids=[uuid4()],
    )

    result = await rag_retention.purge_rag_retention_batch(
        session,
        now=now,
        tombstone_retention_days=30,
        assistance_retention_days=90,
        batch_size=2,
        run_id="retention-test",
        batch_number=3,
    )

    assert result.tombstoned_documents_deleted == 2
    assert result.assistance_records_deleted == 1
    assert result.tombstone_cutoff.isoformat() == "2026-06-19T06:00:00+00:00"
    assert result.assistance_cutoff.isoformat() == "2026-04-20T06:00:00+00:00"
    assert result.has_more is True
    assert result.legal_hold_mode is False
    assert [statement.table.name for statement in session.statements] == [
        "rag_documents",
        "rag_assistance",
    ]
    document_delete = str(session.statements[0]).lower()
    assistance_delete = str(session.statements[1]).lower()
    assert "rag_documents.is_active is false" in document_delete
    assert document_delete.count("rag_documents.indexed_at <") >= 2
    assert assistance_delete.count("rag_assistance.created_at <") >= 2
    assert " limit " in document_delete
    assert " returning rag_documents.id" in document_delete

    assert len(session.added) == 1
    audit = session.added[0]
    assert isinstance(audit, AuditEvent)
    assert audit.actor == "system:rag-retention"
    assert audit.action == "rag.retention.purge"
    assert audit.object_id == "retention-test:batch-3"
    assert audit.details["tombstoned_documents_deleted"] == 2
    assert audit.details["assistance_records_deleted"] == 1
    assert audit.details["chunk_delete_cascade"] is True
    assert audit.details["proposal_delete_cascade"] is True
    assert "source_ids" not in audit.details


@pytest.mark.asyncio
async def test_zero_day_values_enable_audited_legal_hold_without_deletes():
    session = _RetentionSession()

    result = await rag_retention.purge_rag_retention_batch(
        session,
        now=datetime(2026, 7, 19, tzinfo=timezone.utc),
        tombstone_retention_days=0,
        assistance_retention_days=0,
        batch_size=100,
    )

    assert session.statements == []
    assert result.legal_hold_mode is True
    assert result.has_more is False
    assert result.tombstone_cutoff is None
    assert result.assistance_cutoff is None
    assert session.added[0].action == "rag.retention.legal_hold"
    assert session.added[0].details["backup_retention_unchanged"] is True


@pytest.mark.asyncio
async def test_retention_can_hold_one_record_family_independently():
    session = _RetentionSession(assistance_ids=[uuid4()])

    result = await rag_retention.purge_rag_retention_batch(
        session,
        tombstone_retention_days=0,
        assistance_retention_days=7,
        batch_size=10,
    )

    assert [statement.table.name for statement in session.statements] == [
        "rag_assistance"
    ]
    assert result.tombstoned_documents_deleted == 0
    assert result.assistance_records_deleted == 1
    assert result.legal_hold_mode is False


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"tombstone_retention_days": -1}, "tombstone_retention_days"),
        ({"assistance_retention_days": True}, "assistance_retention_days"),
        ({"batch_size": 0}, "batch_size"),
        ({"batch_number": 101}, "batch_number"),
    ],
)
@pytest.mark.asyncio
async def test_retention_rejects_unbounded_policy_inputs(kwargs, message):
    with pytest.raises(ValueError, match=message):
        await rag_retention.purge_rag_retention_batch(
            _RetentionSession(),
            tombstone_retention_days=kwargs.pop(
                "tombstone_retention_days", 30
            ),
            assistance_retention_days=kwargs.pop(
                "assistance_retention_days", 90
            ),
            **kwargs,
        )


class _TaskConnection:
    def __init__(self):
        self.commits = 0
        self.unlocks = 0
        self.closed = False

    async def scalar(self, _statement, _params):
        return True

    async def execute(self, _statement, _params):
        self.unlocks += 1

    async def commit(self):
        self.commits += 1

    async def invalidate(self):
        return None

    async def close(self):
        self.closed = True


class _TaskEngine:
    def __init__(self, connection):
        self.connection = connection
        self.disposals = 0

    async def connect(self):
        return self.connection

    async def dispose(self):
        self.disposals += 1


class _TaskSession:
    def __init__(self):
        self.commits = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def commit(self):
        self.commits += 1


def test_scheduled_retention_task_batches_commits_and_uses_corpus_lock(monkeypatch):
    connection = _TaskConnection()
    engine = _TaskEngine(connection)
    session = _TaskSession()
    calls = []

    def session_factory(*, bind, expire_on_commit):
        assert bind is connection
        assert expire_on_commit is False
        return session

    async def purge(db, *, run_id, batch_number):
        assert db is session
        calls.append((run_id, batch_number))
        return SimpleNamespace(
            tombstoned_documents_deleted=2 if batch_number == 1 else 1,
            assistance_records_deleted=1,
            has_more=batch_number == 1,
            legal_hold_mode=False,
        )

    monkeypatch.setattr(retention_tasks, "engine", engine)
    monkeypatch.setattr(retention_tasks, "AsyncSession", session_factory)
    monkeypatch.setattr(retention_tasks, "purge_rag_retention_batch", purge)
    monkeypatch.setattr(settings, "rag_retention_max_batches", 3)
    monkeypatch.setattr(settings, "rag_tombstone_retention_days", 30)
    monkeypatch.setattr(settings, "rag_assistance_retention_days", 90)

    outcome = retention_tasks.purge_rag_retention.run()

    assert outcome["status"] == "completed"
    assert outcome["tombstoned_documents_deleted"] == 3
    assert outcome["assistance_records_deleted"] == 2
    assert outcome["batches"] == 2
    assert outcome["limit_reached"] is False
    assert [number for _run_id, number in calls] == [1, 2]
    assert session.commits == 2
    assert connection.unlocks == 1
    assert connection.closed is True
    assert engine.disposals == 2


def test_retention_task_is_registered_on_the_daily_utc_schedule():
    schedule = celery_app.conf.beat_schedule["rag-retention-daily"]
    assert schedule["task"] == "rag.retention_purge"
    assert retention_tasks.purge_rag_retention.acks_late is True
    assert retention_tasks.purge_rag_retention.reject_on_worker_lost is True
    assert retention_tasks.purge_rag_retention.max_retries == 4
