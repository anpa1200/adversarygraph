from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from celery.exceptions import Retry

from app.core import database as database_module
from app.models.rag import RAGIndexRun
from app.tasks import rag as rag_tasks
from app.tasks import celery_app as celery_module
from app.tasks.celery_app import celery_app


class _Result:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class _Connection:
    def __init__(self, *, lock_acquired=True):
        self.lock_acquired = lock_acquired
        self.commits = 0
        self.closed = False
        self.invalidated = False
        self.unlocks = 0

    async def scalar(self, _statement, _params):
        return self.lock_acquired

    async def execute(self, _statement, _params):
        self.unlocks += 1

    async def commit(self):
        self.commits += 1

    async def invalidate(self):
        self.invalidated = True

    async def close(self):
        self.closed = True


class _Engine:
    def __init__(self, connection):
        self.connection = connection
        self.disposals = 0

    async def connect(self):
        return self.connection

    async def dispose(self):
        self.disposals += 1


class _Session:
    def __init__(self, run):
        self.run = run
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def execute(self, _statement):
        return _Result(self.run)

    async def get(self, model, item_id):
        if model is RAGIndexRun and item_id == self.run.id:
            return self.run
        return None

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


class _QueueSession(_Session):
    def __init__(self, run):
        super().__init__(run)
        self.statements = []

    async def execute(self, statement, params=None):
        self.statements.append((str(statement), params))
        return _Result(None)

    async def scalar(self, _statement):
        return self.run


def test_only_rag_reconciliation_requeues_after_abrupt_worker_loss():
    assert celery_app.conf.task_acks_late is True
    assert not bool(celery_app.conf.task_reject_on_worker_lost)
    assert rag_tasks.reconcile_rag.acks_late is True
    assert rag_tasks.reconcile_rag.reject_on_worker_lost is True
    assert rag_tasks.reconcile_rag.max_retries is None


def test_running_staleness_uses_heartbeat_then_persisted_timestamps():
    now = datetime.now(timezone.utc)
    run = RAGIndexRun(
        status="running",
        heartbeat_at=now - timedelta(hours=3),
        started_at=now - timedelta(hours=4),
    )

    assert rag_tasks.rag_index_run_is_stale(run, now=now) is True
    run.heartbeat_at = now - timedelta(minutes=5)
    assert rag_tasks.rag_index_run_is_stale(run, now=now) is False
    run.status = "queued"
    assert rag_tasks.rag_index_run_is_stale(run, now=now) is False


@pytest.mark.parametrize(
    ("status", "heartbeat"),
    [
        ("queued", None),
        ("running", datetime.now(timezone.utc) - timedelta(hours=3)),
    ],
)
def test_scheduler_redispatches_abandoned_runs_under_enqueue_lock(
    monkeypatch,
    status,
    heartbeat,
):
    run = RAGIndexRun(
        id=uuid4(),
        status=status,
        source_types=["ioc"],
        include_embeddings=False,
        created_by="scheduler",
        heartbeat_at=heartbeat,
    )
    connection = _Connection()
    engine = _Engine(connection)
    session = _QueueSession(run)
    send_task = SimpleNamespace(calls=[])

    def record_send(name, *, args):
        send_task.calls.append((name, args))

    monkeypatch.setattr(database_module, "engine", engine)
    monkeypatch.setattr(database_module, "async_session_factory", lambda: session)
    monkeypatch.setattr(celery_module.settings, "rag_enabled", True)
    monkeypatch.setattr(celery_module.celery_app, "send_task", record_send)

    result = celery_module.queue_rag_reconcile.run()

    assert result == {
        "run_id": str(run.id),
        "status": status,
        "redispatched": True,
    }
    assert send_task.calls == [("rag.reconcile", (str(run.id),))]
    assert any("pg_advisory_xact_lock" in statement for statement, _ in session.statements)
    assert session.commits == 1
    assert engine.disposals == 2


def test_corpus_lock_contention_retries_without_touching_run_state(monkeypatch):
    connection = _Connection(lock_acquired=False)
    engine = _Engine(connection)

    monkeypatch.setattr(rag_tasks, "engine", engine)

    with pytest.raises(Retry):
        rag_tasks.reconcile_rag.run(str(uuid4()))

    assert connection.closed is True
    assert connection.unlocks == 0
    assert engine.disposals == 2


def test_scheduler_publish_failure_keeps_run_redispatchable(monkeypatch):
    run = RAGIndexRun(
        id=uuid4(),
        status="queued",
        source_types=["ioc"],
        include_embeddings=False,
        created_by="scheduler",
    )
    connection = _Connection()
    engine = _Engine(connection)
    session = _QueueSession(run)

    def fail_publish(_name, *, args):
        assert args == (str(run.id),)
        raise RuntimeError("broker unavailable")

    monkeypatch.setattr(database_module, "engine", engine)
    monkeypatch.setattr(database_module, "async_session_factory", lambda: session)
    monkeypatch.setattr(celery_module.settings, "rag_enabled", True)
    monkeypatch.setattr(celery_module.celery_app, "send_task", fail_publish)

    with pytest.raises(RuntimeError, match="broker unavailable"):
        celery_module.queue_rag_reconcile.run()

    assert run.status == "queued"
    assert run.completed_at is None
    assert session.commits == 1


def test_reconcile_uses_lock_connection_and_takes_over_redelivered_run(monkeypatch):
    run = RAGIndexRun(
        id=uuid4(),
        status="running",
        source_types=["ioc"],
        include_embeddings=False,
        created_by="test",
        worker_task_id="previous-celery-task",
        attempt_count=1,
        heartbeat_at=datetime.now(timezone.utc),
    )
    connection = _Connection()
    engine = _Engine(connection)
    session = _Session(run)
    session_arguments = []
    reconciliations = []

    def session_factory(*, bind, expire_on_commit):
        session_arguments.append((bind, expire_on_commit))
        return session

    async def reconcile(db, index_run, *, source_types, include_embeddings):
        reconciliations.append((db, index_run, source_types, include_embeddings))
        index_run.status = "completed"
        return SimpleNamespace(
            to_dict=lambda: {
                "status": "completed",
                "source_types": source_types,
            }
        )

    monkeypatch.setattr(rag_tasks, "engine", engine)
    monkeypatch.setattr(rag_tasks, "AsyncSession", session_factory)

    from app.services import rag as rag_service

    monkeypatch.setattr(rag_service, "reconcile_corpus", reconcile)

    result = rag_tasks.reconcile_rag.run(str(run.id))

    assert result == {
        "run_id": str(run.id),
        "status": "completed",
        "source_types": ["ioc"],
    }
    assert session_arguments == [(connection, False)]
    assert reconciliations == [(session, run, ["ioc"], False)]
    assert run.attempt_count == 2
    assert run.status == "completed"
    assert run.worker_task_id != "previous-celery-task"
    assert session.commits == 2
    assert connection.unlocks == 1
    assert connection.closed is True
    assert connection.invalidated is False
    assert engine.disposals == 2
