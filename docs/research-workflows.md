# Durable Research Workflows

AdversaryGraph research workflows execute immutable project revisions through a
transactional outbox. The API, publisher, consumer, worker coordinators, and
recovery tasks all exchange detached, versioned authority; no ORM row or
uncommitted worker capability crosses those boundaries.

## API lifecycle

The `/api/research/projects` resource owns project scope and immutable
revisions. A caller with `manage_intel` can start the registered
`cti.research.scope` workflow with an idempotency token, inspect its ordered
stages, and cancel it with an explicit request UUID and expected workflow state
version. Repeating the exact cancellation command is an immutable replay;
changing its actor, reason, request UUID, or predecessor version is a conflict.

The atomic cancellation audit authority is the persisted `WorkflowRun` tuple:
`cancel_request_id`, `cancel_requested_by`, `cancel_requested_by_id`,
`cancel_reason`, and `cancel_requested_at` (with the matching terminal workflow
state and completion time). The API `AuditEvent` is a secondary projection for
operator search. If that projection is missing after a partial API failure, it
may be healed idempotently from the persisted request UUID and cancellation
facts; it must never be treated as permission to repeat or alter cancellation.
Before inserting a repair event, match the workflow object ID and
`details.request_id` against existing cancel and cancel-replay events; an
existing match makes the repair a no-op. Audit-event counts are therefore not
cancellation counts.

Only the built-in `research.project.scope@1` handler is registered by default.
Unknown stage types or versions fail closed. New handlers must use the generic
v1 stage config/checkpoint envelopes, register an exact `(stage_type,
stage_version)` pair during worker startup, and return a bounded immutable
handler result.

Before registering a handler that can run longer than one lease, make every
external side effect idempotent on stable workflow/stage/attempt or receipt
lineage and implement periodic receipt-bound heartbeats before lease expiry.
Checkpointing does not replace heartbeats. A handler that cannot safely replay
an interrupted side effect or renew its lease must not be registered as a
long-running workflow handler.

## Worker and outbox tasks

Celery Beat schedules three bounded tasks:

- `workflow.publish_due` claims and publishes due outbox messages.
- `workflow.recover_outbox` releases expired publisher or receipt leases.
- `workflow.recover_expired` recovers expired stage executions through the
  receipt-bound recovery coordinator.

The scheduled batch is 100 and every recovery boundary rejects values above
the worker maximum of 500. Beat entries expire one second before their next
cadence, so a stopped or congested worker does not later drain a stale periodic
backlog; each scan is level-triggered and the next fresh scan rediscovers any
still-due rows. Expiry does not terminate a task that has already started.

Run exactly one Celery Beat scheduler for these entries (or an HA scheduler
that itself provides singleton scheduling). The application does not hold a
distributed singleton lock across a pass: adding one would require another
coordination dependency and could span the distinct transaction/session
boundaries required by publisher and stage recovery. Database row locks and
the bounded coordinators remain the concurrency authority for worker tasks.

The broker message ID is fixed to the durable delivery identity. The consumer
validates the complete workflow, stage, attempt, message, delivery, cycle, and
receipt lineage before invoking a handler. It acknowledges only a validated,
commit-confirmed coordinator decision. Deterministically invalid or stale
authority is discarded without requeue; infrastructure failures are requeued
without including raw authority in task metadata or exception chaining.

Recovery tasks emit low-cardinality, privacy-safe log metrics for pass success,
pass failure, and stored-contract quarantine signals. They include only the
recovery kind, count, recovered-row count, and exception class--never workflow
authority, connection strings, exception text, or secrets. Aggregate the
`adversarygraph_workflow_recovery_*_total` metric fields in the deployment log
pipeline. A stored-contract quarantine signal is diagnostic only: it does not
mutate or automatically quarantine data.

## Lock and mutation authority

Worker mutations use the canonical lock order `W -> all S -> all M -> all D ->
all A`, followed by a fresh database clock. Heartbeat, checkpoint, completion,
failure, explicit cancellation, and expired-stage recovery each reserve and
consume a transaction-local, single-use authority. Cancellation writes active
delivery rows before their messages, then attempts, stages in plan order, and
the workflow aggregate. Delivered message/receipt evidence remains immutable.

Legacy direct heartbeat, checkpoint, completion, failure, cancellation, and
recovery mutators are pre-SQL conflict fences. Application code must call the
commit-owning coordinators in `workflow_worker.py`.

## Deployment and recovery

Apply Alembic through `20260824_0004` before starting any API, Celery worker, or
Beat process. The contract migration fails closed if active v1 workflows have
an incomplete stage set, a running attempt without exact delivered receipt
evidence, or incompatible live outbox authority. Do not bypass this preflight
with `alembic stamp`.

Drain workers before the contract upgrade. If the preflight rejects historical
expand-era rows, repair them from retained broker and audit evidence or
quarantine the affected workflow under an operator-reviewed procedure. After
upgrade, run the schema authority fingerprint verifier and the real PostgreSQL
workflow suite before admitting traffic.
