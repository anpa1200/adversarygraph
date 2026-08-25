# AdversaryGraph v8.0.0-beta.1 Release Summary

AdversaryGraph v8.0.0-beta.1 is a manual-testing pre-release that changes how
report-derived intelligence becomes authoritative. A stored or AI-analyzed
report remains a candidate until analysts complete five evidence gates, a
different named user approves the current revision, and an immutable promotion
manifest authorizes specific downstream targets.

v7.0.0 remains the latest stable release. This beta is intended to collect the
upgrade, browser, workflow-recovery, and end-to-end review evidence required for
a later stable decision. It must not be described as stable or fully manually
validated while that record is incomplete.

## What Changes for Analysts

- Reports / Research and AI Analysis expose a revisioned Review Gate for source
  provenance, publication date, procedure relevance, procedure claims, and
  actor basis.
- Machine preflight and AI assistance remain separate from analyst decisions.
  Evidence must bind to the stored source or acquisition receipt.
- The reviewing analyst submits the completed assessment; a different named
  approver accepts or returns it. Promotion snapshots only accepted claims.
- Canonical intelligence is mandatory at promotion. RAG, Threat Hunting, and
  exports require their own explicit target authorization.
- Editing a source or analysis makes the current authority stale. Revocation
  withdraws active downstream projections while preserving history.

## What Changes for Operators

- Research projects execute immutable revisions through durable workflow,
  stage, attempt, message, delivery, and receipt records.
- A transactional outbox and bounded Celery publisher/recovery tasks separate
  committed database authority from broker delivery.
- Alembic revisions `20260823_0001` through `20260824_0004` own the new
  research/workflow/outbox schema and enforce its physical authority contract.
- Compose blocks API and worker startup on a one-shot migration service. Helm
  adds first-install and pre-upgrade migration Jobs plus schema-authority init
  containers.
- React Router 7 and the new Review Gate UI require manual deep-link,
  navigation, concurrency, and two-person workflow testing.

## Trust Boundary

The beta makes report promotion explicit, but it does not make the report true.
Accepted ATT&CK mappings, actor claims, indicators, and dates remain bounded by
their cited source evidence and analyst decision. Source overlap, AI prose, RAG
ranking, and shared tooling cannot independently establish attribution.

Only the active, version-matched promotion manifest may authorize report-derived
graph, IOC, RAG, hunt, PDF, or STIX/OpenCTI output. Legacy or independent
intelligence sources keep their own provenance and must not be relabelled as
Review Gate promotions.

## Migration Boundary

The four-revision chain is intentionally limited to the new authority domain.
Other legacy tables still use additive startup compatibility. The beta does not
claim complete Alembic ownership, zero-downtime migration, or safe downgrade.
A verified backup, drained writers/workers, exact migration head, and physical
fingerprint are mandatory acceptance evidence. Do not use `alembic stamp` to
bypass a failed contract preflight.

## Manual Test Decision

Stable promotion is a separate decision after the user completes and retains
the checklist in [v8 release readiness](release-readiness-v8.md). Required
coverage includes:

- fresh and upgraded Compose/Helm deployments;
- two-person report approval, negative authorization cases, stale revisions,
  promotion targets, and revocation;
- graph, IOC, RAG, hunting, PDF, and STIX/OpenCTI withdrawal behavior;
- outbox delivery, retry, cancellation, lease recovery, and broker/worker
  interruption; and
- React Router 7 navigation and deep links.

The new
[Operation Desert Hydra AdversaryGraph workflow draft](publication-drafts/medium-adversarygraph-operation-desert-hydra-workflow.md)
provides an additional public/synthetic evaluation path. It is a new article,
not a modification of the original, and its inclusion is not evidence that its
31 steps have been executed.

## Release Evidence

The complete automated source gate is:

```bash
./scripts/release-readiness.sh --full
```

Immutable beta acceptance additionally requires successful merge CI and the
protected `v8.0.0-beta.1` tag workflow. The tag workflow must publish the exact
scanned images, verify public registry identity, attach the digest manifest, and
create a GitHub **pre-release** from the beta notes. None of those artifacts
should be inferred before the workflow succeeds.

See the [complete beta release notes](release-notes/v8.0.0-beta.1.md),
[version matrix](version-matrix.md),
[Report Review Gate](report-review-gate.md),
[Durable Research Workflows](research-workflows.md), and
[production-readiness boundary](production-readiness.md).
