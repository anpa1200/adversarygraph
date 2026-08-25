# AdversaryGraph v8.0.0-beta.1 Release Readiness

This is the acceptance plan for the `v8.0.0-beta.1` manual-testing
pre-release. v7.0.0 remains the latest stable release. The beta is not stable,
production-accepted, or fully tested until every applicable automated and
manual gate below has retained evidence for the exact revision and deployment.

Use this file as a test record, not as evidence by its existence. Change a row
to passed only after attaching the operator, timestamp, tag/commit, architecture,
deployment mode, input fixture, expected result, actual result, and log or
screenshot reference. An unrecorded test is `pending`, not passed.

## Release State

| Item | Required state for beta publication | Prepared-source state |
|---|---|---|
| Source version | Exact `8.0.0-beta.1` across validated metadata | Verify with the version-consistency gate |
| Latest stable | v7.0.0 remains identified as latest stable | Required |
| Full local release gate | Passed for exact candidate revision | Pending evidence |
| Merge CI | Passed for exact candidate revision | Pending evidence |
| Protected beta tag workflow | Passed; exact tag still resolves to candidate commit | Pending evidence |
| Registry artifacts | Exact scanned image identity and digest manifest verified | Pending evidence |
| GitHub release state | Marked pre-release, not stable/latest | Pending evidence |
| Manual beta matrix | May remain incomplete for beta publication, but must be labelled pending | Pending user testing |
| Stable promotion | Separate reviewed release after all mandatory manual rows pass | Not authorized by this beta |

## Automated Source Gate

Use the same fail-closed toolchain as CI and run:

```bash
./scripts/release-readiness.sh --full
```

The exact beta gate must verify at least:

- semantic pre-release metadata consistency and the matching beta release
  notes/summary/readiness documents;
- generated OpenAPI/frontend call consistency and complete governed-module
  documentation;
- Review Gate route/service/unit and browser coverage;
- research project, workflow engine, orchestrator, worker, cancellation,
  heartbeat, checkpoint, completion, failure, retry, and recovery coverage;
- PostgreSQL-backed migration, schema constraint, transactional outbox,
  delivery-receipt, reservation, and concurrency tests;
- exact Alembic head and catalog-derived authority fingerprint checks;
- default, development, local-AI, and hardened production Compose rendering,
  including the one-shot migration dependency;
- Helm lint and install/upgrade rendering, including the migration Job,
  pre-upgrade hook, schema-authority init containers, external PostgreSQL path,
  security contexts, and NetworkPolicies;
- frontend lint, production build, dependency audit, and Playwright coverage
  after the React Router 7 migration;
- backend lint, full tests, coverage floor, Bandit, dependency audit, and secret
  scan;
- scanner MCP checks and the existing strict eight-image release scan path; and
- compiled scanner assertions for Go 1.26.7, `golang.org/x/mod` v0.40.0, and
  `golang.org/x/text` v0.41.0 before the fixed-finding image scan; and
- documentation links, release metadata, and patch hygiene.

The full gate requires its documented Python, Node, browser, Docker, Helm,
Gitleaks, and Trivy dependencies plus a reviewed environment. Missing tooling,
credentials, Docker access, or database configuration is a stopped gate, not a
pass. A `--quick` run is development feedback only.

Do not copy v7 counts into this record. Record the exact beta test, API, module,
frontend-call, browser, audit, and image-scan counts only from the final
successful run.

## Migration Acceptance

The beta introduces formal authority migrations:

| Revision | Acceptance focus |
|---|---|
| `20260823_0001` | Research projects, immutable revisions, ownership, and constraints |
| `20260823_0002` | Workflow runs, ordered stages, fenced attempts, project lineage |
| `20260823_0003` | Transactional outbox, deliveries, attempts, receipts, reservations |
| `20260824_0004` | Exact v1 plan contract, running-attempt receipt binding, canonical lock order, terminal consistency, cancellation identity |

For both Compose and Helm upgrade tests:

1. Back up PostgreSQL and verify the backup checksum and restore in a separate
   environment.
2. Record the old application version, database revision, active workflows,
   and worker/Beat state.
3. Quiesce API writers and stop worker/Beat processing.
4. Apply the beta migration using the exact candidate backend artifact.
5. Verify Alembic reports the expected head and the schema-authority fingerprint
   verifier passes.
6. Start API, worker, and Beat only after the migration gate succeeds.
7. Verify existing supported intelligence records and v7 workflows remain
   readable and no report-derived row is silently promoted.
8. Run the authenticated full self-test and resolve every non-`ok` result.
9. Exercise backup restore and application rollback planning. Do not claim that
   an application rollback reverses the database migration.

Negative migration cases must include a disposable database with a missing or
altered authority constraint/index/trigger and an incompatible expand-era
workflow. Startup or `0004` must fail closed, preserve diagnostics, and avoid a
partially committed contract. Never use `alembic stamp` to make a negative case
appear successful.

## Manual Report Review Matrix

Use public or synthetic report material. Enable authentication and create two
different named users: a submitter with `review_reports` and an approver with
`promote_reports`. An auth-disabled `local:local` identity cannot prove the
four-eyes rule.

| Test | Required result | Status |
|---|---|---|
| Start and preflight | Current fingerprinted draft and all five machine gates are visible | Pending |
| Source provenance | Upload/URL receipt and hashes remain bound; replacement text cannot impersonate original bytes | Pending |
| Publication date | Supported date can pass; conflict or unsupported date cannot silently pass | Pending |
| Procedure relevance | Behavior evidence can pass; name-only mention cannot pass | Pending |
| Procedure claim | Exact source-bound behavior and local ATT&CK/ATLAS ID accepted; generic tool label rejected | Pending |
| Actor identification | Explicit source claim or no-actor decision accepted; overlap-only attribution rejected | Pending |
| AI assistance | Suggestions remain suggested and cannot write gates, accept claims, approve, or promote | Pending |
| Coverage | Incomplete bounded analysis blocks promotion unless a durable, reasoned exception is recorded | Pending |
| Optimistic concurrency | Stale `expected_version` returns HTTP 409 with no replay against the newer revision | Pending |
| Four-eyes approval | Same-user approval fails; a different authorized named user can approve | Pending |
| Promotion targets | Canonical intelligence is mandatory; RAG, hunting, and exports are independently selected | Pending |
| Staleness | Source or review-relevant analysis mutation withdraws current authority and creates/requires a new revision | Pending |
| Revocation | Active projections disappear while append-only review/promotion history remains | Pending |
| Service account | Ingestion/preflight may run where authorized; analyst decisions remain forbidden | Pending |

## Downstream Authority Matrix

Test before promotion, after promotion, after staleness, and after revocation.

| Consumer | Required behavior | Status |
|---|---|---|
| Intelligence graph | Only accepted manifest claims from current `canonical_intelligence` promotion materialize; stale/revoked provenance disappears | Pending |
| IOC Library | Unpromoted candidates stay report-local; promotion namespace is read-time revalidated and withdrawn when authority ends | Pending |
| RAG | Excluded before promotion; included only with `rag`; removed during reconciliation after authority ends | Pending |
| Threat Hunting AI | HTTP 409 without active `hunting`; provenance included after authorization; in-flight stale authority fails | Pending |
| Asset retrohunt | No report intake before authority; projection refreshed/removed with promotion state | Pending |
| PDF | Non-authoritative assessment without `exports`; accepted claims only when authorized; revoked/stale clearly labelled | Pending |
| STIX/OpenCTI | HTTP 409 without active `exports`; accepted procedures and explicit actor claims only | Pending |
| Evidence Graph report route | Only unambiguous session/intake UUID and exact current canonical promotion accepted | Pending |
| Generic report intake | URL/upload/RSS/STIX/TAXII/MISP/OpenCTI/pipeline paths create candidates without global trusted projections | Pending |
| Generic IOC STIX import | Report-bearing bundle is rejected and routed to report-aware intake | Pending |

## Durable Workflow and Outbox Matrix

| Test | Required result | Status |
|---|---|---|
| Project revision | Scope change creates immutable lineage; historical revision remains unchanged | Pending |
| Idempotent start | Exact token replay returns the same authority; conflicting payload is rejected | Pending |
| Registered handler | `research.project.scope@1` runs; unknown type/version fails closed | Pending |
| Publish path | Committed outbox row publishes with stable delivery identity | Pending |
| Consumer lineage | Workflow/stage/attempt/message/delivery/receipt mismatch is rejected before handler execution | Pending |
| Heartbeat/checkpoint | Receipt-bound authority renews or records progress without extending invalid ownership | Pending |
| Completion/failure | Single-use reservation commits one terminal decision and matching receipt outcome | Pending |
| Retry | New attempt and message lineage is durable; stale delivery cannot execute it | Pending |
| Cancellation | Actor, reason, request UUID, predecessor version, and terminal state are atomic | Pending |
| Cancellation replay | Exact command is idempotent; altered actor/reason/predecessor conflicts | Pending |
| Publisher recovery | Expired claims are released in bounded batches without duplicate authority | Pending |
| Stage recovery | Expired execution recovers only through exact receipt-bound coordinator authority | Pending |
| Broker interruption | Committed outbox work is rediscovered after broker recovery | Pending |
| Worker interruption | Replay-safe handler resumes or retries without repeating an unkeyed external side effect | Pending |
| Beat topology | Exactly one scheduler, or a documented singleton HA scheduler, emits bounded scans | Pending |
| Safe diagnostics | Recovery logs expose low-cardinality counts/classes, not secrets or raw authority | Pending |

## Frontend Manual Matrix

| Test | Required result | Status |
|---|---|---|
| Direct deep links | Main governed routes load after refresh under React Router 7 | Pending |
| Auth redirect | Protected route returns to the intended safe internal location after sign-in | Pending |
| Back/forward | Review and report navigation preserves expected route state without duplicating decisions | Pending |
| Review concurrency | Second browser receives conflict and refreshes rather than overwriting newer state | Pending |
| Permission visibility | Review, approval, promotion, and revocation actions match API permissions | Pending |
| History display | Append-only revision, approval, promotion, staleness, and revocation events remain understandable | Pending |
| Error recovery | 409, policy rejection, unavailable provider, and migration/readiness errors are actionable and do not imply success | Pending |

## Operation Desert Hydra Evaluation

The new
[AdversaryGraph Operation Desert Hydra draft](publication-drafts/medium-adversarygraph-operation-desert-hydra-workflow.md)
is a separate article and may be used as an extended beta scenario. It contains
31 mapped steps, but the release does not claim those steps were executed.

If used, retain evidence for each step and use its exact outcome vocabulary:
`passed`, `failed`, `partial`, or `not_proven`. External research acquisition,
SIEM execution, endpoint telemetry, and unsupported simulation IDs remain
external/manual boundaries; do not convert missing evidence into a platform
pass.

## Deployment Go/No-Go

| Gate | Go condition | Status |
|---|---|---|
| Scope | Controlled self-hosted, single-workspace evaluation; no SaaS or tenant-isolation claim | Pending |
| Identity | `AUTH_ENABLED=true`, named submitter/approver, least privilege, bootstrap removed | Pending |
| Secrets/TLS/network | Reviewed external secrets, TLS proxy, secure cookies/CORS, private database/Redis/scanner | Pending |
| Backup/restore | Verified pre-upgrade backup and tested restore | Pending |
| Migration | Exact head and physical fingerprint pass for deployed artifact | Pending |
| Workers | Publisher/recovery/Beat topology and monitoring accepted | Pending |
| Review Gate | Manual report and downstream authority matrices pass | Pending |
| RAG | Reconciliation completes; lexical/vector readiness is stated accurately | Pending |
| Images | Exact beta tag images pass strict scans and deploy by verified digests | Pending |
| Automated gate | Full local gate, merge CI, and protected beta tag workflow pass | Pending |
| Rollback | Previous images/configuration and database recovery decision are documented | Pending |

Any failed mandatory gate is a no-go for that deployment. A risk acceptance
must name its owner, expiry, compensating control, and rollback trigger. It does
not turn a failed test into a pass.

## Stable Promotion Requirements

Do not overwrite or retag `v8.0.0-beta.1` as stable. Prepare a separate stable
version only after:

1. Every applicable mandatory row above is passed with retained evidence.
2. Beta defects are fixed and the complete automated/manual suites are rerun
   against the resulting stable candidate, not reused from an older commit.
3. Migration from v7 and from the beta is tested with verified backups.
4. Release notes and the version matrix replace pending language with exact,
   evidence-backed results.
5. The final stable tag workflow publishes revision-matched artifacts and does
   not mark the beta as latest.

See the [beta release notes](release-notes/v8.0.0-beta.1.md),
[Report Review Gate](report-review-gate.md),
[Durable Research Workflows](research-workflows.md),
[upgrade guide](upgrade-guide.md), and
[production readiness](production-readiness.md).
