# Production Readiness

AdversaryGraph is a production-oriented self-hosted analyst platform for
controlled deployments. The latest reviewed release tag is `v6.0.0`; the
checked-out source is the `v6.5.0` release candidate described in
[the changelog](../CHANGELOG.md). This document tracks the checked-out
repository, so every production review must record the exact tag or commit and
must not transfer evidence from a different revision.

## Current Status

The reviewed AdversaryGraph v6.0.0 tag is suitable for:

- local CTI labs
- controlled self-hosted analyst workspaces
- portfolio and demo use
- internal evaluation with non-sensitive or approved data
- controlled self-hosted deployment only when the operator retains equivalent
  build, scan, configuration, backup, restore, and acceptance evidence for the
  exact deployed artifacts

The public `v6.0.0` GitHub release predates the current immutable seven-image
manifest and has no attached `adversarygraph-images.env`. It therefore cannot
be claimed to have passed the strengthened v6.5 artifact gate documented in
this checkout. The v6.5 source is a release candidate until the protected
`v6.5.0` tag workflow succeeds; it must not be represented as the existing
`v6.0.0` artifact or as an immutable v6.5 artifact before that point.

AdversaryGraph is not a managed public SaaS. The default deployment is suitable
for controlled self-hosted use; public internet exposure still requires a
hardened reverse proxy, TLS, authentication, monitoring, backups, and local data
handling policy.

## Implemented Gates

| Gate | Status | Evidence |
|---|---|---|
| Backend tests | Implemented | `backend/tests/` |
| Frontend production build | Implemented | `npm run build` |
| Anomaly documentation build | Implemented | `npm --prefix anomaly_detection/docs-site run build` with fail-closed internal-link and anchor checks |
| CI workflow | Implemented | `.github/workflows/ci.yml` |
| Coverage gate | Implemented baseline | full backend suite enforces at least 60% line coverage; continue raising it around high-risk workflows |
| Analyst review states | Partial | `suggested`, `accepted`, `rejected`, `needs-evidence` stored in analysis records |
| Evidence binding | Partial | best-effort character offsets for quoted source evidence |
| Security model | Implemented | `docs/security-model.md` |
| Limitations | Implemented | `docs/limitations.md` |
| Demo data and sample outputs | Implemented | `demo/`, `docs/sample-outputs/` |
| Release notes | Implemented | `docs/release-notes/` |
| Sector relevance workflow | Implemented | Sector Intel page and `/api/sector/*` |
| IOC enrichment workflow | Implemented | Actor IOC tabs and `/api/ioc/*` |
| Required database secret | Implemented | `DB_PASS` is required at startup |
| Redis authentication | Implemented | `REDIS_PASSWORD` / authenticated `REDIS_URL` |
| Configurable CORS | Implemented | `CORS_ALLOWED_ORIGINS`, wildcard rejection |
| Native user authentication | Implemented | Named username/password accounts, policy-aware user creation, session cookie, Admin Panel, and `/auth-guide` |
| Trusted-header auth guard | Implemented | `PROXY_SECRET` and `X-Internal-Proxy-Secret` |
| Enterprise SSO integration pattern | Implemented | OIDC/SAML via trusted reverse proxy, `AUTH_SSO_MODE`, `X-Auth-User`, `X-Auth-Roles` |
| Expanded RBAC | Implemented in v6.5 source | Twelve persistent SOC access groups, 31 module allowlists, API/UI enforcement, legacy role baselines, direct-grant ceilings, and final-user-manager continuity |
| Auth audit trail | Implemented | login, logout, user changes, password reset, MFA, session review/revocation |
| Session administration | Implemented | expiry, admin session list, user session revoke, own-session revoke |
| Local MFA support | Implemented | TOTP setup/confirm/admin disable for native accounts |
| SSRF-hardened feed fetches | Implemented; deployment egress still required | `backend/app/core/safe_http.py`; validated addresses are pinned at connect time and redirects are revalidated, while network policy remains defense in depth |
| XML parser hardening | Implemented | `defusedxml` for RSS parsing |
| Frontend URL scheme guard | Implemented | `frontend/src/utils/url.ts` |
| Production frontend build | Implemented | default compose uses built frontend image; dev override is separate |
| Hardened Compose overlay | Implemented | `docker-compose.prod.yml` |
| Kubernetes Helm scaffold | Implemented (initial) | `helm/adversarygraph/` |
| Sizing guide | Implemented | `docs/deployment-sizing.md` |
| Backup/restore scripts | Implemented | checksummed, archive-validated backup and writer-stopped restore in `scripts/backup.sh`, `scripts/restore.sh` |
| Request-size controls | Implemented with deployment requirement | bounded structured models and file handlers plus route-specific Nginx decoded-body limits; the API must remain behind that edge because `Content-Length` alone does not cover chunked bodies |
| Fresh image scan/publish path | Implemented in v6.5 source; tag-workflow evidence required | strict local builds scan seven custom images plus the three pinned third-party stack images; the tag workflow loads and scans seven versioned images before pushing those same local images |
| Immutable Compose deployment | Implemented | production preflight requires all seven custom registry images by digest and `make prod` uses `--no-build` |
| Helm image digests | Implemented with operator input | PostgreSQL and Redis evaluation defaults are digest-pinned; backend/frontend/MalwareGraph default to v6.5.0 candidate tags with empty digest fields. Production replaces PostgreSQL and supplies reviewed digests for all four release components from the successful v6.5 tag workflow. |
| Upgrade guide | Implemented | `docs/upgrade-guide.md` |
| PostgreSQL full-text and pgvector | Implemented in v6.5 source | checksum-pinned pgvector build, extension/version smoke, generated `tsvector`, GIN, HNSW, and cosine-query CI checks |
| Unified RAG corpus | Implemented in v6.5 source | normalized allowlisted source adapters, idempotent scheduled reconciliation, advisory locking, stale-run redispatch, status/history API, tombstone and assistance retention |
| Governed Navigator assistant | Implemented in v6.5 source | business profiles, exact/FTS/optional vector retrieval, source-bound structured output, TLP/legal gates, verified citations, temporary preview, and explicit non-mutating Add/Replace confirmation; advisory/audit records are persisted but no layer is saved |
| Local MCP integration | Implemented in v6.5 source | stdio-only bounded tools over authenticated RAG API routes; no remote listener, arbitrary URL/SQL access, proposal confirmation, reindex, or operational mutation |
| Dependency audit | Implemented with documented residual risk | backend and Anomaly docs resolve without known findings at the v6.5 candidate lockfiles; the client frontend has two documented moderate React Router v6 advisories, while the available Router 7 path currently introduces a high RSC advisory and a breaking migration |

## Remaining Production Blockers

These items block broader enterprise, managed-service, or default
internet-facing claims. They do not invalidate a controlled self-hosted
deployment with documented compensating controls:

- Raise backend coverage beyond the enforced 60% baseline, prioritizing
  authentication, ingestion, exports, threat hunting, simulation, and recovery
  paths rather than treating the aggregate percentage as sufficient evidence.
- Add report-level review summary counts.
- Add full UI controls for accepting, rejecting, and filtering mappings.
- Export review status and evidence spans in Markdown/PDF reports.
- Add retention controls for imported IOC feeds and uploaded IOC extraction inputs.
- Add per-source IOC sync scheduling policies and health history.
- Add reverse-proxy hardening examples for production deployments.
- Collect at least one external quickstart validation report.
- Add broader audit coverage for all remaining state-changing routes.
- Add application-level schema-depth guards for STIX/MISP import routes. The
  current 10 MiB decoded-body edge limits bound request size, but do not by
  themselves bound pathological nesting if the API is exposed without that
  trusted edge.
- Add digest-pinned build-stage and runtime bases to every custom Dockerfile;
  current fresh builds scan the resulting artifact, but upstream Dockerfile
  `FROM` references are still mutable at build time.
- Enable an active GitHub tag ruleset that blocks updates and deletion of
  existing `v*` release tags without bypass actors; the workflow fails closed
  until both rules cover its exact tag.
- Add signature verification for commit-pinned MalwareGraph and optional Atlas
  source updates; current defaults are immutable reviewed SHAs but the upstream
  commits are not signature-verified by the build.
- Add formal Alembic migration chain and migration tests.
- Before enabling semantic retrieval in a production environment, retain an
  end-to-end smoke test against the exact approved private embedding and chat
  endpoint/model pair. Unit/integration protocol tests do not prove that a
  deployment-specific model returns the configured dimensions, obeys latency
  limits, or meets local data-handling policy.
- Reassess the two moderate React Router v6 advisories against the exact
  frontend deployment and the current Router 7 advisory set before the release
  tag. AdversaryGraph does not use Router SSR, and API-controlled external URLs
  pass through the safe-URL guard, but this is a documented residual risk rather
  than a claim of a finding-free frontend dependency tree.

## Deployment Position

Use the default Docker Compose deployment only in controlled environments. For
internet-facing use, place AdversaryGraph behind:

- TLS
- native authentication with named users and roles
- an authenticating reverse proxy or identity-aware gateway when externally exposed
- decoded request-body limits at the reverse proxy/ingress (the bundled Nginx
  policy uses a 10 MiB default with narrow upload-route exceptions)
- restricted network access to PostgreSQL and Redis
- managed secrets
- backups and retention controls
- logging and monitoring
- the bundled pgvector-capable PostgreSQL image, or an external PostgreSQL
  service where the compatible `vector` extension is installed before API
  startup
- a private, authenticated model gateway when embeddings or local generation
  are enabled; restrict model egress and include its logs/retention in policy
- a direct PostgreSQL connection for the RAG worker, or PgBouncer configured in
  session-pooling mode rather than transaction/statement pooling
- reviewed registry digests for deployed images where the orchestrator supports
  them; retain the corresponding tag, architecture, workflow, and scan evidence

For production-like Compose deployments, use the hardened overlay:

```bash
./scripts/validate-production-env.sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build
```

Before this command, load the seven `ADVERSARYGRAPH_*_IMAGE` values from the
`adversarygraph-images.env` file attached to the exact GitHub release. The
production preflight rejects tags and accepts only `repository@sha256:...`
references. It also requires URL-safe Redis credentials because the stack
passes that secret in a Redis URI.

For Kubernetes planning, review the initial Helm chart in
`helm/adversarygraph/`. The chart is a scaffold for controlled internal
deployments and should be reviewed against your ingress, secret-management,
storage, and backup standards before use.
Set `config.productionMode: "true"` in reviewed production values; the chart
then rejects missing release digests, the upstream PostgreSQL compatibility
image, insecure auth/cookie/CORS values, disabled baseline NetworkPolicies, and
the absence of an externally managed Secret.

## Container Release Integrity

In the v6.5 source, strict local and CI container scans are configured to pull
base images and bypass cached layers. Runtime Dockerfiles apply distribution
updates available during the build, and fixable high/critical Trivy findings
fail the strict gate. The current `ignore-unfixed` policy filters findings that
have no upstream fix, so deployments that require a complete vulnerability
inventory need an additional unfiltered scan and risk review. This reduces
stale-image acceptance; it is not bit-for-bit reproducibility and does not
remove the remaining base-image digest-pinning blocker.

The future-tag workflow loads and scans each versioned local image, then pushes
that exact candidate without rebuilding. It serializes release jobs, verifies
that each anonymously readable public manifest contains the scanned image ID,
and attaches the verified immutable digest set as
`adversarygraph-images.env`. Shared `latest` tags are not advanced because the
seven-image family cannot be updated atomically. The workflow refuses to
modify a published GitHub release. It resumes a draft only when the title,
notes, and sole manifest asset exactly match the regenerated release; otherwise
it stops for explicit review. The workflow currently publishes Linux/AMD64
images; multi-architecture publication remains future work.
On retry after a partial publication, the workflow reuses an existing version
image only when its content-addressed image ID exactly matches a fresh source
build, and it rescans that artifact before pushing; labels alone are not
trusted. Mismatches and ambiguous registry or GitHub release lookups stop
publication and require explicit partial-version cleanup after review.
The workflow rechecks release state immediately before publishing the draft.
A successful run for the exact tag is required evidence; the workflow in the
v6.5 source is not evidence for the historical `v6.0.0` artifact.

For Helm deployments, operators supply reviewed registry digests for the
PostgreSQL, backend, frontend, and MalwareGraph release images. Redis and an
upstream PostgreSQL compatibility image have pinned evaluation defaults, but
the latter is not the remediated release artifact and is not acceptable for the
strict production gate. Production values must replace both its repository and
digest with `adversarygraph-postgres` values from the exact release manifest.
The backend, frontend, and MalwareGraph digest fields are empty by default
because the chart cannot determine an unpublished registry artifact. Resolve
all four release images after publication and record their provenance before
rollout. The anomaly documentation builder does not replace packages or source
after deployment when `ATLAS_SYNC_INTERVAL=0`, which the production preflight
requires; publish reviewed Atlas changes through a new scanned image.

## Data Handling

Uploaded reports and extracted text may contain sensitive material. Public demos
must not receive customer reports, incident data, classified material, private
victim details, credentials, or internal telemetry.

IOC feeds can also contain customer, investigation, or vendor-sensitive context.
Operators should define feed provenance, retention, export, and sharing rules
before importing private IOC data.

The unified RAG corpus is a derived copy of allowlisted source fields, not a
separate public knowledge base. Embeddings, source excerpts, actor relationship
evidence, saved business profiles, generated answers, citations, and Navigator
proposals can reveal the same sensitive context as their source records. Apply
the source record's access, TLP, legal, retention, deletion, backup, and incident
response controls to the corpus and to any MCP client/model that receives tool
results. Automatic RAG retention does not delete source records, backups,
exports, replicas, MCP-client history, index-run history, or platform audit
events. Give those records an explicit operator retention/deletion policy.
