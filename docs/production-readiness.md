# Production Readiness

AdversaryGraph is a production-oriented self-hosted analyst platform for
controlled deployments. The latest immutable release tag is `v6.0.0`; the
current `main` branch also contains the post-v6 work listed under
[Unreleased](../CHANGELOG.md). This document tracks the checked-out repository,
so every production review must record the exact tag or commit and must not
transfer evidence from a different revision.

## Current Status

The immutable AdversaryGraph v6.0.0 tag is suitable for:

- local CTI labs
- controlled self-hosted analyst workspaces
- portfolio and demo use
- internal evaluation with non-sensitive or approved data
- controlled self-hosted deployment only when the operator retains equivalent
  build, scan, configuration, backup, restore, and acceptance evidence for the
  exact deployed artifacts

The public `v6.0.0` GitHub release predates the current immutable seven-image
manifest and has no attached `adversarygraph-images.env`. It therefore cannot
be claimed to have passed the strengthened post-v6 artifact gate documented in
this checkout. Current `main` is an unreleased candidate with additional
controls and features. It requires a new semantic release tag and a successful
tag workflow before production rollout, and must not be represented as the
existing `v6.0.0` artifact.

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
| Native user authentication | Implemented | Username/password login, session cookie, roles, Admin Panel, and `/auth-guide` |
| Trusted-header auth guard | Implemented | `PROXY_SECRET` and `X-Internal-Proxy-Secret` |
| Enterprise SSO integration pattern | Implemented | OIDC/SAML via trusted reverse proxy, `AUTH_SSO_MODE`, `X-Auth-User`, `X-Auth-Roles` |
| Expanded RBAC | Implemented | viewer, analyst, threat_intel, detection_engineer, incident_responder, auditor, security_admin, service_account, admin plus explicit permissions |
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
| Fresh image scan/publish path | Implemented on post-v6 `main`; future-tag evidence required | strict local builds scan seven custom images plus the three pinned third-party stack images; the tag workflow loads and scans seven versioned images before pushing those same local images |
| Immutable Compose deployment | Implemented | production preflight requires all seven custom registry images by digest and `make prod` uses `--no-build` |
| Helm image digests | Implemented with operator input | PostgreSQL and Redis evaluation defaults are pinned; production replaces the PostgreSQL repository/digest and supplies reviewed release digests for all four release components |
| Upgrade guide | Implemented | `docs/upgrade-guide.md` |

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
- Add signature verification for commit-pinned MalwareGraph and optional Atlas
  source updates; current defaults are immutable reviewed SHAs but the upstream
  commits are not signature-verified by the build.
- Add formal Alembic migration chain and migration tests.

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
- reviewed registry digests for deployed images where the orchestrator supports
  them; retain the corresponding tag, architecture, workflow, and scan evidence

For production-like Compose deployments, use the hardened overlay:

```bash
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

On post-v6 `main`, strict local and CI container scans are configured to pull
base images and bypass cached layers. Runtime Dockerfiles apply distribution
updates available during the build, and fixable high/critical Trivy findings
fail the strict gate. The current `ignore-unfixed` policy filters findings that
have no upstream fix, so deployments that require a complete vulnerability
inventory need an additional unfiltered scan and risk review. This reduces
stale-image acceptance; it is not bit-for-bit reproducibility and does not
remove the remaining base-image digest-pinning blocker.

The future-tag workflow is configured to load and scan each versioned local
image, verify its version and `latest` local tags identify the same image, and
then push those already scanned local tags without rebuilding. It serializes
release jobs and attaches the published digest set as
`adversarygraph-images.env`. Every published GitHub release is immutable,
regardless of its assets; only a release that is still a draft may be resumed.
On retry after a partial publication, the workflow reuses an existing version
image only when its OCI source, version, and revision labels match the current
tag commit, and it rescans the selected artifact before an idempotent push;
mismatches and ambiguous registry or GitHub release lookups stop publication.
The workflow rechecks release state immediately before its draft update.
A successful run for the exact tag is required evidence; the workflow currently
on `main` is not evidence for the historical `v6.0.0` artifact.

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
