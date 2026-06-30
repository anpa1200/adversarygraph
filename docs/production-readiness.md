# Production Readiness

AdversaryGraph is a production-oriented self-hosted analyst platform for
controlled deployments. This document tracks what is currently true in the
repository and what still needs operator hardening before internet exposure.

## Current Status

AdversaryGraph is suitable for:

- local CTI labs
- controlled self-hosted analyst workspaces
- portfolio and demo use
- internal evaluation with non-sensitive or approved data

AdversaryGraph is not a managed public SaaS. The default deployment is suitable
for controlled self-hosted use; public internet exposure still requires a
hardened reverse proxy, TLS, authentication, monitoring, backups, and local data
handling policy.

## Implemented Gates

| Gate | Status | Evidence |
|---|---|---|
| Backend tests | Implemented | `backend/tests/` |
| Frontend production build | Implemented | `npm run build` |
| CI workflow | Implemented | `.github/workflows/ci.yml` |
| Coverage gate | Partial | current test suite passes; target is 60%+ enforced coverage |
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
| SSRF-safe feed fetches | Implemented | `backend/app/core/safe_http.py` |
| XML parser hardening | Implemented | `defusedxml` for RSS parsing |
| Frontend URL scheme guard | Implemented | `frontend/src/utils/url.ts` |
| Production frontend build | Implemented | default compose uses built frontend image; dev override is separate |

## Remaining Production Blockers

- Raise backend coverage to at least 60%.
- Add report-level review summary counts.
- Add full UI controls for accepting, rejecting, and filtering mappings.
- Export review status and evidence spans in Markdown/PDF reports.
- Add retention controls for imported IOC feeds and uploaded IOC extraction inputs.
- Add per-source IOC sync scheduling policies and health history.
- Add reverse-proxy hardening examples for production deployments.
- Collect at least one external quickstart validation report.
- Add broader audit coverage for all remaining state-changing routes.
- Add body-size and schema-depth guards for STIX/MISP import routes.
- Add digest-pinned base images to every container image.
- Add signed/tag-pinned external repository sync for optional Atlas docs import.

## Deployment Position

Use the default Docker Compose deployment only in controlled environments. For
internet-facing use, place AdversaryGraph behind:

- TLS
- native authentication with named users and roles
- an authenticating reverse proxy or identity-aware gateway when externally exposed
- restricted network access to PostgreSQL and Redis
- managed secrets
- backups and retention controls
- logging and monitoring

## Data Handling

Uploaded reports and extracted text may contain sensitive material. Public demos
must not receive customer reports, incident data, classified material, private
victim details, credentials, or internal telemetry.

IOC feeds can also contain customer, investigation, or vendor-sensitive context.
Operators should define feed provenance, retention, export, and sharing rules
before importing private IOC data.
