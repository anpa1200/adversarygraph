# Production Readiness

ThreatMapper is moving from beta toward production readiness. This document
tracks what is currently true in the repository.

## Current Status

ThreatMapper is suitable for:

- local CTI labs
- controlled self-hosted analyst workspaces
- portfolio and demo use
- internal evaluation with non-sensitive or approved data

ThreatMapper is not yet a hardened public SaaS or a `v1.0` production platform.

## Implemented Gates

| Gate | Status | Evidence |
|---|---|---|
| Backend tests | Implemented | `backend/tests/` |
| Frontend production build | Implemented | `npm run build` |
| CI workflow | Implemented | `.github/workflows/ci.yml` |
| Coverage gate | Partial | enforced at 47%; target is 60%+ |
| Analyst review states | Partial | `suggested`, `accepted`, `rejected`, `needs-evidence` stored in analysis records |
| Evidence binding | Partial | best-effort character offsets for quoted source evidence |
| Security model | Implemented | `docs/security-model.md` |
| Limitations | Implemented | `docs/limitations.md` |
| Demo data and sample outputs | Implemented | `docs/demo-dataset/`, `docs/sample-outputs/` |
| Release notes | Implemented | `docs/release-notes/` |
| Sector relevance workflow | Implemented | Sector Intel page and `/api/sector/*` |
| IOC enrichment workflow | Implemented | Actor IOC tabs and `/api/ioc/*` |

## Remaining Production Blockers

- Raise backend coverage to at least 60%.
- Add report-level review summary counts.
- Add full UI controls for accepting, rejecting, and filtering mappings.
- Export review status and evidence spans in Markdown/PDF reports.
- Add retention controls for imported IOC feeds and uploaded IOC extraction inputs.
- Add per-source IOC sync scheduling policies and health history.
- Add reverse-proxy hardening examples for production deployments.
- Collect at least one external quickstart validation report.

## Deployment Position

Use the default Docker Compose deployment only in controlled environments. For
internet-facing use, place ThreatMapper behind:

- TLS
- an authenticating reverse proxy
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
