# Issue Triage

This local triage file mirrors reviewer-facing project state when GitHub issue metadata is not enough context.

## Open Hardening Items

| Area | Status | Next action |
|---|---|---|
| Celery dead-code cleanup | Closed | Removed the unused `analysis.run` registration; active worker modules now cover sync, pipeline collection, RetroHunt, unified RAG reconciliation, and RAG retention. |
| Starlette transitive CVE | Closed / audited | Current dependencies are audited in CI with `pip-audit`; reverse-proxy Host normalization remains documented for internet-facing deployments. |
| Backend coverage target | In progress | The enforced baseline is 60%; raise it toward 70% with risk-weighted route and failure-path tests. |
| Frontend unit tests | Open | Add Vitest coverage for high-risk pages and shared utilities |
| Reverse-proxy examples | Open | Add NGINX/Caddy examples for auth, TLS, trusted headers, and CORS |

## Closed / Completed Hardening Items

| Area | Evidence |
|---|---|
| Production frontend image | `frontend/Dockerfile` serves built static assets with nginx |
| Non-root runtime containers | Backend, frontend, MalwareGraph, lab fixtures, and anomaly docs builder run as non-root users |
| Gemini SDK migration | `backend/app/services/ai/gemini.py` uses `google-genai` |
| Route-level mutating tests | `backend/tests/integration/test_operations_routes.py`, `backend/tests/integration/test_pipeline_routes.py` |
| Reviewer docs and demo data | `docs/reviewer-guide.md`, `demo/README.md` |

## Labeling Guidance

- `security`: vulnerability, auth, secrets, SSRF, unsafe parsing, or exposure risk.
- `hardening`: production readiness, CI, Docker, dependency, and coverage work.
- `docs`: reviewer, operator, public site, or guide updates.
- `validation`: mapping, detection, telemetry, or demo dataset verification.
- `feature`: new analyst workflow or UI capability.
