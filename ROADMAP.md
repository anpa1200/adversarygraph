# Roadmap

Current release: **v5.5.0** — enterprise access controls, RBAC, MFA workflow support, session administration, and audit history (2026-06-30)

For the full history from v0.2.0 through v5.5.0 see [CHANGELOG.md](CHANGELOG.md).

## v5.6 — Evidence-to-Detection Graph

- [x] Add relational Evidence Graph node and edge model for evidence-backed reasoning paths
- [x] Add CRUD, summary, path, gap, generation, and export APIs
- [x] Add frontend Evidence Graph page with overview, interactive graph, path view, gap view, review queue, and node detail actions
- [x] Add safe synthetic demo dataset for evidence-to-detection review
- [x] Document AI draft boundaries, readiness scoring, exports, gaps, and limitations
- [ ] Add typed foreign-key relationship tables for every external entity link
- [ ] Add deeper ATT&CK data-component import and ECS/OCSF/Splunk CIM/Sentinel ASIM field mapping
- [ ] Add SIEM-specific rule compilers and detection regression tests

## v5.x — Hardening Sprint

- [x] Migrate the legacy Gemini SDK package to `google-genai` (SDK renamed by Google)
- [x] Expand CI: add ruff lint, pip-audit, npm audit, Docker build checks, container scan (Trivy), secret scan (gitleaks)
- [x] Add route-level integration tests for high-risk mutating Operations and Pipeline endpoints
- [x] Publish reviewer guide and demo dataset
- [x] Document Starlette transitive dependency version and CVE status
- [ ] Raise backend coverage gate from the current conservative baseline
- [ ] Add frontend unit tests for Attack Simulation and Asset Surface critical flows

## v5.1 — Review Hardening

- [x] Enforce source-correct telemetry policy for Attack Simulation and AI-assisted scenarios
- [x] Document telemetry fidelity architecture and SIEM validation boundaries
- [ ] Enforced backend coverage gate at 70%
- [ ] Frontend unit tests with Vitest
- [x] Authentication hardening guide for native auth and reverse-proxy deployments
- [ ] `.env.example` credential rotation documentation

## v5.2 — QA Hardening

- [x] Make backend tests reproducible without requiring a developer shell `DB_PASS`
- [x] Clear frontend npm audit findings by overriding Monaco's transitive DOMPurify dependency to the current patched release
- [x] Revalidate backend lint, backend tests with coverage, frontend audit, and frontend production build

## v5.3 — Authentication and User Operations

- [x] Add native authentication setup guide available from the running local instance at `/auth-guide`
- [x] Link the login page directly to the authentication guide before sign-in
- [x] Document bootstrap admin creation, permanent named accounts, role model, password reset behavior, and bootstrap secret cleanup
- [x] Update production, security, quickstart, and privacy guidance for native auth plus optional identity-aware reverse-proxy deployments

## v5.4 — Observability and Validation Evidence

- [x] Add authenticated Observability dashboard with API health, request metrics, recent traces, redacted log tail, and Prometheus-compatible metrics
- [x] Add backend SAST coverage and local `make security-scan` helper
- [x] Document observability, security scanning, and screenshot-backed validation examples
- [x] Validate route tests, frontend build, docs build, lint, SAST, dependency audit, and Docker Compose config

## v5.5 — Enterprise Access Controls

- [x] Add expanded RBAC roles and per-user permissions for team deployments
- [x] Add session inventory, revoke-all, and admin session revocation actions
- [x] Add MFA setup/confirm/disable workflow support for local accounts
- [x] Add trusted proxy SSO metadata and configuration guidance
- [x] Add audit history for login, logout, user changes, session revocation, MFA, exports, feed sync, SIEM forwarding, and file uploads

## Backlog

- Optional local LLM gateway profile (Ollama / LM Studio)
- STIX/TAXII export mode
- Case timeline view
- ATT&CK version-diff view for mappings across releases
- Mapping evaluation harness for public CTI reports
- STIX 2.1 bundle export
