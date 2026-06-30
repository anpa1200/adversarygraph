# Reviewer Guide

This guide is for security researchers, package curators, and tool evaluators who want to assess AdversaryGraph for inclusion in curated lists, publication roundups, or organizational adoption.

## Quick orientation

| Item | Location |
|---|---|
| Project overview | [README.md](../README.md) |
| Full feature docs | [docs/adversarygraph-platform-guide.md](adversarygraph-platform-guide.md) |
| Version history | [docs/version-matrix.md](version-matrix.md) |
| Changelog | [CHANGELOG.md](../CHANGELOG.md) |
| Security policy | [SECURITY.md](../SECURITY.md) |
| Known limitations | [docs/limitations.md](limitations.md) |
| Observability and security validation | [docs/observability-security-validation.md](observability-security-validation.md) |
| Commercial trust package | [Commercial Trust](https://1200km.com/adversarygraph-docs/commercial-trust/) |
| Architecture diagrams | [Architecture Diagrams](https://1200km.com/adversarygraph-docs/architecture/) |
| Case studies and validation examples | [Case Studies And Validation Examples](https://1200km.com/adversarygraph-docs/case-studies-validation/) |
| Comparison pages | [Comparison Overview](https://1200km.com/adversarygraph-docs/comparisons/overview/) |
| Deployment boundary | [SECURITY.md — Deployment Boundary](../SECURITY.md#deployment-boundary) |
| Attack Simulation safety model | [docs/attack-simulation.md — Safety Model](attack-simulation.md#safety-model) |

## What this tool is

AdversaryGraph is a **self-hosted AI-assisted CTI workbench** for:

- Uploading threat reports and extracting ATT&CK-mapped techniques with AI assistance
- Reviewing, accepting, and rejecting extracted mappings as an analyst
- Building detection coverage plans tied to specific TTPs
- Running Attack Simulation scenarios against authorized lab targets, reviewing real lab-target telemetry, and forwarding either real lab logs or synthetic source-shaped telemetry to a SIEM for rule validation
- Generating AI-assisted kill-chain scenarios for detection engineering exercises
- Reviewing platform health through self-test, API request metrics, recent traces, redacted log tails, and Prometheus-compatible metrics

## What this tool is NOT

| Claim | Status |
|---|---|
| Production SaaS | Not claimed. Default deployment is for local or controlled self-hosted use. |
| Multi-tenant cloud product | Not implemented. Native user auth is project-level access control, not tenant isolation. |
| Hardened internet-facing service | Not the default. Requires TLS, auth enabled, network restrictions, and operator hardening — documented in [SECURITY.md](../SECURITY.md) and [Authentication and User Management](authentication-and-users.md). |
| Automated threat actor attribution | Not claimed. TTP overlap is an investigation lead, not attribution proof. |
| Replacement for analyst judgment | Not claimed. All AI outputs require analyst review before operational use. |
| Live attack framework | Not claimed. Attack Simulation uses approved lab fixtures and benign canaries; it is not a general exploit runner and does not target arbitrary systems. |

## Security posture

- All containers run as non-root users (verified in all Dockerfiles)
- PostgreSQL bound to 127.0.0.1 in default Compose profile
- All services have resource limits and `cap_drop: ALL` in Docker Compose
- API keys are passed via environment variables, not embedded in code
- LLM outputs are treated as untrusted and require analyst review
- Generated detection logic (Sigma/KQL/SPL/EQL) is a draft and must be reviewed before deployment
- SIEM forwarding secret values (bearer tokens, passwords) are not stored server-side
- Real lab telemetry and synthetic AI telemetry are labeled separately in documentation and UI copy

See [SECURITY.md](../SECURITY.md) for the full policy and known limitations.

## CI coverage

| Check | Status |
|---|---|
| Backend unit + integration tests | ✅ GitHub Actions |
| Backend lint (ruff) | ✅ GitHub Actions |
| Backend SAST (bandit, medium/high) | ✅ GitHub Actions |
| Backend dependency audit (pip-audit) | ✅ GitHub Actions |
| Frontend build | ✅ GitHub Actions |
| Frontend dependency audit (npm audit) | ✅ GitHub Actions |
| Docker Compose validation | ✅ GitHub Actions |
| Docker build check | ✅ GitHub Actions |
| Container scan (Trivy) | ✅ GitHub Actions |
| Secret scan (gitleaks) | ✅ GitHub Actions |

## Test coverage

26 test files covering:

- Unit tests: API routes, ATT&CK mapping, report parsing, export formats, LLM provider selection, IOC extraction, YARA scanning
- Integration tests: database operations, job pipeline, Celery-backed sync/collection routes, endpoint orchestration

## Demo dataset

A deterministic demo dataset is available in [`demo/`](../demo/) for evaluation without private data.

## Known open items

- Starlette/FastAPI transitive dependencies: audited in CI with `pip-audit`; internet-facing deployments should still normalize `Host` headers at a trusted reverse proxy
- Backend coverage gate is intentionally conservative while route-level coverage is expanded

## Contact

Questions about security: [1200km@gmail.com](mailto:1200km@gmail.com) — see [SECURITY.md](../SECURITY.md) for responsible disclosure guidance.
