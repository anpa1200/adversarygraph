# Reviewer Guide

This guide is for security researchers, package curators, and tool evaluators who want to assess AdversaryGraph for inclusion in curated lists, publication roundups, or organizational adoption.

## Quick orientation

| Item | Location |
|---|---|
| Project overview | [README.md](../README.md) |
| Full feature docs | [docs/adversarygraph-platform-guide.md](adversarygraph-platform-guide.md) |
| Module-by-module examples and case studies | [docs/module-reference.md](module-reference.md) |
| Version history | [docs/version-matrix.md](version-matrix.md) |
| v6.5 release notes | [docs/release-notes/v6.5.0.md](release-notes/v6.5.0.md) |
| v6.5 release summary | [docs/release-summary-v6.5.0.md](release-summary-v6.5.0.md) |
| v6 release readiness | [docs/release-readiness-v6.md](release-readiness-v6.md) |
| Local case studies | [docs/case-studies-v6.md](case-studies-v6.md) |
| Tagged v6.0.0 screenshot evidence | [docs/assets/adversarygraph-v6/manifest.md](assets/adversarygraph-v6/manifest.md) |
| Evidence-to-Detection Graph | [docs/evidence-to-detection-graph.md](evidence-to-detection-graph.md) |
| Unified intelligence RAG | [docs/unified-rag-and-mcp.md](unified-rag-and-mcp.md) |
| MCP server contract | [docs/mcp-server.md](mcp-server.md) |
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
- Building governed threat-hunt hypotheses, query revisions, findings, and
  outcomes with optional multi-provider AI suggestions and mandatory review
- Searching reviewed/community Sigma and YARA-L material and generating typed,
  escaped query drafts from IOCs
- Reviewing saved assets and running explicitly authorized, inventory-bound
  passive, Nmap, and web posture assessment
- Managing named users and persistent least-privilege SOC groups whose module
  and action grants are enforced by both the UI and API
- Reviewing, accepting, and rejecting extracted mappings as an analyst
- Building detection coverage plans tied to specific TTPs
- Preserving evidence-to-detection reasoning chains from raw evidence through claims, behavior, ATT&CK mapping, required telemetry, detection logic, validation, SIEM result, and analyst decision
- Running Attack Simulation scenarios against authorized lab targets, reviewing real lab-target telemetry, and forwarding either real lab logs or synthetic source-shaped telemetry to a SIEM for rule validation
- Generating AI-assisted kill-chain scenarios for detection engineering exercises
- Searching a normalized cross-module IOC/CVE/TTP/actor/report/hunt/evidence/
  asset corpus with exact, full-text, optional private vector, and bounded
  relationship retrieval
- Applying private business context to ranking, generating citation-bound
  answers, and reviewing persisted, expiring ATT&CK Navigator advisory proposals
- Exposing the same bounded retrieval and advisory proposal boundary to a local
  stdio MCP client without automatic platform mutation
- Reviewing platform health through self-test, API request metrics, recent traces, redacted log tails, and Prometheus-compatible metrics

## What this tool is NOT

| Claim | Status |
|---|---|
| Production SaaS | Not claimed. Default deployment is for local or controlled self-hosted use. |
| Multi-tenant cloud product | Not implemented. Native user auth is project-level access control, not tenant isolation. |
| Hardened internet-facing service | Not the default. Requires TLS, auth enabled, network restrictions, and operator hardening — documented in [SECURITY.md](../SECURITY.md) and [Authentication and User Management](authentication-and-users.md). |
| Automated threat actor attribution | Not claimed. TTP overlap is an investigation lead, not attribution proof. |
| Autonomous RAG decision or response engine | Not claimed. Retrieval ranks evidence for review; it does not prove targeting, active IOCs, exploitation, or compromise, and it does not block, contain, execute, or save a layer automatically. |
| Remote MCP service | Not implemented. The supported MCP process is local stdio only and calls fixed authenticated API routes. |
| Replacement for analyst judgment | Not claimed. All AI outputs require analyst review before operational use. |
| Live attack framework | Not claimed. Attack Simulation uses approved lab fixtures and benign canaries; it is not a general exploit runner and does not target arbitrary systems. |

## Security posture

- AdversaryGraph application images run as non-root users; bundled database,
  Redis, build-helper, and third-party base images retain their upstream runtime
  model and must be covered by deployment policy.
- PostgreSQL bound to 127.0.0.1 in default Compose profile
- Core application services have Compose resource and capability restrictions;
  the production overlay and Helm chart add the deployment-specific controls
  documented in their manifests.
- API keys are passed via environment variables, not embedded in code
- LLM outputs are treated as untrusted and require analyst review
- RAG indexes only allowlisted normalized fields; vector similarity and
  one-hop relationship expansion are labeled retrieval signals, not evidence
  confidence
- Embeddings are local-only and the configured endpoint host must pass the
  private-network validation boundary
- Navigator proposals are source-bound, expiring, checksum-checked, locally
  ATT&CK-validated, and require explicit Add/Replace confirmation; confirmation
  persists the audit decision but does not save or mutate a named layer
- MCP has no confirmation, reindex, arbitrary SQL/URL, or operational-action
  tool and should use a dedicated least-privilege session
- Evidence Graph AI-generated nodes and edges are drafts until analyst-reviewed
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
| OpenAPI/frontend contract consistency | ✅ GitHub Actions |
| 31-module documentation coverage | ✅ GitHub Actions |
| Frontend dependency audit (npm audit) | ✅ GitHub Actions |
| Anomaly documentation build and dependency audit | ✅ GitHub Actions |
| Docker Compose validation | ✅ GitHub Actions |
| Docker build check | ✅ GitHub Actions |
| Container scan (Trivy) | ✅ GitHub Actions |
| Secret scan (gitleaks) | ✅ GitHub Actions |

## Test coverage

More than 60 backend test files plus browser-spec coverage for:

- Unit tests: ATT&CK mapping, report parsing, export formats, LLM provider
  selection, safe HTTP, rate limiting, observability, archive handling, Threat
  Hunting AI, RAG retrieval/generation/retention/worker behavior, MCP input and
  output boundaries, IOC extraction, and YARA scanning.
- Integration tests: route authorization, database operations, user/session/MFA
  lifecycle, uploads, analysis, collection, simulation, MalwareGraph, Threat
  Radar, Threat Hunting, RAG profile/search/assistant/proposal/reindex APIs, and
  endpoint orchestration.
- Playwright tests: authentication startup, main navigation and deep links,
  permissions, administrator user creation and password-policy validation,
  safe link handling, Threat Hunting, RAG source deep links, and deterministic
  release screenshot flows.

## Demo dataset

A deterministic demo dataset is available in [`demo/`](../demo/) for evaluation without private data.

## Known open items

- Starlette/FastAPI transitive dependencies: audited in CI with `pip-audit`; internet-facing deployments should still normalize `Host` headers at a trusted reverse proxy
- Backend line coverage has an enforced 60% baseline. Aggregate coverage is not
  treated as proof that every high-risk path is tested; the next target remains
  70% with risk-weighted route and failure-path coverage.

## Contact

Questions about security: [1200km@gmail.com](mailto:1200km@gmail.com) — see [SECURITY.md](../SECURITY.md) for responsible disclosure guidance.
