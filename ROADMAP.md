# Roadmap

Current release: **v6.5.0** — Governed intelligence, hunting, exposure assessment, and SOC operations (2026-07-25)

For the full history from v0.2.0 through v6.5.0 see [CHANGELOG.md](CHANGELOG.md).

## Unreleased

- [ ] Record future work here after the v6.5.0 release boundary.

## v6.5 — Governed Intelligence, Hunting, Asset Assessment, and SOC Operations

- [x] Add a hypothesis-driven Threat Hunting workspace with query revisions,
  evidence-preserving findings, reviewed dispositions, exports, and Threat
  Radar handoff
- [x] Add advisory AI assistance at planning, query, findings, and outcome
  stages, including source-bound report-to-hypothesis generation
- [x] Add a normalized, provenance-preserving corpus across IOC, CVE,
  ATT&CK/ATLAS, actor intelligence, campaigns, reports, knowledge, Threat
  Radar, Threat Hunting, Evidence Graph, and sanitized asset records
- [x] Add exact identifier, PostgreSQL full-text, and optional pgvector retrieval
  with reciprocal-rank fusion, business-profile reranking, lexical-only
  fallback, and bounded relationship expansion
- [x] Add a citation-bound Navigator intelligence assistant with TLP/legal
  provider controls, verified ATT&CK IDs, expiring preview proposals, and
  explicit Add/Replace confirmation
- [x] Add a stdio-only MCP facade for bounded intelligence search, grounded
  questions, indexed-entity reads, and advisory Navigator proposals without
  platform mutation
- [x] Add scheduled, lock-protected corpus reconciliation and bounded retention
  for tombstoned documents, assistance records, and dependent proposals
- [x] Enforce explicit backend and frontend permissions for analysis, uploads,
  intelligence, detections, feeds, exports, simulation, SIEM, auth, users, and
  audit access
- [x] Add decoded upload/response limits, bounded request schemas, safer archive
  extraction, SSRF-hardened outbound fetches, and explicit residual egress
  controls
- [x] Harden authentication, MFA enrollment, session administration, rate-limit
  identity, request observability, and background-task shutdown behavior
- [x] Improve frontend authentication recovery, request cancellation, stale
  response suppression, safe external links, route-level permissions, error
  handling, persistence, deep links, and route code splitting
- [x] Harden Compose, Helm, container users and filesystems, production preflight,
  CI action pinning, tag-only publication, backup/restore, seven-image release
  publication, and ten-image stack scanning
- [x] Add persistent SOC groups, named-user administration, grant ceilings, and
  consistent module-level API/UI authorization across 31 workspaces
- [x] Add a searchable saved-asset registry, evidence-labelled asset detail,
  authorized exposure assessment, bounded passive/Nmap/web checks, and
  controlled merging of discovered inventory facts
- [x] Add the reviewed/community Query Library, Sigma and YARA-L workflows,
  deterministic IOC-to-query generation, and ATT&CK-linked search
- [x] Add complete API contract validation for all documented platform
  operations and include it in CI
- [x] Add a detailed module reference and casebook for every governed workspace,
  validated against the backend catalog in CI
- [x] Assign v6.5.0 and update source, package, Helm, release, and reviewer
  metadata
- [ ] Cut the immutable v6.5.0 tag only after merge CI and the complete release
  gate pass

## v6.0 — Operational Evidence and Production Readiness

- [x] Consolidate and correct the complete v5 release history
- [x] Add reproducible v6 screenshot capture and sanitized evidence assets
- [x] Add local, evidence-backed case studies using repository demo data
- [x] Add an explicit release-readiness gate and deployment go/no-go checklist
- [x] Remove stale hard-coded frontend release metadata
- [x] Align backend, frontend, Helm, README, roadmap, security policy, changelog,
  release notes, and reviewer documentation on v6.0.0
- [x] Revalidate backend, frontend, Compose, security, and release checks

## v5.9.1 — JA3/JA4+ Network Fingerprint IOC Workflows

- [x] Add JA3, JA3S, JA4, JA4S, JA4H, JA4L, JA4LS, JA4X, JA4SSH, and JA4T IOC types
- [x] Extract labeled JA3/JA4+ fingerprints from uploaded report text
- [x] Normalize network fingerprints during IOC import and preserve raw context
- [x] Add network fingerprint filtering and labels in IOC Library
- [x] Add network fingerprint context to IOC Detail and IOC node detail pages
- [x] Include network fingerprints in IOC Investigation pivots and scoring

## v5.9 — EMB3D and Threat Radar Asset Workflows

- [x] Add EMB3D backend service and API route for embedded-device threat model assessment workflows
- [x] Add EMB3D frontend page and documentation
- [x] Add unified model support for product, component, dependency, and asset exposure analysis
- [x] Add Threat Radar full asset-inventory templates and product-security example datasets
- [x] Add Threat Radar asset review page for product/component/dependency exposure triage
- [x] Extend Asset Surface and Threat Radar tests for the expanded asset workflow

## v5.7 — Research Collection and Linked Report Review

- [x] Add Reports / Research collection page with TTP, IOC, CVE, threat actor, sector, and infrastructure tag buckets
- [x] Add linked report review pages with inline links back to Navigator, IOC Library, CVE Library, and ATT&CK Group Library
- [x] Preserve source text for new AI analysis sessions so report evidence remains reviewable
- [x] Add Upload Research control with optional Parse with AI workflow
- [x] Add store-only research upload path for analyst staging before LLM parsing
- [x] Add AdversaryGraph research analysis guide based on embedded/hardware/firmware research workflow
- [ ] Add bulk research import queue with per-report parsing status
- [ ] Add reviewed tag editing and analyst confidence overrides

## v5.6 — Evidence-to-Detection Graph

- [x] Add relational Evidence Graph node and edge model for evidence-backed reasoning paths
- [x] Add CRUD, summary, path, gap, generation, and export APIs
- [x] Add frontend Evidence Graph page with overview, interactive graph, path view, gap view, review queue, and node detail actions
- [x] Add safe synthetic demo dataset for evidence-to-detection review
- [x] Document AI draft boundaries, readiness scoring, exports, gaps, and limitations
- [x] Add Statistics tag analytics across IOC, CVE, TTP, actor/group, report, sector, and cross-dataset views
- [x] Add risk, confidence, region, sector, type, source, telemetry, TLP, attack-vector, malware-family, and relationship-confidence tag widgets
- [ ] Add typed foreign-key relationship tables for every external entity link
- [ ] Add deeper ATT&CK data-component import and ECS/OCSF/Splunk CIM/Sentinel ASIM field mapping
- [ ] Add SIEM-specific rule compilers and detection regression tests

## v5.x — Hardening Sprint

- [x] Migrate the legacy Gemini SDK package to `google-genai` (SDK renamed by Google)
- [x] Expand CI: add ruff lint, pip-audit, npm audit, Docker build checks, container scan (Trivy), secret scan (gitleaks)
- [x] Add route-level integration tests for high-risk mutating Operations and Pipeline endpoints
- [x] Publish reviewer guide and demo dataset
- [x] Document Starlette transitive dependency version and CVE status
- [x] Raise the backend coverage gate to an enforced 60% baseline
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

- Packaged, opt-in local LLM gateway profile (Ollama / LM Studio); the current
  integration uses an operator-managed private OpenAI-compatible endpoint
- Retrieval evaluation fixtures and relevance/recall regression thresholds
- Streaming or paged source materialization for very large RAG corpora
- Per-source distribution markings where authoritative tables do not yet store
  reviewed TLP metadata
- Independently scoped MCP credentials; remote MCP transport remains out of
  scope until an OAuth-based authorization boundary exists
- Tenant-level ownership across every source table; use separate deployments
  for mutually untrusted customers until this exists
- STIX/TAXII export mode
- Case timeline view
- ATT&CK version-diff view for mappings across releases
- Mapping evaluation harness for public CTI reports
- STIX 2.1 bundle export
