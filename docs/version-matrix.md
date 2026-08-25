# Version Matrix

This file is the canonical reference for AdversaryGraph release history and feature gates.

## Current Pre-release

| Field | Value |
|---|---|
| Version | v8.0.0-beta.1 |
| Release date | 2026-08-25 |
| Theme | Governed report promotion and durable workflow authority |
| Status | Manual-testing pre-release; automated and deployment-specific acceptance evidence remains required |

Immutable beta artifacts and their digest manifest exist only after the
protected `v8.0.0-beta.1` tag workflow succeeds. Historical screenshots and v7
test records are not beta runtime evidence. The beta must not be represented as
stable or manually accepted while the v8 readiness matrices remain pending.

### v8 Beta Capability Evaluation

v8.0.0-beta.1 adds the five-gate Report Review Gate, source-bound claims,
two-person approval, promotion/revocation authority, durable research projects,
transactional workflow/outbox processing, Alembic revisions 0001-0004, blocking
Compose/Helm migration gates, React Router 7, and the new Operation Desert Hydra
AdversaryGraph workflow draft. See the
[beta release notes](release-notes/v8.0.0-beta.1.md) and
[v8 readiness matrix](release-readiness-v8.md).

## Latest Stable Release

| Field | Value |
|---|---|
| Version | v7.0.0 |
| Release date | 2026-08-12 |
| Theme | Isolated assessment, governed intelligence, and data quality |

v7.0.0 remains the latest stable release. Its release notes and historical
readiness record are not rewritten to describe v8 behavior.

## Release History

| Version | Theme | Key additions |
|---|---|---|
| v8.0.0-beta.1 | Governed Report Promotion and Durable Workflow Authority | Manual-testing pre-release: five-gate Review Gate, two-person promotion, downstream evidence authority, research workflow runtime, transactional outbox, Alembic 0001-0004, Compose/Helm migration gates, React Router 7, and Desert Hydra workflow draft |
| v7.0.0 | Isolated Assessment, Governed Intelligence, and Data Quality | Private scanner MCP boundary, verified assessment traces, production RAG/MCP readiness, governed local AI adapter, stronger intelligence relationships, closed taxonomy, self-maintaining catalogs, self-test data inventory, and eight-image release publication |
| v6.5.0 | Governed Intelligence, Hunting, Exposure Assessment, and SOC Operations | Threat Hunting and Query Library workflows, unified RAG/MCP, saved-asset intelligence, inventory-bound passive/Nmap/web assessment, persistent SOC groups, module-level API/UI authorization across 31 workspaces, complete API contracts, and post-v6 platform hardening |
| v6.0.0 | Operational Evidence and Production Readiness | Reproducible release gate, corrected v5 history, tagged screenshot evidence, local case studies, deployment go/no-go criteria, version-derived UI metadata, and reviewer handoff material |
| v5.9.1 | JA3/JA4+ Network Fingerprint IOC Workflows | JA3/JA3S/JA4/JA4S/JA4H/JA4L/JA4LS/JA4X/JA4SSH/JA4T IOC types, report-text extraction, normalized import tagging, IOC Library filtering, IOC Detail context, IOC node detail support, and IOC Investigation pivots |
| v5.9.0 | EMB3D and Threat Radar Asset Workflows | EMB3D API/service/UI/documentation, unified product/component/dependency/asset modeling, full asset-inventory import templates, product-security sample datasets, and Threat Radar asset review pages |
| v5.8.0 | Threat Radar Product-Security CTI | Threat Radar module, scored CVE/KEV/PoC/zero-day/supplier/package/hardware/customer/internal telemetry signals, product/component/dependency exposure mappings, case graph, sanitized legal-sensitive evidence handling, PSIRT/Hunt/IR/Detection queues, watchlists, and generated reports |
| v5.7.0 | Research Collection and Linked Report Review | Reports / Research collection page, linked report review with inline entity links, source-text preservation for AI analysis, store-only research upload, Parse with AI upload workflow, and research analysis guide |
| v5.6.0 | Statistics Tag Analytics | Expanded Statistics module with IOC/CVE/TTP/actor/report/sector/global tag widgets for risk, confidence, region, sector, type, source, telemetry, TLP, attack vector, malware family, and relationship-confidence analysis |
| v5.5.0 | Enterprise Access Controls | Expanded RBAC roles, per-user permissions, password policy settings, MFA workflow support, trusted proxy SSO metadata, session inventory and revocation, authentication audit history, Admin Panel updates, and deployment configuration coverage |
| v5.4.0 | Observability and Validation Evidence | Authenticated Observability dashboard, request metrics, recent traces, redacted API log tail, Prometheus-compatible metrics endpoint, backend SAST CI coverage, security scan helper, and screenshot-backed validation examples |
| v5.3.0 | Authentication and User Operations | Local `/auth-guide` page reachable before sign-in, login-page guide link, native auth bootstrap guidance, role model documentation, password reset/session behavior notes, and production/security docs for native auth plus optional identity-aware reverse proxy |
| v5.2.0 | QA Hardening and Release Validation | Reproducible backend test environment defaults, frontend DOMPurify override for Monaco transitive audit cleanup, local lint/test/audit/build validation, and v5.2 release metadata |
| v5.1.0 | Telemetry Fidelity, Raw STIX, and CVE Library Correlation | Source-correct telemetry policy for Attack Simulation, raw STIX object/relationship preservation, CVE Library with NVD/CISA KEV sync, CVSS score fields, and strict APT-TTP-IOC-CVE links, AI assistant prompt guardrails, updated architecture documentation, CI-validated release metadata |
| v5.0.0 | Attack Simulation and SIEM Validation | TTP-first simulation matrix, real lab-target attack flows, AI kill-chain telemetry generation, SIEM forwarding with authentication, Scenario Library, attack-chain graph view |
| v4.1.0 | Detection Coverage | Detection coverage states per technique, Sigma/KQL/SPL/EQL skeleton export, telemetry source tracking, coverage summaries by tactic and platform |
| v4.0.0 | Detection Engineering Workflow | Detection backlog export, detection coverage tracking, production-readiness hardening |
| v3.2.0 | Evidence Binding | Source paragraph/span references, evidence snippets beside ATT&CK mappings, evidence-backed export |
| v3.1.0 | Analyst Review Workflow | Review states (`suggested`/`accepted`/`rejected`/`needs-evidence`), analyst notes, confidence filtering |
| v3.0.0 | Malware Analysis Module | YARA scanning, string extraction, PE header parsing, IOC extraction, AI-assisted analysis |
| v2.x | Report Processing | Multi-format ingestion, AI TTP extraction, ATT&CK mapping, Navigator export, JSONB storage |
| v0.2.0–v1.x | Foundation | Initial FastAPI backend, React frontend, PostgreSQL, Redis, Celery, Docker Compose |

For complete per-version changelogs see [CHANGELOG.md](../CHANGELOG.md).
For a consolidated account of every v5 release, see the [v5 overview](v5-overview.md).
For the current pre-release narrative, see
[v8.0.0-beta.1 release notes](release-notes/v8.0.0-beta.1.md). For the latest
stable narrative, see [v7.0.0 release notes](release-notes/v7.0.0.md).

## Feature Gate Legend

| Label | Meaning |
|---|---|
| **Beta** | Pre-release functionality awaiting complete manual and deployment-specific acceptance |
| **Implemented** | Present in the checked-out source; beta items still require their documented acceptance evidence |
| **Implemented (partial)** | Core logic shipped; some UI controls or edge cases remain pending |
| **Planned** | On the roadmap but not yet started |
| **Gated** | Available only in specific deployment configurations |
| **AI-generated** | Output is produced by an LLM and requires analyst review before use |
| **Synthetic** | Telemetry or data is generated for testing purposes, not from a real attack |
| **Not claimed** | Functionality that is sometimes assumed but is explicitly not implemented |

See [ROADMAP.md](../ROADMAP.md) for upcoming work.
