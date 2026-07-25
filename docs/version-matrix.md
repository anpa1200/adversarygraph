# Version Matrix

This file is the canonical reference for AdversaryGraph release history and feature gates.

## Current Release

| Field | Value |
|---|---|
| Version | v6.5.0 |
| Release date | 2026-07-25 |
| Theme | Governed intelligence, hunting, exposure assessment, and SOC operations |
| Status | Source release prepared; immutable tag and artifacts require the successful tag workflow |

The source release is v6.5.0. The latest previously published immutable tag is
v6.0.0 until the v6.5.0 tag workflow completes. Historical v6.0 screenshots and
artifact limitations remain scoped to that tag.

### v6.5 Capability Promotion

v6.5.0 promotes the complete development line after v6.0.0: governed Threat
Hunting and Query Library workflows, multi-provider AI, unified hybrid RAG,
the Navigator intelligence assistant, local stdio MCP, saved-asset
intelligence, inventory-bound exposure assessment, persistent SOC access
groups, module-level authorization across 31 workspaces, complete API
contracts, and the hardened seven-image release path. They are documented in
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md), the
[v6.5.0 release notes](release-notes/v6.5.0.md), and the changelog. They are not
retroactively attributed to the immutable v6.0.0 tag. The earlier v6.1.0 source
milestone was not published as a stable tag and is superseded by v6.5.0.

## Release History

| Version | Theme | Key additions |
|---|---|---|
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
For the current release narrative, see [v6.5.0 release notes](release-notes/v6.5.0.md).

## Feature Gate Legend

| Label | Meaning |
|---|---|
| **Implemented** | Shipped and available in the current release |
| **Implemented (partial)** | Core logic shipped; some UI controls or edge cases remain pending |
| **Planned** | On the roadmap but not yet started |
| **Gated** | Available only in specific deployment configurations |
| **AI-generated** | Output is produced by an LLM and requires analyst review before use |
| **Synthetic** | Telemetry or data is generated for testing purposes, not from a real attack |
| **Not claimed** | Functionality that is sometimes assumed but is explicitly not implemented |

See [ROADMAP.md](../ROADMAP.md) for upcoming work.
