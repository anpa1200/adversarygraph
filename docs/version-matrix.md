# Version Matrix

This file is the canonical reference for AdversaryGraph release history and feature gates.

## Current Release

| Field | Value |
|---|---|
| Version | v5.6.0 |
| Release date | 2026-07-02 |
| Theme | Statistics tag analytics, Evidence-to-Detection Graph workflows, and cross-dataset detection-engineering views |
| Status | Stable — hardening sprint in progress |

## Release History

| Version | Theme | Key additions |
|---|---|---|
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
For the current release narrative, see [v5.6.0 release summary](release-summary-v5.6.0.md).

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
