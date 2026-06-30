# Version Matrix

This file is the canonical reference for AdversaryGraph release history and feature gates.

## Current Release

| Field | Value |
|---|---|
| Version | v5.1.0 |
| Release date | 2026-06-30 |
| Theme | Attack Simulation telemetry fidelity and review hardening |
| Status | Stable — hardening sprint in progress |

## Release History

| Version | Theme | Key additions |
|---|---|---|
| v5.1.0 | Telemetry Fidelity and Review Hardening | Source-correct telemetry policy for Attack Simulation, raw STIX object/relationship preservation, AI assistant prompt guardrails, updated architecture documentation, CI-validated release metadata |
| v5.0.0 | Attack Simulation and SIEM Validation | TTP-first simulation matrix, real lab-target attack flows, AI kill-chain telemetry generation, SIEM forwarding with authentication, Scenario Library, attack-chain graph view |
| v4.1.0 | Detection Coverage | Detection coverage states per technique, Sigma/KQL/SPL/EQL skeleton export, telemetry source tracking, coverage summaries by tactic and platform |
| v4.0.0 | Detection Engineering Workflow | Detection backlog export, detection coverage tracking, production-readiness hardening |
| v3.2.0 | Evidence Binding | Source paragraph/span references, evidence snippets beside ATT&CK mappings, evidence-backed export |
| v3.1.0 | Analyst Review Workflow | Review states (`suggested`/`accepted`/`rejected`/`needs-evidence`), analyst notes, confidence filtering |
| v3.0.0 | Malware Analysis Module | YARA scanning, string extraction, PE header parsing, IOC extraction, AI-assisted analysis |
| v2.x | Report Processing | Multi-format ingestion, AI TTP extraction, ATT&CK mapping, Navigator export, JSONB storage |
| v0.2.0–v1.x | Foundation | Initial FastAPI backend, React frontend, PostgreSQL, Redis, Celery, Docker Compose |

For complete per-version changelogs see [CHANGELOG.md](../CHANGELOG.md).

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
