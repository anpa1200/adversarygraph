# AdversaryGraph v5: Complete Release Overview

This document consolidates the changes shipped from **v5.0.0 through v5.9.1**.
It is an orientation guide; [`CHANGELOG.md`](../CHANGELOG.md) remains the
canonical release ledger and [`release-notes/`](release-notes/) contains the
version-specific notes.

## What Changed Across v5

AdversaryGraph v5 grew from an ATT&CK mapping and detection-validation platform
into a broader defensive intelligence workbench. The v5 series added controlled
attack simulation, source-correct telemetry, raw STIX retention, CVE and IOC
correlation, authentication and enterprise access controls, observability,
cross-dataset statistics, research collection, product-security threat radar,
embedded-device threat modeling, asset exposure workflows, and JA3/JA4+
network-fingerprint investigations.

## Release-by-Release Changes

### v5.0.0 — Attack Simulation and SIEM Validation

- Added a TTP-first Attack Simulation workspace and per-technique configuration
  routes.
- Added a built-in Docker lab web target and fixed benign request flows for
  web discovery, exposure validation, injection-shaped canaries, authentication
  testing, beaconing, transfer, and exfiltration-shaped validation.
- Added real-time access, security, error, authentication, and JSONL attack-run
  logs.
- Added guarded HTTP(S) SIEM forwarding with authentication, routing options,
  delivery status, and non-secret destination history.
- Added the AI Attack Assistant, 25 scenario templates, multi-source complicated
  attack mode, an attack-chain graph, and scenario explanations.
- Renamed External Simulation to Attack Simulation while retaining a redirect
  for the old route.
- Kept execution lab-scoped: fixed canaries, allowlisted targets, no arbitrary
  exploit payloads, and no arbitrary command execution.

### v5.1.0 — Telemetry Fidelity, Raw STIX, and CVE Intelligence

- Required simulations to produce source-correct, vendor/source-shaped
  telemetry and to report unsupported techniques as telemetry gaps.
- Added a telemetry-readiness matrix to technique details.
- Preserved every ingested STIX object and relationship in raw graph tables
  alongside the normalized ATT&CK query model.
- Added the CVE Library with NVD CVE API 2.0 and CISA KEV synchronization,
  CVSS/CWE/CPE storage, and evidence-backed CVE links to techniques, IOCs, and
  threat actors.
- Added CVE layout fixes, AI-assistant guardrails, and documentation for the
  ATT&CK/STIX and CVE data models.

### v5.2.0 — QA and UI Hardening

- Made backend tests reproducible in a clean shell with explicit test-safe
  database-password and log-directory defaults.
- Cleared the frontend dependency audit finding by overriding Monaco's
  transitive DOMPurify dependency to a patched release.
- Added a shared frontend component-system foundation and migrated key
  workspaces to it.
- Fixed resizable Debugger panel sizing and revalidated backend lint/tests,
  frontend audit, and the production build.

### v5.3.0 — Authentication and User Operations

- Added native authentication and user management.
- Added a pre-login `/auth-guide`, linked it from the login screen, and
  documented bootstrap administration, roles, password reset, and session
  behavior.
- Passed authentication bootstrap settings through Compose services.
- Updated quickstart, administration, security, production-readiness, and
  public-demo privacy guidance for native authentication and optional
  identity-aware reverse proxies.

### v5.4.0 — Observability and Security Validation

- Added an authenticated Observability dashboard for uptime, request metrics,
  recent traces, top routes, redacted API log tails, and Prometheus-compatible
  metrics.
- Added backend summary, trace, log, and metrics routes.
- Added `make security-scan` and a local security-scan script covering the
  available lint, SAST, dependency, secret, Compose, and container checks.
- Added Bandit SAST to CI and corrected weak-hash and XML-parsing findings.
- Added screenshot-backed validation material for authentication, Attack
  Simulation, CVE correlation, malware analysis, observability, and security
  scanning.

### v5.5.0 — Enterprise Access Controls and Production Readiness

- Expanded RBAC roles and per-user permissions.
- Added password-policy settings, MFA workflow support, and trusted-proxy SSO
  metadata.
- Added session inventory, individual and revoke-all controls, user-session
  revocation, and authentication audit history.
- Updated the Admin Panel, Compose files, production overlay, Helm values, and
  environment examples for the new access controls.
- Expanded commercial-trust and production-readiness documentation and refined
  navigation, evidence-graph entry points, and page scrolling.

### v5.6.0 — Statistics and Tag Analytics

- Expanded Statistics across IOC, CVE, TTP, actor/group, report, sector, and
  cross-dataset views.
- Added widgets for risk, confidence, region, sector, type, source, telemetry,
  TLP, attack vector, malware family, free-form IOC tags, and relationship
  confidence.
- Added a global entity tag cloud.
- Hardened widget query isolation so one failed query no longer hides later
  results, and added regression coverage for the widget catalog.
- Improved startup checks, local help, comparison empty states, ATT&CK data
  permissions, and troubleshooting guidance.

### v5.7.0 — Research Collection and Linked Report Review

- Added the Reports / Research collection workspace.
- Added deterministic TTP, IOC, CVE, actor, sector, and infrastructure tag
  buckets.
- Added linked report pages that retain source text and pivot into Navigator,
  IOC Library, CVE Library, and ATT&CK Group Library.
- Added research upload with optional AI parsing and a store-only path for
  analyst staging.
- Added a research-analysis guide for hardware, firmware, embedded, edge,
  BMC, UEFI, GPU, SOHO/IoT, and OT/IoT material.
- Included additional security, datetime, test, startup-ingestion, and CI
  hardening.

### v5.8.0 — Product-Security Threat Radar

- Added Threat Radar for product-security CTI early warning.
- Added scored signals, claims, evidence, entities, cases, links, watchlists,
  product mappings, workflow queues, reports, and audit records.
- Added product, component, and dependency exposure mapping with source
  reliability, claim credibility, relevance, exploitability, exposure, and
  blast-radius scoring.
- Added case graphs and PSIRT, Threat Hunt, incident-response, and detection
  requirement workflows.
- Added Flash Note, Product Impact Assessment, Threat Hunt Pack, PSIRT appendix,
  and Executive Summary outputs.
- Added sanitized handling and explicit boundaries for legal-sensitive or
  restricted-source intelligence.

### v5.9.0 — EMB3D and Asset Exposure Workflows

- Added EMB3D backend, API, frontend, tests, and guidance for embedded-device
  threat-model assessment.
- Unified product, component, dependency, and asset modeling across Threat
  Radar and Asset Surface.
- Added full asset-inventory templates and product-security example datasets
  for products, components, dependency/SBOM data, exposures, and assets.
- Added a Threat Radar asset-review page for product/component/dependency
  exposure triage.

### v5.9.1 — JA3/JA4+ Network-Fingerprint IOCs

- Added JA3, JA3S, JA4, JA4S, JA4H, JA4L, JA4LS, JA4X, JA4SSH, and JA4T IOC
  types.
- Added labeled fingerprint extraction from report text, normalized import
  tagging, and raw-context preservation.
- Added fingerprint context, labels, and filtering to IOC Detail, IOC Library,
  and IOC node-detail workflows.
- Added network fingerprints to IOC Investigation pivot scoring while hiding
  inapplicable VirusTotal lookup actions.
- Clarified that fingerprints are correlation signals and require supporting
  evidence before being treated as malicious.

## Cross-Cutting Outcome

The v5 line connects the defensive workflow end to end:

1. Collect reports, research, CVEs, IOCs, assets, and product-security signals.
2. Preserve source evidence and normalize ATT&CK, STIX, vulnerability, and
   observable relationships.
3. Prioritize risks through statistics, Threat Radar, EMB3D, and exposure
   analysis.
4. Turn findings into detections, hunts, PSIRT/IR actions, and controlled
   ATT&CK simulations.
5. Validate telemetry and SIEM delivery with authentication, auditability,
   observability, CI security checks, and documented safety boundaries.

## Related Documentation

- [Version matrix](version-matrix.md)
- [Complete changelog](../CHANGELOG.md)
- [v5.0 Attack Simulation guide](attack-simulation.md)
- [CVE and CVSS intelligence](cve-cvss-intelligence.md)
- [Authentication and users](authentication-and-users.md)
- [Observability and security validation](observability-security-validation.md)
- [Research analysis guide](research-analysis-guide.md)
- [Threat Radar guide](threat-radar.md)
- [EMB3D guide](emb3d.md)

