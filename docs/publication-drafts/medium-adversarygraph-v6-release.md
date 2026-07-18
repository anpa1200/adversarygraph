# AdversaryGraph v6.0: The Complete Self-Hosted CTI-to-Detection Platform

## Threat intelligence, ATT&CK mapping, IOC and CVE investigation, Threat Radar, EMB3D, malware analysis, Attack Simulation, SIEM validation, and production operations in one platform

By Andrey Pautov

AdversaryGraph v6.0.0 is now released.

Version 6 is the most complete AdversaryGraph release so far.

Version 4 introduced malware analysis as first-class evidence. Version 5 connected ATT&CK-shaped simulation, target-side telemetry, SIEM delivery, vulnerability intelligence, authentication, observability, Threat Radar, EMB3D, asset exposure, and network fingerprints.

Version 6 brings those capabilities together as one production-ready, controlled self-hosted platform—with a repeatable release gate, current visual evidence, detailed case studies, explicit deployment acceptance criteria, security validation, and a documented upgrade and rollback path.

The result is a complete workflow for moving from raw intelligence to reviewed evidence, prioritized risk, detection engineering action, and validation telemetry.

Release:

https://github.com/anpa1200/adversarygraph/releases/tag/v6.0.0

GitHub:

https://github.com/anpa1200/adversarygraph

Documentation:

https://1200km.com/adversarygraph-docs/

Project hub:

https://1200km.com/adversarygraph/

## The Road to v6

AdversaryGraph started with a practical problem: threat intelligence usually arrives as prose, but defensive teams need structured and reviewable outputs.

The working chain became:

```text
reports / logs / IOCs / CVEs / malware / assets
                    ↓
        evidence extraction and review
                    ↓
      ATT&CK, STIX, and graph relationships
                    ↓
  detections / hunts / PSIRT / IR / simulation
                    ↓
       telemetry and SIEM validation evidence
```

The earlier articles document that evolution:

- [AdversaryGraph: I Built a Self-Hosted AI Threat Intelligence Platform](https://infosecwriteups.com/threatmapper-i-built-a-self-hosted-ai-threat-intelligence-platform-heres-how-to-use-it-0aa7673e6bd8)
- [AdversaryGraph v2.0: I Built a Self-Hosted AI Threat Intelligence Platform](https://infosecwriteups.com/threatmapper-v2-0-i-built-a-self-hosted-ai-threat-intelligence-platform-941a80cc5a65)
- [AdversaryGraph v2.5: New Name, New Release, Full AI CTI Platform Capability Map](https://infosecwriteups.com/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e)
- [30 Practical AdversaryGraph Use Cases](https://infosecwriteups.com/adversarygraph-usecases-820d03c3a7ab)
- [From Log to Report: Using AdversaryGraph](https://medium.com/@1200km/from-log-to-report-using-adversarygraph-eff2e1d8f2cd)
- [AdversaryGraph v4.0: I Added a Full Malware Analysis Workbench](https://medium.com/@1200km/adversarygraph-v4-0-i-added-a-full-malware-analysis-workbench-to-my-self-hosted-cti-platform-8dfbf1db2c9e)
- [AdversaryGraph v5.0: From CTI Mapping to Attack Simulation and SIEM Validation](https://infosecwriteups.com/adversarygraph-v5-0-from-cti-mapping-to-attack-simulation-and-siem-validation-21873b2a6c39)

Those releases expanded what the platform can do. Version 6 packages that work into something an operator can evaluate with evidence.

## What AdversaryGraph Is Today

AdversaryGraph is a self-hosted, AI-assisted CTI-to-detection workbench.

It helps analysts and detection teams:

- ingest reports, logs, IOCs, CVEs, research, malware findings, and asset inventories;
- map behavior to MITRE ATT&CK and ATLAS with evidence and analyst review;
- preserve normalized and raw STIX relationships;
- investigate IOCs and network fingerprints;
- compare reports, groups, campaigns, and behavior overlap;
- prioritize product-security and asset-exposure signals;
- create detection, hunt, PSIRT, and incident-response work items;
- run controlled ATT&CK-shaped lab scenarios;
- inspect target-side telemetry and forward selected events to a SIEM;
- retain review decisions, operational status, and exportable evidence.

The platform is designed for analyst-guided defensive operations. It connects AI analysis, public intelligence, private evidence, malware research, product-security context, and lab validation while preserving the source and review state of the work.

## What Changed in v6.0

The headline improvement is operational confidence across the entire platform.

Version 6 adds five release-level capabilities.

### 1. One repeatable release gate

The new release-readiness command runs the checks an operator should expect before accepting the build:

```bash
./scripts/release-readiness.sh --full
```

The gate covers:

- release metadata and version consistency;
- patch hygiene;
- default and production Docker Compose rendering;
- frontend lint and production build;
- browser smoke tests;
- backend lint and tests;
- dependency audits;
- Bandit static analysis;
- Gitleaks secret scanning;
- container and Compose validation.

The GitHub workflows independently repeat the critical checks. For the public v6 release, the pull-request and post-merge workflows passed backend tests, frontend lint/build/E2E, dependency audits, secret scanning, Bandit, Docker builds, Compose self-tests, Helm validation, and Trivy scans across the release images.

The tag workflow then built and published the versioned container families for the backend, frontend, MalwareGraph service, attack-lab web target, and attack-lab endpoint.

The result is a transparent validation record that operators can repeat in their own environment.

### 2. Current screenshots with a reproducible capture method

Version 6 introduces a reproducible visual-evidence workflow for the current interface.

The current v6 images are captured from the production-built frontend at 1920×1200 using Chromium and sanitized deterministic API fixtures. The Playwright capture checks expected UI content before writing each image.

The manifest records:

- the capture method;
- the surface shown;
- what the screenshot demonstrates;
- the evidence scope of each capture;
- dimensions, file sizes, and SHA-256 checksums;
- the exact command used to reproduce the capture.

Reproduction is straightforward:

```bash
cd frontend
npm ci
npx playwright install chromium
npm run build
npm run screenshots:v6
```

The screenshots provide current, reproducible proof of UI rendering, workflow structure, and documented controls using safe fictional records and approved lab targets.

**Suggested image 1 — Discover workspace**

https://1200km.com/adversarygraph-docs/img/adversarygraph-v6/01-discover-workspace.png

*Caption: The v6 Discover workspace connects intelligence, investigation, asset, evidence, simulation, and malware-analysis workflows.*

### 3. Explicit go/no-go criteria and rollback

The v6 production profile is clearly defined:

> AdversaryGraph v6.0 is suitable for controlled self-hosted production when the operator passes the release-readiness checklist and supplies TLS, authentication, network isolation, managed secrets, backups, monitoring, retention policy, and an approved data-handling process.

The release-readiness guide requires the operator to verify:

1. the exact release and container versions;
2. production Compose rendering;
3. TLS and named authenticated users;
4. private PostgreSQL, Redis, malware-analysis, and attack-lab networks;
5. secret handling and log redaction;
6. backup creation and checksum verification;
7. application self-tests and feature smoke checks;
8. monitoring and retention;
9. a tested rollback decision and procedure.

AdversaryGraph currently uses additive startup schema compatibility rather than a formal Alembic migration chain. That makes a verified pre-upgrade PostgreSQL backup mandatory, not optional.

If an acceptance criterion fails, the documented response is to stop, return to the previous tag, and restore the verified backup when required.

Release readiness guide:

https://1200km.com/adversarygraph-docs/release-readiness-v6/

### 4. Case studies that preserve the evidence boundary

Version 6 ships with reproducible local acceptance studies built from fictional repository data:

#### Report evidence to detection review

A sample report is analyzed for ATT&CK and IOC candidates. The reviewer compares the result with an expected baseline, records unexpected and missing mappings, and keeps generated detections in draft status until they are tested.

The outcome is a defensible chain from source text and AI-assisted extraction to analyst-reviewed work items.

#### Asset exposure prioritization

A fictional inventory is normalized into product, component, dependency, reachability, criticality, and exposure context. Threat Radar and Asset Surface create prioritization questions for PSIRT, Hunt, IR, and Detection teams.

Asset-owner input and authoritative configuration evidence enrich CVE and product context, producing a practical and explainable priority decision.

#### Controlled simulation and SIEM validation

An approved lab target runs a fixed benign ATT&CK-shaped request set. The operator checks target-side telemetry, forwards selected events to a test collector, and records transport, parsing, and detection as separate outcomes.

That separation is essential:

```text
HTTP delivery success ≠ parser success ≠ detection success
```

The expanded documentation now includes 22 detailed validation workflows with prerequisites, numbered procedures, expected results, screenshot evidence, acceptance criteria, and claim boundaries.

Validation catalog:

https://1200km.com/adversarygraph-docs/case-studies-validation/

**Suggested image 2 — CVE Library evidence review**

https://1200km.com/adversarygraph-docs/img/adversarygraph-v6/04-cve-library.png

*Caption: CVE review combines severity, KEV status, relationship evidence, and local asset context in one prioritization workflow.*

### 5. Corrected history and one v5-to-v6 evidence map

Version 6 also corrects the v5.1–v5.4 release record and consolidates the complete v5 evolution.

That history matters because v6 packages a large set of capabilities delivered incrementally:

- v5.0 — controlled Attack Simulation and SIEM validation;
- v5.1 — telemetry fidelity, raw STIX retention, and CVE intelligence;
- v5.2 — QA and UI hardening;
- v5.3 — native authentication and user operations;
- v5.4 — observability and security validation;
- v5.5 — expanded RBAC, sessions, audit history, MFA workflow support, and trusted-proxy SSO metadata;
- v5.6 — cross-dataset statistics and tag analytics;
- v5.7 — research collection and linked report review;
- v5.8 — product-security Threat Radar;
- v5.9 — EMB3D and asset exposure workflows;
- v5.9.1 — JA3/JA4+ network-fingerprint IOC workflows.

Together, these modules create one evidence-to-action workflow:

```text
collect → normalize → review → prioritize → hand off → validate → record
```

## A Closer Look at Controlled Attack Simulation

Attack Simulation remains one of the most visible parts of the platform, so its boundary deserves emphasis.

The workflow begins with ATT&CK technique selection. The operator reviews the scenario, approved target, expected telemetry, timeout, and cleanup requirements before execution.

**Suggested image 3 — Attack Simulation matrix**

https://1200km.com/adversarygraph-docs/img/adversarygraph-v6/02-attack-simulation-matrix.png

*Caption: The v6 Attack Simulation matrix provides a TTP-first entry point and indicates where an approved runnable scenario exists.*

The built-in lab scenarios use approved fixtures and fixed benign requests, giving detection teams a controlled and repeatable way to exercise telemetry pipelines.

The detail view connects:

- approved target context;
- scenario configuration;
- real-time target-side logs;
- guarded SIEM forwarding;
- AI-assisted explanation;
- saved attack-flow evidence.

**Suggested image 4 — Attack Assistant and saved evidence**

https://1200km.com/adversarygraph-docs/img/adversarygraph-v6/03-attack-assistant-evidence.png

*Caption: The scenario detail view keeps target context, telemetry, SIEM delivery, assistant boundaries, and saved evidence in one reviewable workflow.*

Real lab telemetry and AI-generated source-shaped telemetry are labeled separately. This lets teams use each evidence type appropriately for parser, field-mapping, correlation, and detection-rule exercises.

## Installation

Clone the release:

```bash
git clone --branch v6.0.0 https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
cp .env.example .env
```

Configure the required secrets and at least one approved AI provider or local OpenAI-compatible gateway. Then validate the rendered stack:

```bash
docker compose config --quiet
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
```

Start the controlled deployment:

```bash
docker compose up -d --build
```

Open the UI:

```text
http://localhost:3000
```

The public API and Swagger UI are exposed through the frontend proxy:

```text
http://localhost:3000/api/
http://localhost:3000/docs
```

Run the application self-test and release gate:

```bash
./scripts/selftest.sh
./scripts/release-readiness.sh --full
```

For production, continue with the readiness guide to configure TLS, authentication, secrets, backups, network isolation, monitoring, retention, and rollback.

## Built for Analyst-Guided Defensive Operations

AdversaryGraph keeps the analyst in the decision loop across the platform.

AI output arrives as reviewable evidence and candidates. Actor similarity supports structured hypothesis development. CVE relationships and network fingerprints enrich investigations. Generated detections move into testing and validation. SIEM delivery, parsing, and detection results are recorded separately so teams can identify the exact layer that needs improvement.

Malware and Attack Simulation workflows use explicit authorization and isolated lab profiles. Production deployments add the organization’s TLS, identity, secrets, backup, monitoring, retention, and data-handling controls.

This design gives CTI, SOC, DFIR, product-security, and detection-engineering teams a shared workspace without removing professional judgment from the workflow.

## Why This Release Matters

Version 6 completes the connective tissue across the platform:

- one release version across backend, frontend, Helm, and documentation;
- repeatable browser evidence;
- testable case studies;
- evidence provenance and analyst review;
- security and dependency checks;
- container validation;
- backup and rollback requirements;
- a clear definition of the deployment for which “production ready” applies.

The platform makes analyst and operator decisions easier to trace, review, reproduce, and defend.

For me, AdversaryGraph v6 brings the complete idea together: broad defensive capabilities, connected evidence, reproducible validation, clear operational guidance, and a release that teams can deploy and evaluate with confidence.

## Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v6.0.0
- Repository: https://github.com/anpa1200/adversarygraph
- Project hub: https://1200km.com/adversarygraph/
- Documentation: https://1200km.com/adversarygraph-docs/
- v6 release readiness: https://1200km.com/adversarygraph-docs/release-readiness-v6/
- v6 case studies: https://1200km.com/adversarygraph-docs/case-studies-v6/
- 22 validation workflows: https://1200km.com/adversarygraph-docs/case-studies-validation/
- Platform guide: https://1200km.com/adversarygraph-docs/platform-guide/
- Security and validation: https://1200km.com/adversarygraph-docs/observability-security-validation/

## Suggested Medium tags

Cybersecurity, Threat Intelligence, MITRE ATT&CK, Detection Engineering, Open Source

## Suggested preview text

AdversaryGraph v6.0 unifies threat intelligence, ATT&CK mapping, IOC/CVE investigation, Threat Radar, EMB3D, malware analysis, controlled Attack Simulation, SIEM validation, reproducible evidence, and production operations in one self-hosted platform.
