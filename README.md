# AdversaryGraph

![AdversaryGraph AI banner](docs/assets/adversarygraph-ai-banner.png)

**Self-hosted AI-assisted CTI-to-detection workbench for ATT&CK mapping, Evidence-to-Detection Graph reasoning, IOC enrichment, CVE Library correlation, malware-analysis triage, asset attack-surface review, Attack Simulation, and SIEM validation.**

[![CI](https://github.com/anpa1200/adversarygraph/actions/workflows/ci.yml/badge.svg)](https://github.com/anpa1200/adversarygraph/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v5.5.0-blue)](VERSION)
[![Security policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)
[![Roadmap](https://img.shields.io/badge/roadmap-public-blue)](ROADMAP.md)
[![License](https://img.shields.io/badge/license-personal%20use%20only-orange)](LICENSE)

Current release: **v5.5.0**. This release adds enterprise access controls: expanded RBAC permissions, session administration, MFA workflow support, trusted proxy SSO metadata, audit history, and hardened authentication documentation. See the [version matrix](docs/version-matrix.md), [v5.5 release summary](docs/release-summary-v5.5.0.md), [v5.4 release summary](docs/release-summary-v5.4.0.md), and [published v5 article](https://medium.com/@1200km/adversarygraph-v5-0-from-cti-mapping-to-attack-simulation-and-siem-validation-21873b2a6c39).

## What It Does

AdversaryGraph helps analysts turn threat reports, IOC evidence, CVE vulnerability context, malware-analysis leads, asset inventories, and validation telemetry into reviewed ATT&CK/ATLAS mappings and detection engineering work items.

Core capabilities:

- AI-assisted report ingestion from text, PDF, DOCX, and TXT.
- ATT&CK/ATLAS Navigator with actor, campaign, sector, and comparison overlays.
- IOC Library, IOC Investigation pivots, VirusTotal lookup, and feed management.
- CVE Library with NVD and CISA KEV sync, CVSS score/CWE/CPE storage, and strict APT-TTP-IOC-CVE correlations.
- Asset Attack Surface Mapping from CMDB, scanner, cloud, CSV, JSON, and hostname/IP inventories.
- Malware Analysis workflow backed by the isolated MalwareGraph service for static triage, strings, unpacking/deobfuscation support, debugger-style review, and AI summaries.
- Attack Simulation for TTP-first lab scenarios, real attacked-server telemetry, SIEM forwarding, coherent AI-assisted kill-chain drills, and attack-chain graph review.
- Evidence-to-Detection Graph for preserving the full reasoning chain from evidence to claims, behavior, ATT&CK, required telemetry, detection candidates, rules, validation scenarios, SIEM results, and analyst decisions.
- Observability dashboard with API request metrics, recent traces, redacted log tails, Prometheus-compatible metrics, and health/self-test views.
- Operations, Pipeline, detection backlog, investigation reports, exports, and API workflows.

## What It Is Not

AdversaryGraph is not a managed SaaS, not a multi-tenant security platform, and not a replacement for analyst validation. LLM mappings, generated detections, actor similarity, malware-analysis findings, and synthetic SIEM telemetry are analyst-assistance outputs.

Attack Simulation has two different telemetry modes:

- **Real lab telemetry:** produced by approved Docker lab fixtures such as `attack-lab-web` and `attack-lab-endpoint`.
- **Synthetic AI telemetry:** source-shaped events generated for SIEM parser/rule exercises. This validates field handling and correlation logic, not real exploit behavior.

See [Validation and Limitations](docs/validation-and-limitations.md), [Attack Simulation](docs/attack-simulation.md), and [SIEM forwarding security](docs/attack-simulation-siem-forwarding-security.md).

## Evidence-to-Detection Graph

AdversaryGraph preserves the full reasoning chain from raw evidence to validated
detection outcome:

```text
Evidence -> Claim -> Behavior -> ATT&CK Technique -> Required Telemetry
  -> Detection Candidate -> Detection Rule -> Validation Scenario
  -> SIEM Result -> Analyst Decision
```

This helps analysts see what is proven, what is inferred, what telemetry is
required, which detections exist, what has been validated, and what still needs
review. AI-generated graph nodes and edges are drafts until analyst-reviewed.
See [docs/evidence-to-detection-graph.md](docs/evidence-to-detection-graph.md).

## Quick Start

```bash
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
cp .env.example .env
```

Edit `.env` and set strong local secrets. Add at least one LLM provider key, or configure a local OpenAI-compatible endpoint.

```bash
docker compose up -d --build
./scripts/selftest.sh
```

Open:

- Frontend: `http://localhost:3000`
- API health: `http://localhost:8000/api/health`
- API docs: `http://localhost:8000/docs`

The default Compose deployment binds the public UI and reference docs to localhost and keeps the API, Redis, malware-analysis service, and lab fixtures on the internal Compose network.

## Documentation

| Need | Link |
|---|---|
| Commercial trust package | [Commercial Trust](https://1200km.com/adversarygraph-docs/commercial-trust/) |
| Architecture diagrams | [Architecture Diagrams](https://1200km.com/adversarygraph-docs/architecture/) |
| Case studies and validation examples | [Case Studies And Validation Examples](https://1200km.com/adversarygraph-docs/case-studies-validation/) |
| Comparison pages | [Comparison Overview](https://1200km.com/adversarygraph-docs/comparisons/overview/) |
| Reviewer orientation | [docs/reviewer-guide.md](docs/reviewer-guide.md) |
| Version history | [docs/version-matrix.md](docs/version-matrix.md) |
| ATT&CK/STIX data model | [docs/attack-data-model.md](docs/attack-data-model.md) |
| CVE Library | [docs/cve-cvss-intelligence.md](docs/cve-cvss-intelligence.md) |
| Evidence-to-Detection Graph | [docs/evidence-to-detection-graph.md](docs/evidence-to-detection-graph.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Security threat model | [docs/security-threat-model.md](docs/security-threat-model.md) |
| Production readiness | [docs/production-readiness.md](docs/production-readiness.md) |
| Hardened Docker Compose profile | [docker-compose.prod.yml](docker-compose.prod.yml) |
| Kubernetes Helm chart | [helm/adversarygraph/README.md](helm/adversarygraph/README.md) |
| Deployment sizing | [docs/deployment-sizing.md](docs/deployment-sizing.md) |
| Backup and restore | [docs/backup-restore.md](docs/backup-restore.md) |
| Upgrade guide | [docs/upgrade-guide.md](docs/upgrade-guide.md) |
| Validation and limitations | [docs/validation-and-limitations.md](docs/validation-and-limitations.md) |
| Public demo privacy | [docs/public-demo-privacy.md](docs/public-demo-privacy.md) |
| Platform guide | [docs/adversarygraph-platform-guide.md](docs/adversarygraph-platform-guide.md) |
| User guide | [docs/user-guide.md](docs/user-guide.md) |
| Admin guide | [docs/admin-guide.md](docs/admin-guide.md) |
| Authentication and user management | [docs/authentication-and-users.md](docs/authentication-and-users.md) |
| Observability and security validation | [docs/observability-security-validation.md](docs/observability-security-validation.md) |
| Attack Simulation | [docs/attack-simulation.md](docs/attack-simulation.md) |
| SIEM forwarding security | [docs/attack-simulation-siem-forwarding-security.md](docs/attack-simulation-siem-forwarding-security.md) |
| Asset Attack Surface Mapping | [docs/asset-attack-surface.md](docs/asset-attack-surface.md) |
| Malware Analysis guide | [docs/malware-analysis-guide.md](docs/malware-analysis-guide.md) |
| Malware Analysis boundary | [docs/malware-analysis-boundary.md](docs/malware-analysis-boundary.md) |
| Demo dataset | [demo/README.md](demo/README.md) |
| Issue triage | [docs/issue-triage.md](docs/issue-triage.md) |

Official public pages:

- Project landing page: <https://1200km.com/adversarygraph/>
- Documentation: <https://1200km.com/adversarygraph-docs/>
- Live intelligence workspace: <https://1200km.com/threat-matrix/>
- Medium archive: <https://medium.com/@1200km>

## Architecture

```text
React frontend
  -> FastAPI API
     -> PostgreSQL for stored analyses, cases, feeds, CVEs, mappings, and operations
     -> Redis/Celery for background sync, feed collection, and RetroHunt jobs
     -> LLM providers selected by the operator
     -> MalwareGraph service for isolated malware-analysis workflows
     -> Attack lab fixtures for authorized simulation telemetry
```

The main platform stores structured CTI and workflow data. Malware samples are handled by the MalwareGraph boundary. Attack Simulation lab targets are separate fixture containers so telemetry comes from the target class being tested.

## Safety Boundaries

- Do not upload confidential data to public demos.
- Do not expose the default Compose stack directly to the internet.
- Use TLS, authentication, restricted networks, backups, monitoring, and secret rotation for controlled production deployments.
- Native username/password login, role-based access, user management, and trusted reverse-proxy auth are documented in [Authentication and User Management](docs/authentication-and-users.md).
- Treat LLM output and generated detections as untrusted until reviewed.
- Use only approved lab targets for Attack Simulation.
- Keep malware runtime execution in disposable isolated profiles only.

## Validation

Local validation commands:

```bash
./scripts/check-version-consistency.sh
docker compose config --quiet
docker compose -f docker-compose.yml -f docker-compose.dev.yml config --quiet
cd backend && PYTHONPATH=. DB_PASS=ci_test_password LOG_DIR=/tmp/adversarygraph-test-logs python -m pytest
cd frontend && npm ci && npm run build && npm audit --audit-level=high
make security-scan
```

CI runs backend tests, backend lint, backend SAST, backend dependency audit, frontend build, frontend dependency audit, Docker Compose validation, Docker image builds, container scanning, secret scanning, and version consistency checks.

## License

Personal-use license. See [LICENSE](LICENSE).
