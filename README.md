# AdversaryGraph

![AdversaryGraph AI banner](docs/assets/adversarygraph-ai-banner.png)

**Self-hosted AI-assisted CTI-to-detection workbench for ATT&CK mapping, hypothesis-driven threat hunting, Threat Radar early warning, Evidence-to-Detection Graph reasoning, IOC enrichment, CVE Library correlation, malware-analysis triage, asset attack-surface review, Attack Simulation, and SIEM validation.**

[![CI](https://github.com/anpa1200/adversarygraph/actions/workflows/ci.yml/badge.svg)](https://github.com/anpa1200/adversarygraph/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v6.0.0-blue)](VERSION)
[![Security policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)
[![Roadmap](https://img.shields.io/badge/roadmap-public-blue)](ROADMAP.md)
[![License](https://img.shields.io/badge/license-personal%20use%20only-orange)](LICENSE)

Current release: **v6.0.0**. This release packages AdversaryGraph for controlled
self-hosted production with a reproducible readiness gate, corrected release
history, current screenshot evidence, local case studies, clearer deployment
go/no-go criteria, and a complete v5-to-v6 reviewer handoff. See the
[v6 release notes](docs/release-notes/v6.0.0.md),
[release readiness guide](docs/release-readiness-v6.md),
[case studies](docs/case-studies-v6.md), and
[screenshot manifest](docs/assets/adversarygraph-v6/manifest.md).

The current development checkout also contains the post-v6.0.0 work listed under
[Unreleased](CHANGELOG.md): the governed Threat Hunting workspace and AI
assistant, unified intelligence RAG, the local MCP integration, finer-grained
authorization, safer file and network boundaries, frontend resilience work,
and deployment/validation hardening. These changes are not part of the existing
`v6.0.0` tag until a new immutable release is cut.

## What It Does

AdversaryGraph helps analysts turn threat reports, IOC evidence, CVE vulnerability context, malware-analysis leads, asset inventories, and validation telemetry into reviewed ATT&CK/ATLAS mappings and detection engineering work items.

Core capabilities:

- AI-assisted report ingestion from text, PDF, DOCX, and TXT.
- Threat Radar for product-security CTI early warning: CVE/KEV/PoC/zero-day/supplier/package/hardware signals, product exposure scoring, case graphs, and PSIRT/Hunt/IR/Detection workflows.
- Threat Hunting for falsifiable hypotheses, bounded scope, ATT&CK mapping, telemetry requirements, versioned query plans, preserved findings, reviewed dispositions, auditable Threat Radar handoff, and governed AI suggestions from stored reports or hunt context. Report-to-hunt AI on current `main` supports Enterprise ATT&CK. The assistant can draft hypotheses, plans, queries, finding summaries, and outcome summaries, but it does not create evidence, execute a query, or make lifecycle and disposition decisions.
- Unified hybrid RAG over normalized IOC, CVE, ATT&CK/TTP, actor, actor sector/region/technology observations, campaign, report, knowledge, Threat Radar signal, Threat Hunting, Evidence Graph, and sanitized asset records, with bounded one-hop expansion across allowlisted stored relationships, saved business profiles used as private request context, PostgreSQL full-text plus pgvector search, citation-bound AI answers, and expiring analyst-confirmed Navigator proposals. Relationship relevance remains an evidence-review lead, not proof of targeting or compromise.
- A bounded MCP server for authenticated read-only/advisory intelligence search, entity retrieval, grounded answers, and Navigator proposals without automatic platform mutation.
- ATT&CK/ATLAS Navigator with actor, campaign, sector, and comparison overlays.
- IOC Library, IOC Investigation pivots, VirusTotal lookup, and feed management.
- CVE Library with NVD and CISA KEV sync, CVSS score/CWE/CPE storage, and strict APT-TTP-IOC-CVE correlations.
- Asset Attack Surface Mapping from CMDB, scanner, cloud, CSV, JSON, and hostname/IP inventories, with strict `namespace:value` labels for products, suppliers, dependencies, technologies, sectors, CVEs, TTPs, risk, and exposure.
- Malware Analysis workflow backed by the isolated MalwareGraph service for static triage, strings, unpacking/deobfuscation support, debugger-style review, and AI summaries.
- Attack Simulation for TTP-first lab scenarios, real attacked-server telemetry, SIEM forwarding, coherent AI-assisted kill-chain drills, and attack-chain graph review.
- Evidence-to-Detection Graph for preserving the full reasoning chain from evidence to claims, behavior, ATT&CK, required telemetry, detection candidates, rules, validation scenarios, SIEM results, and analyst decisions.
- Observability dashboard with API request metrics, recent traces, redacted log tails, Prometheus-compatible metrics, and health/self-test views.
- Operations, Pipeline, detection backlog, investigation reports, exports, and API workflows.

## What It Is Not

AdversaryGraph is not a managed SaaS, not a multi-tenant security platform, and not a replacement for analyst validation. LLM mappings, RAG rankings and relationship expansion, AI answers, Navigator proposals, Threat Hunting AI suggestions, generated detections, actor similarity, malware-analysis findings, and synthetic SIEM telemetry are analyst-assistance outputs, not evidence or autonomous decisions. A retrieved relationship is not proof that an actor targets the selected business, an IOC is active, a CVE was exploited, or a compromise occurred.

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

Edit `.env` and set strong local secrets. AI features are optional for the base
platform. To use them, configure an approved local OpenAI-compatible endpoint
or an operator-approved cloud provider as described in the relevant guide.

```bash
docker compose up -d --build
./scripts/selftest.sh
```

Open:

- Frontend: `http://localhost:3000`
- API liveness: `http://localhost:3000/api/health`
- API readiness: `http://localhost:3000/api/ready`
- API docs: `http://localhost:3000/docs`

The default Compose deployment binds the public UI and reference docs to localhost and keeps the API, Redis, malware-analysis service, and lab fixtures on the internal Compose network.
Local configuration is stored in `.env`; the default persistent database is `${ADVERSARYGRAPH_DB_DIR:-./data/postgres}`. See [local storage and permissions](docs/local-storage-and-permissions.md) before deleting data directories or Docker volumes.

### Enable unified intelligence search

The unified RAG subsystem is enabled by default, but semantic embeddings are
off until an operator supplies a reviewed private embedding service. Exact-ID
and PostgreSQL full-text retrieval remain available without a model.

For an Ollama endpoint on the Docker host:

```bash
ollama pull nomic-embed-text
```

Back up PostgreSQL and review the [upgrade guide](docs/upgrade-guide.md) before
changing an existing deployment. Set these values in `.env`, then rebuild the
pgvector PostgreSQL image and the services that read or present RAG state:

```dotenv
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_API_KEY=local
RAG_ENABLED=true
RAG_EMBEDDING_ENABLED=true
RAG_EMBEDDING_PROVIDER=local
RAG_EMBEDDING_MODEL=nomic-embed-text
RAG_EMBEDDING_DIMENSIONS=768
```

```bash
docker compose up -d --build postgres api worker beat frontend
```

Open **ATT&CK Navigator → AI RAG assistant** (dialog title: **Intelligence RAG
assistant**) and select **Build /
refresh RAG index**. An account needs `manage_feeds` to queue reconciliation;
search and assistance require `run_analysis`. Confirm `/api/rag/status` reports
a non-empty sanitized corpus before relying on assistant results. Changing the
embedding dimensions later requires a reviewed database migration and complete
reindex.

For example, create a profile with region **Israel**, sector **Technology**, and
the relevant technologies/crown jewels, then ask “Find IOCs relevant to this
business.” Review every cited record and warning. A second request such as
“Propose the relevant TTPs for Navigator” returns a temporary preview; applying
the verified IDs requires explicit Add/Replace confirmation and still does not
save a named layer.

The MCP integration is a separate, optional stdio process. It exposes four
bounded read-only/advisory tools and cannot confirm a proposal, save a layer,
reindex data, or execute a response action. See the [MCP server guide](docs/mcp-server.md)
for dedicated-account and client configuration.

## Documentation

| Need | Link |
|---|---|
| Commercial trust package | [Commercial Trust](https://1200km.com/adversarygraph-docs/commercial-trust/) |
| Architecture diagrams | [Architecture Diagrams](https://1200km.com/adversarygraph-docs/architecture/) |
| Case studies and validation examples | [Case Studies And Validation Examples](https://1200km.com/adversarygraph-docs/case-studies-validation/) |
| Comparison pages | [Comparison Overview](https://1200km.com/adversarygraph-docs/comparisons/overview/) |
| Reviewer orientation | [docs/reviewer-guide.md](docs/reviewer-guide.md) |
| Version history | [docs/version-matrix.md](docs/version-matrix.md) |
| Complete v5 overview | [docs/v5-overview.md](docs/v5-overview.md) |
| v6 release readiness | [docs/release-readiness-v6.md](docs/release-readiness-v6.md) |
| v6 case studies | [docs/case-studies-v6.md](docs/case-studies-v6.md) |
| v6 screenshot evidence | [docs/assets/adversarygraph-v6/manifest.md](docs/assets/adversarygraph-v6/manifest.md) |
| ATT&CK/STIX data model | [docs/attack-data-model.md](docs/attack-data-model.md) |
| Threat Radar | [docs/threat-radar.md](docs/threat-radar.md) |
| Threat Hunting operational guide | [docs/threat-hunting-guide.md](docs/threat-hunting-guide.md) |
| Unified intelligence RAG and MCP | [docs/unified-rag-and-mcp.md](docs/unified-rag-and-mcp.md) |
| MCP server configuration | [docs/mcp-server.md](docs/mcp-server.md) |
| EMB3D embedded threat modeling | [docs/emb3d.md](docs/emb3d.md) |
| CVE Library | [docs/cve-cvss-intelligence.md](docs/cve-cvss-intelligence.md) |
| Evidence-to-Detection Graph | [docs/evidence-to-detection-graph.md](docs/evidence-to-detection-graph.md) |
| Security policy | [SECURITY.md](SECURITY.md) |
| Security threat model | [docs/security-threat-model.md](docs/security-threat-model.md) |
| Production readiness | [docs/production-readiness.md](docs/production-readiness.md) |
| Local storage and permissions | [docs/local-storage-and-permissions.md](docs/local-storage-and-permissions.md) |
| Hardened Docker Compose profile | [docker-compose.prod.yml](docker-compose.prod.yml) |
| Kubernetes Helm chart | [helm/adversarygraph/README.md](helm/adversarygraph/README.md) |
| Deployment sizing | [docs/deployment-sizing.md](docs/deployment-sizing.md) |
| Backup and restore | [docs/backup-restore.md](docs/backup-restore.md) |
| Upgrade guide | [docs/upgrade-guide.md](docs/upgrade-guide.md) |
| Validation and limitations | [docs/validation-and-limitations.md](docs/validation-and-limitations.md) |
| Public demo privacy | [docs/public-demo-privacy.md](docs/public-demo-privacy.md) |
| Platform guide | [docs/adversarygraph-platform-guide.md](docs/adversarygraph-platform-guide.md) |
| User guide | [docs/user-guide.md](docs/user-guide.md) |
| Research analysis guide | [docs/research-analysis-guide.md](docs/research-analysis-guide.md) |
| Admin guide | [docs/admin-guide.md](docs/admin-guide.md) |
| Authentication and user management | [docs/authentication-and-users.md](docs/authentication-and-users.md) |
| Observability and security validation | [docs/observability-security-validation.md](docs/observability-security-validation.md) |
| Attack Simulation | [docs/attack-simulation.md](docs/attack-simulation.md) |
| SIEM forwarding security | [docs/attack-simulation-siem-forwarding-security.md](docs/attack-simulation-siem-forwarding-security.md) |
| Asset Attack Surface Mapping | [docs/asset-attack-surface.md](docs/asset-attack-surface.md) |
| Taxonomy and Label Convention | [docs/taxonomy-and-label-convention.md](docs/taxonomy-and-label-convention.md) |
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
     -> PostgreSQL + pgvector for authoritative records, normalized RAG documents,
        full-text indexes, vectors, proposals, analyses, cases, and operations
     -> Redis/Celery for background sync, RAG reconciliation/retention,
        feed collection, and RetroHunt jobs
     -> LLM providers selected by the operator
     -> MalwareGraph service for isolated malware-analysis workflows
     -> Attack lab fixtures for authorized simulation telemetry

Local MCP client
  -> stdio-only AdversaryGraph MCP process
     -> fixed governed RAG API routes
```

The main platform stores structured CTI and workflow data. Malware samples are handled by the MalwareGraph boundary. Attack Simulation lab targets are separate fixture containers so telemetry comes from the target class being tested.

## Safety Boundaries

- Do not upload confidential data to public demos.
- Do not expose the default Compose stack directly to the internet.
- Use TLS, authentication, restricted networks, backups, monitoring, and secret rotation for controlled production deployments.
- Native username/password login, role-based access, user management, and trusted reverse-proxy auth are documented in [Authentication and User Management](docs/authentication-and-users.md).
- Treat LLM output and generated detections as untrusted until reviewed.
- Threat Hunting AI defaults to the operator-configured local provider. Cloud use
  is disabled by default and requires operator enablement plus explicit analyst
  acknowledgment; `TLP:AMBER+STRICT` and `TLP:RED` inputs remain local-only.
- RAG embeddings accept only the configured local provider, and its
  OpenAI-compatible endpoint must use a loopback, private/link-local IP, or
  recognized private service DNS host. Public endpoints cannot be relabeled as
  `local`.
- Connect RAG reconciliation workers directly to PostgreSQL or through
  PgBouncer in session-pooling mode. Transaction or statement pooling is not
  compatible with the worker's session advisory lock.
- Treat vectors, source excerpts, saved business profiles, assistant records,
  and MCP tool results as sensitive derived data under the source records'
  handling requirements. The default purge windows are 30 days for inactive
  corpus tombstones and 90 days for assistance records; a zero value disables
  that automatic purge for operator-controlled legal hold.
- Run MCP through stdio with a dedicated least-privilege analyst session. The
  current session token is not independently scoped, and the MCP process does
  not provide a remote HTTP transport or OAuth boundary.
- Use only approved lab targets for Attack Simulation.
- Keep malware runtime execution in disposable isolated profiles only.

## Validation

Local validation commands:

```bash
./scripts/release-readiness.sh --full
```

CI runs backend tests, backend lint, backend SAST, backend dependency audit,
frontend build and dependency audit, the Anomaly Detection Atlas documentation
build and dependency audit, Docker Compose and Helm validation, Docker image
builds, container scanning, secret scanning, and version consistency checks.
The automated gate does not prove that a deployment-specific private embedding
or chat endpoint is reachable or produces acceptable intelligence. Before a
production rollout, reconcile a representative corpus and perform a cited
search, a governed assistant query, a Navigator preview/confirmation check, and
an MCP stdio smoke test in the target environment.

## License

Personal-use license. See [LICENSE](LICENSE).
