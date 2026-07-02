# Changelog

## v5.6.0 - 2026-07-02

- Promoted active release markers to v5.6.0 across backend, frontend, README,
  roadmap, security policy, Helm metadata, and release consistency checks.
- Expanded the Statistics module with tag analytics across IOC, CVE, TTP,
  actor/group, report, sector, and cross-dataset views.
- Added risk, confidence, region, sector, type, source, telemetry source, TLP,
  attack-vector, malware-family, freeform IOC tag, and relationship-confidence
  statistics widgets.
- Hardened statistics query execution so one failed widget query rolls back
  cleanly and does not suppress later widgets.
- Added regression coverage for the new Statistics tag widget catalog.

## v5.5.0 - 2026-06-30

- Promoted active release markers to v5.5.0 across backend, frontend, README,
  roadmap, security policy, Helm metadata, and release consistency checks.
- Added enterprise access controls with expanded RBAC roles, per-user
  permissions, password policy settings, MFA workflow support, and trusted
  proxy SSO metadata.
- Added session administration, revoke-all controls, user-session revocation,
  and authentication audit history in the backend and Admin Panel.
- Updated Docker Compose, production overlay, Helm values, and `.env.example`
  with the new auth policy controls.
- Updated authentication, admin, and production-readiness documentation for
  enterprise access operations.

## v5.4.0 - 2026-06-30

- Promoted active release markers to v5.4.0 across backend, frontend,
  README, roadmap, security policy, version matrix, and release metadata.
- Added authenticated Observability dashboard coverage for API uptime,
  request metrics, recent traces, top routes, redacted API log tails, and
  Prometheus-compatible metrics.
- Added backend observability API routes for summary, traces, logs, and
  metrics.
- Added `make security-scan` and `scripts/security-scan.sh` for local
  validation of lint, SAST, dependency audit, secret scan, Docker config, and
  container scan where tools are installed.
- Added Bandit backend SAST coverage to CI and fixed SAST findings around weak
  hashes and XML parsing.
- Added screenshot-backed observability, security scanning, and validation
  documentation, including Attack Simulation, CVE correlation, authentication,
  and malware-analysis validation examples.

## v5.3.0 - 2026-06-30

- Promoted active release markers to v5.3.0 across backend, frontend,
  README, roadmap, security policy, version matrix, and release metadata checks.
- Added a local authentication guide page at `/auth-guide` that remains
  reachable before sign-in when native auth is enabled.
- Linked the login page directly to the authentication setup guide.
- Updated authentication, quickstart, admin, security, production-readiness,
  and public-demo privacy documentation for native username/password auth,
  roles, bootstrap admin cleanup, session behavior, and optional
  identity-aware reverse-proxy deployments.
- Revalidated frontend production build, backend lint, and the full GitHub CI
  workflow during the release update.

## v5.2.0 - 2026-06-30

- Promoted active release markers to v5.2.0 across backend, frontend,
  README, roadmap, security policy, version matrix, and release metadata checks.
- Made backend tests reproducible in a clean local shell by seeding explicit
  test-safe `DB_PASS` and `LOG_DIR` defaults before app settings are imported.
- Added a frontend npm override for Monaco's transitive DOMPurify dependency,
  clearing the frontend audit finding while preserving the decompilation/debug
  editor integration.
- Revalidated backend lint, backend tests with coverage, frontend dependency
  audit, and frontend production build during the release QA pass.

## v5.1.0 - 2026-06-30

- Promoted the active release marker to v5.1.0 across backend, frontend,
  README, roadmap, security policy, and release metadata checks.
- Added the Attack Simulation telemetry fidelity policy: scenarios and
  AI-assisted simulations must use source-correct telemetry and
  vendor/source-shaped event structures, and unsupported TTPs must be reported
  as telemetry gaps instead of generic fake logs.
- Added raw STIX preservation tables for every ingested STIX object and
  relationship while keeping the existing normalized ATT&CK query tables.
- Added CVE Library with NVD CVE API 2.0 and CISA KEV source sync,
  normalized CVE/CVSS score/CWE/CPE storage, strict evidence-backed
  CVE-to-technique/IOC/actor correlation tables, API routes, and a frontend
  CVE review page.
- Documented the Attack Simulation telemetry architecture rule for detection
  engineering and SIEM validation review, plus the ATT&CK/STIX and CVE Library
  data models.

## v4.1.0 - 2026-06-27

- Added Asset Attack Surface Mapping for uploaded or pasted CSV/JSON/TXT asset
  inventories, deterministic exposure/risk scoring, ATT&CK candidate links,
  priority actions, validation gaps, and optional AI-enriched summaries.
- Added saved backend cases for each Asset Surface analysis, with reload and
  delete actions for inventory reviews.
- Added white ATT&CK comparison layers for asset-inventory-derived TTPs so
  inventory findings are visually distinct from manually selected techniques.
- Updated Discover with first-screen launchers for Asset Surface, Malware
  Analysis, String Analyzer, Decompilation and Debug, Malware Unpacker, and
  Dynamic Analysis.
- Fixed sidebar scrolling for long module lists and updated the UI footer,
  backend version, frontend package version, and release documentation to
  v4.1.0.
- Added v4.1 screenshot evidence for Discover, Asset Surface analysis, saved
  Asset Surface history, and the white asset-surface Navigator layer.

## Unreleased

## v3.1.0 - 2026-06-21

- Published the From Log to Report workflow as the v3.1 documentation and
  use-case refresh.
- Added the full Medium article media set, including animated GIF workflows,
  to the official guide, use-case drafts, Docusaurus docs, and 1200km site.
- Reworked use case 21 from the older ransomware triage placeholder into the
  end-to-end investigation workflow: create investigation, analyze firewall and
  EDR logs separately, enrich IOCs, review relationship graph pivots, compare
  TTPs, summarize with AI, and generate the report.
- Updated public documentation entry points for AI Analysis, Capabilities,
  Full Flow, and Use Cases.

## v3.0.0 - 2026-06-20

- Promoted AdversaryGraph to v3.0.0 with the investigation workflow as the
  main platform focus.
- Expanded IOC Investigation with Tier 1, Tier 2, and Tier 3 relationship
  expansion for IPs, domains, URLs, hashes, and suspicious artifacts.
- Added saved IOC investigations with history, reload, and delete actions.
- Added an analyst-focused relationship graph with actionable-node filtering,
  node detail pages, connected-node focus, clickable pivots, and observable
  reinvestigation from any graph node.
- Added evidence ranking, next-best pivot ranking, timeline extraction, and
  source-conflict summaries to make IOC investigations easier to defend.
- Added urlscan activity analysis for suspicious URL/page behavior and TTP
  leads.
- Added AI log/PCAP analysis workflows for extracting IOCs, suspicious
  behavior, functions, PowerShell indicators, TTP leads, and report-ready
  summaries from telemetry.
- Added richer AI report formatting and safer overlap/explanation language for
  analyst handoff.
- Added the v3.0 release notes, release summary, and Medium-style publication
  draft.

## v2.7.0 - 2026-06-20

- Added IOC Investigation as a dedicated Tier 1 / Tier 2 pivot workflow for
  IPs, domains, URLs, hashes, and other suspicious artifacts.
- Added `/api/ioc/investigate` to combine local IOC DB evidence, configured
  enrichment providers, relationship expansion, ATT&CK TTP leads, actor leads,
  kill-chain/tactic context, and AI-ready report input.
- Added enrichment pivots for VirusTotal, ThreatFox, MalwareBazaar, OTX,
  urlscan.io, GreyNoise, AbuseIPDB, Shodan, and local IOC/OpenCTI/MISP-loaded
  records.
- Added the IOC Investigation page with actions to show discovered TTPs on the
  ATT&CK matrix, add them to My TTPs, search IOC Library, and open VirusTotal
  Lookup.
- Added optional AI summarization for IOC investigations through the configured
  LLM providers.
- Updated Discover, quickstart, admin docs, and environment examples for the
  new investigation workflow and optional enrichment keys.

## v2.6.0 - 2026-06-19

- Added AI log/PCAP analysis for pasted telemetry or uploaded files, with IOC
  extraction, suspicious activity triage, ATT&CK mapping, actor-overlap hints,
  and report output.
- Added Navigator layer save/import/compare workflows for reviewing overlapping
  ATT&CK layers with distinct layer colors and overlap tags.
- Added AI Analysis actions to inject extracted TTPs into Navigator or compare
  them as a separate layer.
- Expanded the Discover page with direct workflow actions for self-test, report
  analysis, IOC investigation, actor review, feed management, and matrix work.
- Updated the 30-use-case documentation set to v2.6.0, removed draft markers,
  and embedded the animated GIF walkthroughs from the published Medium use-case
  article.

## v2.5.9 - 2026-06-19

- Added the public Yara-Rules malware repository as a default YARA feed source.
- Added YARA-L detection skeleton generation and validation support.
- Added optional AI-assisted detection rule generation for Sigma, YARA, YARA-L,
  KQL, SPL, and EQL outputs.
- Added provider selection, model override, telemetry input, and analyst context
  fields for AI rule generation in Intelligence Pipeline.
- Updated operator documentation for detection generation workflows.

## v2.5.8 - 2026-06-19

- Added per-IOC enrichment detail pages with source metadata, raw enrichment
  values, mapped TTPs, actor links, source metadata, and raw JSON.
- Made IOC values clickable from the IOC Library and actor/group IOC tabs.
- Added clickable pivots into Navigator, ATT&CK Group Library, source reports,
  and IOC Library search.
- Updated operator documentation for the IOC detail workflow.

## v2.5.7 - 2026-06-19

- Added MiniMax as a first-class external LLM provider through its
  OpenAI-compatible Chat Completions API.
- Added `MINIMAX_API_KEY`, `MINIMAX_MODEL`, and `MINIMAX_BASE_URL` settings.
- Wired MiniMax into AI Analysis, Navigator AI chat, IOC AI-enrichment provider
  selection, backend provider validation, self-test API-key reporting, Docker
  Compose API/worker environment forwarding, and operator documentation.
- Added focused provider factory test coverage for MiniMax registration.

## v2.5.4 - 2026-06-19

- Normalized legacy/provider hash IOC labels into `sha256`, `sha1`, and `md5`.
- Added duplicate IOC consolidation with actor-link and metadata preservation.
- Added evidence-priority IOC-to-TTP mapping: strict source/report evidence,
  enrichment-platform metadata, then optional AI fallback.
- Added `/api/ioc/enrich/ttps` for local IOC DB reprocessing.
- Added opt-in AI fallback controls to IOC Library and Feeds Management.
- Updated IOC sync APIs with `ai_enrich` and `ai_provider` options.
- Added focused tests and updated operator documentation.

## v2.5.0 - 2026-06-18

- Added a full IOC Library page with search, type/source filtering, group/actor
  filtering, sorting, enrichment actions, STIX export/import, TAXII pull, MISP
  JSON export connection, and custom feed registration.
- Added searchable multi-select ATT&CK group filtering for IOC Library records
  and STIX exports.
- Added VirusTotal IOC enrichment with structured verdicts, detection context,
  sandbox/rule details, extracted ATT&CK TTP evidence, actor matches, and
  Navigator/My TTP actions.
- Added YARA/Sigma rule-feed synchronization and sandbox behavior feed
  enrichment for malware behavior and detection context.
- Added IOC-to-TTP mapping from imported reports, source metadata, VirusTotal,
  OTX, Malpedia, and custom feeds.
- Added STIX 2.1 and TAXII workflows for IOC exchange with CTI platforms.
- Fixed dynamic reference DB manual sync so FastAPI no longer calls
  `asyncio.run()` from an active event loop.
- Improved IOC Library group dropdown behavior and visibility.
- Changed project licensing from MIT to the AdversaryGraph Personal Use License:
  personal/private use is free; business, commercial, organizational,
  client-delivery, production, or government use requires prior written
  approval from Andrey Pautov.

## v2.4.0 - 2026-06-18

- Added daily dynamic reference database synchronization for MITRE ATT&CK,
  MISP Galaxy, and configured IOC intelligence sources.
- Added an external persistent Postgres data directory controlled by
  `ADVERSARYGRAPH_DB_DIR`, so private reports, custom IOCs, custom feeds, and
  analyst data survive Docker image rebuilds.
- Added `POST /api/sync/dynamic-db` and a Reference Sync UI action for manually
  refreshing the dynamic reference database.
- Added a migration helper for moving existing Docker named-volume Postgres data
  into the external deployment directory.
- Extended deployment self-test output with database host/name and external data
  directory details.
- Fixed ATT&CK Group Library IOC count mismatch by using the same active
  180-day IOC definition in the group list and actor IOC tab.
- Updated docs for the dynamic DB model, external data directory, release
  workflow, and IOC count semantics.

## v2.2.0 - 2026-06-18

- Added an internal Docker troubleshooting page at `/troubleshooting` with
  deployment checks, self-test commands, log commands, ATT&CK data probes, and
  recovery order.
- Added contextual troubleshooting links to API and startup self-test error
  popups.
- Added a global API error popup with clear HTTP status, request path, and
  message context.
- Added a `Recheck` action on API error popups that reruns the AdversaryGraph
  self-test and turns the popup green with `All correct.` when the deployment
  is healthy.
- Added `/api/system/selftest` and a Docker `selftest` service for validating
  database connectivity, ATT&CK/ATLAS ingestion, and Redis connectivity after
  `docker compose up`.
- Improved startup behavior by retrying matrix data queries and refreshing
  matrix/discover/sync data after self-test passes.
- Documented the v2.2 operational troubleshooting workflow in release notes,
  release summary, quickstart, and full guide examples.

## v2.1.1 - 2026-06-18

- Published the project under the canonical AdversaryGraph name after the
  product rename.
- Renamed repository, docs, Docker defaults, generated assets, docs, release
  material, and ecosystem links to AdversaryGraph.
- Preserved old public site URLs through compatibility redirects and retained
  legacy asset paths where external links may exist.
- Updated connected 1200km ecosystem repositories to point to the new
  AdversaryGraph project hub, docs, article, and repository.
- Fixed the embedded ATLAS docs nginx fallback to avoid pre-build redirect-loop
  errors during fresh Docker startup.
- Verified a clean clone deployment with `docker compose up -d --build` and
  HTTP 200 probes for API, frontend, and embedded ATLAS docs.

## v2.1.0 - 2026-06-17

- Added Sector Intelligence MVP for client-facing actor relevance scoring.
- Added local intel source tables, MISP Galaxy threat-actor sync, sector/region
  observations, and actor relevance scoring from sector evidence, geography,
  ATT&CK campaign recency, and TTP depth.
- Added `/api/sector/*` endpoints and a Sector Intel UI page for syncing actor
  metadata and ranking actors by client sector, region, environment keywords,
  and activity window.
- Added IOC Intelligence MVP with local IOC source/indicator/actor-link tables,
  ThreatFox sync support, manual IOC import, actor IOC tabs, freshness filtering,
  confidence/source evidence, and CSV export.
- Added custom/personal IOC feed registration and sync for JSON, CSV, and TXT
  feeds with actor-aware IOC normalization.
- Added centralized Reference Sync action for all IOC sources, including
  ThreatFox and custom IOC feeds.
- Added AlienVault OTX actor pulse sync to enrich IOC-to-actor links from pulse
  adversary fields, actor aliases, pulse tags, and pulse indicators.
- Added report-upload IOC extraction for private PDF/DOCX/TXT analysis inputs.
- Added actor IOC count display, actor IOC tab actions, and Sector Intelligence
  actor IOC shortcuts.
- Improved Sector Intelligence filters with multi-select A-Z searchable
  dropdowns for sectors, regions, and technologies/environments.

## v2.0.0 - 2026-06-16

- Added local LLM support through OpenAI-compatible endpoints such as Ollama,
  LM Studio, LocalAI, and vLLM.
- Added STIX 2.1 export for OpenCTI workflows from completed analysis sessions.
- Added DFIR Examples with public report metadata, TTP/actor indexing, and a
  local PDF workflow for private AI analysis.
- Added Reference Sync UI/API for MITRE ATT&CK Enterprise, Mobile, ICS, and
  MITRE ATLAS synchronization status and manual sync.
- Added MITRE ATLAS matrix ingestion as a first-class sync domain with ATLAS
  tactics, techniques, sub-techniques, and domain-aware AI extraction prompts.
- Enriched ATT&CK Group Library with actor metadata, aliases, external
  references, technique evidence, tactic coverage, platform coverage, and
  source context.
- Added cached ATT&CK bundle fallback behavior to reduce GitHub API-rate and
  startup fragility.
- Added demo video, GIF, and poster for the report-to-analysis-to-comparison
  workflow.
- Added full v2 user/operator guide and OpenCTI export documentation.
- Expanded backend coverage to 76 passing tests and kept frontend production
  build green.

## v0.9.0 - 2026-06-15

- Added maturity documentation package: security policy, contribution guide, maintainers file, roadmap, validation plan, demo dataset, sample outputs, and issue templates.
- Added CI workflow for backend tests and frontend build.
- Documented product limitations, deployment boundaries, and evidence requirements for analyst review.
- Added production-readiness tracker for self-hosted deployment boundaries,
  implemented gates, and remaining blockers.
- Added analyst review-state support and evidence-binding notes to the roadmap
  and maturity documentation.
- Added release notes and a repeatable release checklist for reviewer-friendly
  tagged releases.

## v0.8.5

- Public intelligence and ecosystem release.
- Promoted AdversaryGraph Web as the browser-native workspace.
- Added correlated CTI/IR report and 1200km resource indexes.
- Added persistent evidence, source, confidence, mapping quality, notes, and coverage maturity fields.
- Added Anomaly Detection Atlas integration and ATT&CK technique cross-links.
