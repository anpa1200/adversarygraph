# Changelog

## Unreleased

No unreleased changes.

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
