# Changelog

## Unreleased

No unreleased changes.

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
