# Changelog

## v2.0.0 - 2026-06-16

- Added local LLM support through OpenAI-compatible endpoints such as Ollama,
  LM Studio, LocalAI, and vLLM.
- Added STIX 2.1 export for OpenCTI workflows from completed analysis sessions.
- Added DFIR Examples with public report metadata, TTP/actor indexing, and a
  local PDF workflow for private AI analysis.
- Added Reference Sync UI/API for MITRE ATT&CK Enterprise, Mobile, and ICS
  synchronization status and manual sync.
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
- Promoted ThreatMapper Web as the browser-native workspace.
- Added correlated CTI/IR report and 1200km resource indexes.
- Added persistent evidence, source, confidence, mapping quality, notes, and coverage maturity fields.
- Added Anomaly Detection Atlas integration and ATT&CK technique cross-links.
