# AdversaryGraph v2.1.1 Release Summary

AdversaryGraph v2.1.1 is the rename and deployment validation release.

The project is now published under the canonical **AdversaryGraph** name. The
release includes the complete v2.1 sector relevance and IOC intelligence feature
set, plus the repository/docs/site rename, legacy link compatibility, ecosystem
link updates, and a clean Docker deployment test from a fresh GitHub clone.

## What Changed Since v2.1.0

- Product name changed to **AdversaryGraph** across the application, docs,
  repository metadata, Docker defaults, release material, screenshots, and
  ecosystem links.
- Main repository moved to:
  `https://github.com/anpa1200/adversarygraph`
- Docs repository moved to:
  `https://github.com/anpa1200/adversarygraph-docs`
- Old public URLs on `1200km.com` now have compatibility redirects or retained
  legacy asset paths.
- Connected 1200km ecosystem projects now link to the AdversaryGraph hub, docs,
  article, and repository.
- Embedded ATLAS docs nginx fallback was fixed to prevent startup redirect-loop
  errors before the reference book build is written.

## Feature Set In This Release

### Sector Intelligence

- Actor relevance ranking by sector, region, technology/environment, and
  activity window.
- MISP Galaxy-backed evidence for sectors, origins, motivations, regions, and
  aliases.
- Searchable A-Z multi-select filters.
- Direct actions to actor profile, TTP information, IOC view, and Navigator
  overlay.

### IOC Intelligence

- ThreatFox sync.
- AlienVault OTX actor pulse enrichment.
- Custom/personal JSON, CSV, and TXT IOC feeds.
- Manual IOC import.
- Uploaded report IOC extraction.
- Actor IOC tabs with counts, source evidence, confidence, freshness, and CSV
  export.
- Centralized IOC sync controls in Reference Sync.

### Core v2 Workflows

- ATT&CK Enterprise, Mobile, ICS, and MITRE ATLAS sync.
- AI-assisted ATT&CK/ATLAS mapping with analyst review.
- Local LLM support via OpenAI-compatible endpoints.
- Analysis session history with delete support.
- Review status colors for suggested, accepted, rejected, and needs-evidence.
- Group, campaign, report, and Navigator TTP comparison.
- STIX 2.1 export for OpenCTI report/TTP workflows.
- PDF and JSON analyst report export.

## Verification

- Main app CI: passed.
- Frontend build: passed.
- Backend tests: `97 passed`.
- Docs build: passed.
- Website link check: passed.
- Fresh clone Docker deployment: passed.
- Runtime probes: API, frontend, and embedded ATLAS docs returned HTTP `200`.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.1.1
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.1.1.md`

