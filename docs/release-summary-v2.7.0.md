# AdversaryGraph v2.7.0 Release Summary

AdversaryGraph v2.7.0 turns IOC lookup into a full investigation workflow.

The release adds a dedicated IOC Investigation page and API that collect
configured enrichment, expand relationships, identify TTP and actor leads,
summarize kill-chain context, and prepare structured data for AI-assisted
reporting.

## Operator Value

- Analysts can start from a single IP, domain, URL, hash, or suspicious
  artifact and immediately see what the platform can verify from local and
  external sources.
- Tier 1 and Tier 2 pivots make related infrastructure, malware names, tags,
  reports, DNS records, hostnames, service exposure, reputation data, and local
  IOC records visible in one workflow.
- Source status is explicit, so missing optional keys or provider failures are
  visible without hiding successful local enrichment.
- ATT&CK TTP leads can be sent directly to Navigator or added to My TTPs for
  coverage review and comparison.
- Actor/APT leads are treated as investigation hints from source evidence and
  local alias matches, not as attribution conclusions.
- The AI summary mode packages the collected source evidence, relationships,
  TTPs, actors, and score into a controlled report input.

## Key Sources

- Local IOC DB, including OpenCTI, MISP, STIX/TAXII, custom feeds, and reviewed
  report imports
- VirusTotal
- abuse.ch ThreatFox
- MalwareBazaar
- AlienVault OTX
- urlscan.io
- GreyNoise
- AbuseIPDB
- Shodan

## Verification

- Backend unit and integration tests passed.
- Frontend production build passed.
- Frontend lint passed.
- Live `/api/ioc/investigate` smoke test passed.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.7.0
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.7.0.md`

