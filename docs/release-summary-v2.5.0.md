# AdversaryGraph v2.5.0 Release Summary

AdversaryGraph v2.5.0 is the IOC Library, enrichment, and connector hardening
release.

The release expands AdversaryGraph from actor/TTP mapping into a more practical
IOC and malware-context workspace. Analysts can search and filter observables,
connect external sources, enrich indicators, map evidence back to ATT&CK, and
export the resulting context for CTI handoff.

## What Changed Since v2.4.0

- Added the IOC Library page with global IOC search, type/source filters,
  group/actor filters, sorting, enrichment actions, and pagination.
- Added searchable multi-select ATT&CK group filtering for IOC records and STIX
  exports.
- Added VirusTotal IOC enrichment with clean structured output, ATT&CK TTP
  evidence, local actor matches, detection/sandbox context, and matrix actions.
- Added STIX 2.1 IOC export/import and TAXII collection pull support.
- Added MISP JSON export connection as a custom IOC source.
- Added custom JSON, CSV, and TXT IOC feed registration from the IOC Library.
- Added YARA/Sigma rule-feed synchronization for detection context.
- Added sandbox behavior feed synchronization for malware behavior enrichment.
- Added IOC-to-TTP mapping from imported reports and enrichment metadata.
- Fixed manual dynamic DB sync event-loop handling in the API route.
- Updated the license to the AdversaryGraph Personal Use License.

## Operator Value

- Search all known observables from ThreatFox, OTX, Malpedia, MISP exports,
  TAXII/STIX imports, custom feeds, and report uploads in one place.
- Filter IOC evidence by one or more ATT&CK groups before exporting STIX.
- Enrich a single IOC and immediately pivot to matched actors, TTPs, and the
  Navigator matrix.
- Keep private/local IOC sources separate from rebuildable public reference
  data.
- Use the tool in personal/private environments for free while keeping business
  usage approval-controlled.

## Verification

- Frontend production build passed.
- Backend focused integration tests passed inside the Docker API container.
- Dynamic DB sync endpoint returned HTTP 200 after the event-loop fix.
- IOC Library repeated actor query returned HTTP 200 with filtered records.
- Docker frontend/API rebuild completed successfully.

## Release Links

- GitHub release: https://github.com/anpa1200/adversarygraph/releases/tag/v2.5.0
- Repository: https://github.com/anpa1200/adversarygraph
- Documentation: https://1200km.com/adversarygraph-docs/
- Project hub: https://1200km.com/adversarygraph/
- Full guide: `docs/full-guide-v2.md`
- Detailed notes: `docs/release-notes/v2.5.0.md`
