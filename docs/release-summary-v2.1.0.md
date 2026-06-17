# ThreatMapper v2.1.0 Release Summary

ThreatMapper v2.1.0 is the sector relevance and IOC intelligence release.

The release keeps ThreatMapper's core position as a self-hosted
CTI-to-detection workbench: reports are mapped to ATT&CK or ATLAS, analysts
review the evidence, and selected TTPs are compared against actor, campaign,
report, and Navigator views. v2.1 adds two daily-use CTI workflows on top of
that foundation.

## What Changed

### Sector Intelligence

Sector Intelligence ranks actors against a client context:

- sector or industry
- optional geography or region
- technology/environment filters such as cloud, Kubernetes, Microsoft 365, VPN,
  OT, and other local keywords
- activity window: quarter, year, or two years
- ATT&CK technique depth and campaign recency
- MISP Galaxy-backed evidence and references

The page explains why an actor was ranked and provides direct actions to open
actor information, TTPs, IOCs, and a Navigator overlay for relevant techniques.

### IOC Intelligence

IOC Intelligence adds a local observable layer without turning ThreatMapper into
a MISP replacement. IOCs are source-backed, actor-linked only when evidence
exists, and stored separately from ATT&CK data.

Supported inputs:

- abuse.ch ThreatFox sync
- AlienVault OTX actor pulse enrichment
- custom/personal JSON, CSV, and TXT feeds
- manual IOC import
- uploaded report IOC extraction for PDF, DOCX, TXT, JSON, and CSV style inputs

Actor profiles now include an IOCs tab with count, source, freshness,
confidence, evidence, and CSV export.

### Reference Sync

Reference Sync now covers both framework/reference data and IOC feeds:

- MITRE ATT&CK Enterprise, Mobile, ICS
- MITRE ATLAS
- ThreatFox
- OTX enrichment
- registered custom IOC feeds

## Operator Notes

Optional IOC providers need local `.env` configuration:

```env
THREATFOX_AUTH_KEY=
OTX_API_KEY=
```

Keep feed credentials out of commits and screenshots.

## Verification

Release preparation verification:

- Frontend production build: `npm run build`
- Backend pytest suite: `97 passed`

## Release Links

- GitHub release: https://github.com/anpa1200/threatmapper/releases/tag/v2.1.0
- Full guide: `docs/full-guide-v2.md`
- Release notes: `docs/release-notes/v2.1.0.md`
