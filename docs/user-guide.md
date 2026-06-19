# User Guide

AdversaryGraph is built around a defensive CTI workflow:

```text
client context/report -> ATT&CK mapping candidates -> analyst review -> actor/campaign/sector relevance -> IOC enrichment -> detection gaps -> exports
```

Published walkthrough and visual reference:

- 1200km mirror: <https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html>
- Medium article: <https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e>
- Local screenshot and infographic appendix: [`full-guide-v2.md#24-visual-appendix`](full-guide-v2.md#24-visual-appendix)

## Core Concepts

| Concept | Meaning |
|---|---|
| Technique | MITRE ATT&CK technique or sub-technique ID such as `T1566.001` |
| Evidence | The report text that supports a mapping |
| Confidence | Extraction confidence from the model plus analyst judgment |
| Similarity | Jaccard overlap between selected TTPs and a known group/campaign profile |
| Sector relevance | Local score explaining why an actor matters to selected sectors, regions, technologies, and activity windows |
| IOC | Source-backed observable linked to an actor only when the feed, import, or uploaded report provides actor evidence |
| Detection gap | A mapped behavior without sufficient local telemetry, detection, or validation |

## Public Web Workspace

Use <https://1200km.com/threat-matrix/> for:

- ATT&CK exploration.
- Manual layer creation.
- Group overlays.
- Group and campaign comparison.
- Coverage-gap review.
- Browser-generated exports.

Do not upload private reports to public demos.

## Docker Workspace

Use the Docker deployment for:

- Private report analysis.
- PostgreSQL-backed report history.
- Configured LLM extraction.
- Stored analyses and exports.
- Sector Intelligence and local actor relevance scoring.
- IOC Intelligence with source-backed actor observables.
- API-driven workflows.

## Analyst Workflow

### 1. Start With a Question

Examples:

- Which ATT&CK techniques appear in this public report?
- Which known groups share TTP overlap with this report?
- Which mapped behaviors lack detection coverage?
- Which telemetry sources are required before writing detections?
- Which actors matter for this client sector or environment?
- Which current or historical IOCs are linked to this actor by source evidence?

### 2. Ingest or Paste a Report

Supported inputs:

- Plain text.
- PDF.
- DOCX.

AdversaryGraph extracts candidate ATT&CK mappings. These are suggestions, not final intelligence.

### 3. Review Technique Evidence

For every mapping, check:

- Does the evidence show behavior, or only a tool name?
- Is the technique too broad?
- Is a sub-technique more accurate?
- Is the mapping based on actor attribution rather than observed behavior?
- Is the confidence justified?

### 4. Compare With Groups and Campaigns

Similarity is an investigation lead only. It is not attribution proof.

Use comparison to answer:

- Which known profiles share behaviors?
- Which techniques are common commodity behaviors?
- Which overlaps are distinctive enough to investigate?
- Which expected techniques are missing from the report?

### 5. Build Detection Gaps

For each accepted technique, record:

- Required telemetry.
- Current detection status.
- Candidate logic.
- Validation environment.
- Triage guidance.

### 6. Use Sector Intelligence

Use Sector Intelligence when the question starts with client context rather than
a single report.

1. Sync MISP Galaxy metadata from Feeds Management or the Sector Intel page.
2. Select one or more sectors.
3. Add optional regions and technologies/environments.
4. Choose quarter, year, or two-year activity window.
5. Review ranked actors and the evidence that caused each rank.
6. Jump to actor profile, TTP profile, IOC tab, or Navigator overlay.

The score is a relevance rank, not an attribution score and not IOC confidence.

### 7. Use IOC Intelligence

Use IOC Intelligence for actor-linked observables.

- ThreatFox and OTX provide public enrichment when configured.
- Custom feeds can import private JSON, CSV, or TXT indicators.
- Uploaded reports can be parsed locally for IOCs.
- Actor links require explicit actor IDs, actor names, aliases, or source
  evidence; many actors will legitimately show `0 IOCs`.

Treat IOCs as time-sensitive operational context, not as durable ATT&CK
behavior.

### 8. Export

Use exports for:

- ATT&CK Navigator review.
- Analyst handoff.
- Detection backlog planning.
- Report appendix material.
- Actor IOC CSV handoff when a source-backed IOC set is available.

Generated detections or summaries must be reviewed before use.

## Review Rules

- ATT&CK is not attribution evidence.
- Tool names do not automatically imply techniques.
- LLM output is untrusted until reviewed.
- Similarity scores should be explained in prose.
- Low-confidence mappings should remain in a backlog, not in final findings.
- IOC links should cite source and freshness; stale or weakly attributed IOCs
  should not be presented as current threat activity.
