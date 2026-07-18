# User Guide

AdversaryGraph is built around a defensive CTI workflow:

```text
client context/report -> ATT&CK mapping candidates -> analyst review -> actor/campaign/sector relevance -> IOC enrichment -> detection gaps -> exports
```

Published walkthrough and visual reference:

- Current platform guide: [`adversarygraph-platform-guide.md`](adversarygraph-platform-guide.md)
- Research analysis guide: [`research-analysis-guide.md`](research-analysis-guide.md)
- Threat hunting guide: [`threat-hunting-guide.md`](threat-hunting-guide.md)
- v5 Attack Simulation screenshot manifest: [`assets/attack-simulation-v5/manifest.md`](assets/attack-simulation-v5/manifest.md)
- v6 current UI screenshot evidence: [`assets/adversarygraph-v6/manifest.md`](assets/adversarygraph-v6/manifest.md)
- v6 reproducible case studies: [`case-studies-v6.md`](case-studies-v6.md)
- Asset Surface screenshot addendum: [`assets/adversarygraph-v4.1-platform/manifest.md`](assets/adversarygraph-v4.1-platform/manifest.md)
- Platform screenshot manifest: [`assets/adversarygraph-v4-platform/manifest.md`](assets/adversarygraph-v4-platform/manifest.md)
- Malware screenshot manifest: [`assets/malware-analysis-v4/manifest.md`](assets/malware-analysis-v4/manifest.md)
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
| Telemetry Readiness Score | Per-technique score that compares required telemetry to available logs and highlights missing data components before detection engineering starts |

## Public Web Workspace

Use <https://1200km.com/threat-matrix/> for:

- ATT&CK exploration.
- Manual layer creation.
- Group overlays.
- Group and campaign comparison.
- Coverage-gap review.
- Browser-generated exports.

Do not upload private reports to public demos.

## Current Platform Modules

For a screenshot-backed walkthrough of every current module, see the
[AdversaryGraph Platform Guide](adversarygraph-platform-guide.md). It covers:

- Discover and workflow entry points
- Navigator and ATT&CK/ATLAS matrix review
- ATT&CK Group Library and actor/campaign pivots
- AI Analysis for report extraction
- Compare and Group vs Group similarity workflows
- Sector Intel and Sector Packs
- Asset Attack Surface Mapping for CMDB, scanner, and cloud inventory review
- Threat Hunting for scoped hypotheses, telemetry plans, findings, and reviewed outcomes
- RetroHunt Signals and Knowledge Library
- IOC Library, IOC Investigation, IOC Node Detail, and VirusTotal Lookup
- Feeds Management and Pipeline imports
- Operations and Investigation Report
- DFIR Examples and Troubleshooting
- Malware Analysis, String Analyzer, Unpacker, Decompilation/Debug, and Dynamic Analysis

## Docker Workspace

Use the Docker deployment for:

- Private report analysis.
- PostgreSQL-backed report history.
- Configured LLM extraction.
- Stored analyses and exports.
- Sector Intelligence and local actor relevance scoring.
- Asset inventory attack surface matrices with optional AI enrichment, saved
  local analysis history, and white Navigator layers for inventory-derived TTPs.
- IOC Intelligence with source-backed actor observables.
- PostgreSQL-backed Threat Hunting records with versioned query plans,
  evidence references, lifecycle controls, and Threat Radar handoff.
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

Every TTP detail panel includes a **Telemetry Coverage Matrix**:

| Technique | Required Data Components | Available Logs | Missing Telemetry | Detection Feasibility |
|---|---|---|---|---|
| T1059.001 PowerShell | Process Creation, Command Execution, Script Block Logging, Module Load | Sysmon Event ID 1, Windows Security 4688, EDR command-line telemetry | PowerShell Script Block Logging 4104 | Medium |

The **Telemetry Readiness Score** turns CTI into an engineering question: do we
have the logs needed to prove or disprove the behavior? If a technique is mapped
but required telemetry is missing, the panel shows the gap, for example
`Enable Script Block Logging`.

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
- Open any IOC detail page to inspect stored enrichment/source values, mapped
  TTPs, actor links, source reports, and raw metadata with clickable pivots.
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

Generated Sigma, YARA, YARA-L, KQL, SPL, EQL detections or summaries must be
reviewed before use. AI-assisted detection generation can use local, Claude,
OpenAI, Gemini, or MiniMax providers, but the output remains review material.

## Review Rules

- ATT&CK is not attribution evidence.
- Tool names do not automatically imply techniques.
- LLM output is untrusted until reviewed.
- Similarity scores should be explained in prose.
- Low-confidence mappings should remain in a backlog, not in final findings.
- IOC links should cite source and freshness; stale or weakly attributed IOCs
  should not be presented as current threat activity.
