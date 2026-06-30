# AdversaryGraph Platform Guide

> Current v5.0.0 platform documentation. AdversaryGraph is an analyst-assistance
> system: AI mappings, similarity scores, IOC enrichment, malware-analysis
> output, and generated detections require human validation before operational
> use.

## Table of Contents

1. [Visual Evidence](#visual-evidence)
2. [Core Workflow](#core-workflow)
3. [Modules and Abilities](#modules-and-abilities)
4. [Module Walkthrough](#module-walkthrough)
5. [Asset Attack Surface Mapping](#asset-attack-surface-mapping)
6. [Attack Simulation](#attack-simulation)
7. [Evidence-to-Detection Graph](#evidence-to-detection-graph)
8. [Malware Analysis Extension](#malware-analysis-extension)
9. [Operating Notes](#operating-notes)

## Visual Evidence

Platform screenshots are stored in
[`docs/assets/adversarygraph-v4-platform`](assets/adversarygraph-v4-platform/manifest.md).
That folder name is historical; the screenshots remain representative of the
current v5 platform surfaces unless a newer v5-specific screenshot set is listed
below. The Asset Surface and Discover addendum is stored in
[`docs/assets/adversarygraph-v4.1-platform`](assets/adversarygraph-v4.1-platform/manifest.md).
The malware-analysis screenshot set is stored in
[`docs/assets/malware-analysis-v4`](assets/malware-analysis-v4/manifest.md).
Those v4 malware screenshots remain representative for the current v5 Malware
Analysis workflow.
The v5 Attack Simulation screenshot set is stored in
[`docs/assets/attack-simulation-v5`](assets/attack-simulation-v5/manifest.md).

The screenshot packs include validation metadata. The platform set records
route load, expected page text, `1920x1200` dimensions, byte size, mean RGB, and
nonblank image checks in
[`validation.json`](assets/adversarygraph-v4-platform/validation.json).

The v4.1 addendum validates the representative Discover launcher layout, Asset
Surface analysis output, saved analysis history, and the white Navigator layer
created from asset-inventory TTP candidates.

The v5 Attack Simulation set validates the TTP-first simulation matrix, per-TTP
configuration page, SIEM forwarding controls, AI scenario library, generated
attack-chain graph, explain-attack panel, real-time log view, and saved SIEM
destination history.

## Core Workflow

AdversaryGraph is built around this defensive CTI workflow:

```text
report / IOC / malware sample / feed source
  -> extraction and enrichment
  -> ATT&CK / ATLAS mapping candidates
  -> analyst validation
  -> actor, campaign, sector, and IOC pivots
  -> comparison and detection-gap review
  -> evidence-to-detection reasoning graph
  -> investigation report, exports, and operational handoff
```

The platform keeps the source of each conclusion visible. A technique selected
from an uploaded report, an actor profile, an IOC feed, a malware sample, or an
AI assistant should remain traceable back to evidence.

## Modules and Abilities

| Module | Primary abilities |
|---|---|
| Discover | Start workspace, monitor platform state, open common CTI workflows, inspect selected TTP counts, actor context, and recent intelligence entry points. |
| Navigator | Explore Enterprise, Mobile, ICS ATT&CK and ATLAS matrices; select TTPs; review technique detail; overlay actors; track coverage; export Navigator JSON and backlog data. |
| ATT&CK Group Library | Search actor profiles, aliases, campaigns, techniques, reports, source-backed IOCs, and push actor TTPs into Navigator or comparisons. |
| AI Analysis | Paste text or upload PDF/DOCX/TXT; choose Claude, OpenAI, Gemini, MiniMax, or local OpenAI-compatible LLM; extract mapping candidates; review evidence and add accepted TTPs. |
| Compare | Compare current TTP layers, reports, groups, and campaigns; inspect overlap, matrix diff, tactic breakdown, and gap analysis. |
| Group vs Group | Select multiple actor profiles; compare shared and exclusive techniques; view overlap matrix, combined matrix, and technique table. |
| Sector Intel | Rank actors by sector, geography, technology, recency, campaign evidence, and MISP Galaxy context. |
| Asset Surface | Upload or paste asset inventories; normalize assets, exposure, ports, technologies, and owners; create saved attack-surface cases; build an AI-assisted matrix with risk levels, entry points, ATT&CK candidates, priority actions, validation gaps, and cross-asset findings. |
| Attack Simulation | Select ATT&CK TTPs, run safe lab simulations, view real-time attacked-server logs, forward telemetry to SIEM collectors, save recent destinations, generate AI-assisted multi-phase attack stories, review attack-chain graphs, and explain validation logic. |
| Evidence Graph | Preserve evidence-to-detection reasoning paths: Evidence, Claim, Behavior, ATT&CK Technique, Required Telemetry, Detection Candidate, Detection Rule, Validation Scenario, SIEM Result, and Analyst Decision. |
| RetroHunt | Search historical local intelligence, reports, indicators, techniques, and evidence for repeated patterns. |
| Knowledge Library | Browse stored reports, references, entities, and investigation source material. |
| IOC Library | Search observables, source attribution, freshness, enrichment fields, mapped TTPs, and actor links. |
| IOC Investigation | Pivot on IPs, domains, URLs, hashes, and observables; collect reputation, DNS, urlscan, VirusTotal, GreyNoise, Shodan, AbuseIPDB, Censys, and relationship data where configured. |
| VirusTotal Lookup | Run on-demand VT enrichment for hashes, IPs, domains, and URLs; add TTP and actor context into AdversaryGraph workflows. |
| Feeds Management | Sync ATT&CK/ATLAS, ThreatFox, Malpedia, OTX, OpenCTI, STIX/TAXII, MISP JSON, custom CSV/JSON/TXT, Sigma/YARA, and sandbox behavior feeds. |
| Investigation Report | Build analyst handoff reports from selected TTPs, evidence, investigation notes, actor context, and exports. |
| Operations | Manage investigation workspaces, tracked actors, detection lifecycle records, and team operational tasks. |
| Pipeline | Register and import external intelligence sources, STIX/TAXII collections, MISP exports, sandbox behavior, and detection-content feeds. |
| DFIR Examples | Use public DFIR examples and sample workflows to demonstrate report-to-ATT&CK analysis without private data. |
| Troubleshooting | Run and review deployment self-tests, API health checks, database/Redis checks, provider status, and recovery guidance. |
| Sector Packs | Package sector-specific threat context, actors, techniques, and reusable intelligence bundles. |
| IOC Node Detail | Inspect one observable as a graph node with enrichment, linked TTPs, relationship context, and actions. |
| Malware Analysis | Analyze Windows samples in the isolated MalwareGraph workflow: static triage, hashes, strings, unpacking, decompilation, debug workspaces, AI summaries, and gated dynamic analysis. |

## Evidence-to-Detection Graph

The Evidence Graph page connects AdversaryGraph modules into one operational
reasoning model:

```text
Evidence -> Claim -> Behavior -> ATT&CK Technique -> Required Telemetry
  -> Detection Candidate -> Detection Rule -> Validation Scenario
  -> SIEM Result -> Analyst Decision
```

Use it when a report, IOC, malware finding, asset exposure, attack simulation,
or SIEM result needs to become a reviewed detection-engineering outcome. The
graph separates confirmed evidence, analyst claims, inferred behavior, ATT&CK
mapping, detection hypothesis, validation result, and final analyst decision.

AI-generated nodes and edges are saved as drafts. Analysts can approve, reject,
request more evidence, create next-step nodes, review gaps, and export JSON,
Markdown, CSV, or an Evidence Pack. See
[`docs/evidence-to-detection-graph.md`](evidence-to-detection-graph.md).

## Module Walkthrough

### Discover

![Discover dashboard](assets/adversarygraph-v4-platform/01-discover-dashboard.png)

The Discover page is the command surface for starting analyst work. It links to
Navigator, AI Analysis, actor comparison, sector intelligence, IOC workflows,
malware analysis, operations, and troubleshooting.

### Navigator

![ATT&CK Navigator matrix](assets/adversarygraph-v4-platform/02-navigator-matrix.png)

Navigator is the matrix review surface. Analysts select techniques, inspect
evidence, expand sub-techniques, overlay actors or comparison layers, track
coverage, and export matrix-compatible layers.

### ATT&CK Group Library

![ATT&CK Group Library](assets/adversarygraph-v4-platform/03-apt-library.png)

The group library connects actor profiles to aliases, techniques, campaigns,
reports, source-backed IOCs, and Navigator actions. Actor links are investigation
leads, not attribution proof.

### AI Analysis

![AI Analysis](assets/adversarygraph-v4-platform/04-ai-analysis.png)

AI Analysis ingests report text or uploaded documents and extracts ATT&CK/ATLAS
mapping candidates. The page keeps provider choice, source text, extracted
evidence, accepted TTPs, and saved report sessions separate.

### Compare

![Compare reports and layers](assets/adversarygraph-v4-platform/05-compare-behavior.png)

Compare uses the current TTP layer or saved reports to rank overlap with groups
and campaigns. It supports group comparison, campaign comparison, report
comparison, tactic distribution, matrix diff, and detection-gap review.

### Group vs Group

![Group vs Group comparison](assets/adversarygraph-v4-platform/06-group-vs-group.png)

Group vs Group compares multiple actor profiles directly. It highlights shared
techniques, actor-exclusive techniques, tactic coverage, and combined matrix
patterns.

### Sector Intel

![Sector Intelligence](assets/adversarygraph-v4-platform/07-sector-intel.png)

Sector Intel ranks actor relevance for a client context. Inputs include sector,
region, technology/environment keywords, activity window, campaign recency, and
MISP Galaxy evidence.

### RetroHunt

![RetroHunt](assets/adversarygraph-v4-platform/08-retrohunt.png)

RetroHunt searches local historical intelligence for repeated indicators,
techniques, tool names, actor references, and evidence fragments.

### Knowledge Library

![Knowledge Library](assets/adversarygraph-v4-platform/09-knowledge-library.png)

The Knowledge Library stores and browses reports, references, entities, and
saved intelligence material used by investigations and exports.

### IOC Library

![IOC Library](assets/adversarygraph-v4-platform/10-ioc-library.png)

The IOC Library is the searchable observable store. It shows freshness, source
attribution, enrichment values, mapped TTPs, actor links, and pivot actions.

### IOC Investigation

![IOC Investigation](assets/adversarygraph-v4-platform/11-ioc-investigation.png)

IOC Investigation performs a pivot workflow for a single observable. It can
collect reputation, DNS, relationship graph data, external provider context, and
timeline evidence depending on configured keys.

### VirusTotal Lookup

![VirusTotal Lookup](assets/adversarygraph-v4-platform/12-virustotal-lookup.png)

VirusTotal Lookup provides on-demand enrichment for hashes, IPs, domains, and
URLs. Results can feed mapped TTPs and actor context back into Navigator and IOC
workflows.

### Feeds Management

![Feeds Management](assets/adversarygraph-v4-platform/13-feeds-management.png)

Feeds Management controls platform data synchronization: ATT&CK/ATLAS, IOC
sources, MISP/custom feeds, OpenCTI, STIX/TAXII, detection-content feeds, and
sandbox behavior imports.

### Investigation Report

![Investigation report](assets/adversarygraph-v4-platform/14-investigation-report.png)

The report workspace prepares analyst handoff material from selected techniques,
evidence, IOC pivots, actor context, detection gaps, and investigation notes.

### Operations

![Operations](assets/adversarygraph-v4-platform/15-operations.png)

Operations manages investigation workspaces, tracked actors, detection lifecycle
items, report intake, evidence records, and operational task context.

### Pipeline

![Pipeline imports](assets/adversarygraph-v4-platform/16-pipeline.png)

Pipeline connects external intelligence sources and detection-content sources to
the local platform. It supports source registration, import review, and mapping
imported behavior to matrix techniques.

### DFIR Examples

![DFIR Examples](assets/adversarygraph-v4-platform/17-dfir-examples.png)

DFIR Examples provides public sample workflows and report material for demos,
training, validation, and regression checking without private data.

### Troubleshooting

![Troubleshooting](assets/adversarygraph-v4-platform/18-troubleshooting.png)

Troubleshooting shows deployment health, self-test results, Docker/API checks,
provider configuration state, and recovery guidance.

### Sector Packs

![Sector packs](assets/adversarygraph-v4-platform/19-sector-packs.png)

Sector Packs package reusable client or industry context: relevant actors,
techniques, intelligence notes, and recommended review paths.

### IOC Node Detail

![IOC node detail](assets/adversarygraph-v4-platform/20-ioc-node-detail.png)

IOC Node Detail treats an observable as a graph entity and exposes enrichment,
linked TTPs, source evidence, relationship context, and actions.

## Asset Attack Surface Mapping

Asset Surface maps CMDB exports, scanner output, cloud asset lists, and plain
host/IP inventories into a defensive attack surface matrix. The workflow
normalizes owners, environments, IPs, domains, ports, technologies, exposure,
and criticality, then produces risk levels, likely entry points, ATT&CK
technique candidates, priority actions, assumptions, validation gaps, and
optional AI-enriched executive findings.
Each completed run creates a saved case so analysts can reopen the exact matrix,
compare inventory changes, export JSON evidence, and send the same TTP set back
to Navigator later.

The module is useful when the starting point is infrastructure rather than a
report, IOC, actor, or malware sample. It helps answer:

- Which assets appear internet-facing, internal, third-party, or unknown?
- Which assets combine high business criticality with exposed administration,
  web/API, database, identity, container, or remote-access surfaces?
- Which likely ATT&CK techniques should be reviewed in Navigator and detection
  planning?
- Which facts must be validated with scanner, cloud firewall, WAF, CMDB, and
  telemetry data before operational action?

See the dedicated [Asset Attack Surface Mapping](asset-attack-surface.md)
guide for accepted inventory fields and output semantics.

Representative screenshots:

| Workflow | Screenshot |
|---|---|
| Updated Discover launchers | ![Discover launchers](assets/adversarygraph-v4.1-platform/01-discover-launchers.png) |
| Asset Surface analysis result | ![Asset Surface analysis result](assets/adversarygraph-v4.1-platform/02-asset-surface-analysis.png) |
| Saved Asset Surface history | ![Saved Asset Surface history](assets/adversarygraph-v4.1-platform/03-asset-surface-history.png) |
| White asset-surface Navigator layer | ![White asset-surface Navigator layer](assets/adversarygraph-v4.1-platform/04-asset-surface-white-matrix.png) |

## Attack Simulation

Attack Simulation is the v5 detection-validation workspace. Analysts select an
ATT&CK technique first, open a dedicated simulation page, run approved lab
scenarios, inspect real-time target-side logs, and forward telemetry to a SIEM
collector. Web scenarios use the Docker `attack-lab-web` target, which receives
real HTTP requests and writes target-side NGINX access, security/WAF-style,
error, auth, and structured JSONL logs.

The AI Attack Assistant adds a second workflow for detection engineering drills.
It can generate source-shaped telemetry for selected TTPs, actor-oriented
stories, or Challenge Me scenarios. Complicated mode builds longer coherent
kill chains across web, WAF, DNS, proxy, firewall, Windows Security, Sysmon, and
EDR-style sources. The generated attack-chain graph shows phase order,
technique, event source, event format, event count, and detection purpose.

Use this module to answer:

- Which ATT&CK behaviors already have runnable validation scenarios?
- Does the lab target emit the telemetry needed by the detection rule?
- Can the SIEM parser ingest raw web, auth, endpoint, WAF, and source-shaped
  events correctly?
- Does correlation logic detect a coherent attack chain rather than one atomic
  indicator?
- Which assumptions and validation gaps must an analyst document before marking
  coverage as passed?

See the dedicated [Attack Simulation](attack-simulation.md) guide for the full
workflow, safety model, log locations, SIEM forwarding modes, AI assistant
behavior, and scenario catalog.

Representative screenshots:

| Workflow | Screenshot |
|---|---|
| TTP-first simulation matrix | ![Attack Simulation matrix](assets/attack-simulation-v5/01-attack-simulation-matrix.png) |
| Per-TTP configuration | ![Per-TTP configuration page](assets/attack-simulation-v5/02-ttp-configuration-page.png) |
| SIEM forwarding controls | ![SIEM forwarding configuration](assets/attack-simulation-v5/03-siem-forwarding-configuration.png) |
| AI scenario library | ![AI scenario library](assets/attack-simulation-v5/04-ai-scenario-library.png) |
| Attack-chain graph | ![AI generated attack chain graph](assets/attack-simulation-v5/05-ai-generated-attack-chain-graph.png) |
| Explain attack panel | ![Explain attack panel](assets/attack-simulation-v5/06-explain-attack-panel.png) |
| Real-time logs | ![Real-time attack logs](assets/attack-simulation-v5/07-real-time-attack-logs.png) |
| SIEM destination history | ![SIEM history and delivery](assets/attack-simulation-v5/08-siem-history-and-delivery.png) |

## Malware Analysis Extension

The malware workflow has its own detailed documentation:

- [Malware Analysis Guide](malware-analysis-guide.md)
- [Malware Analysis Module](malware-analysis-module.md)
- [Malware Analysis Architecture](malware-analysis-architecture.md)
- [v4 Malware Analysis release article draft](publication-drafts/adversarygraph-v4-malware-analysis.md)

Representative screenshots:

| Workflow | Screenshot |
|---|---|
| Malware Analysis dashboard | ![Malware Analysis dashboard](assets/malware-analysis-v4/01-malware-analysis-dashboard.png) |
| Hash-check feed results | ![Hash-check feed results](assets/malware-analysis-v4/02-hash-check-feed-results.png) |
| String Analyzer smart IOC/TTP leads | ![String Analyzer smart IOC/TTP leads](assets/malware-analysis-v4/06-string-analyzer-smart-iocs.png) |
| Unpacker packed sample | ![Unpacker packed sample](assets/malware-analysis-v4/08-unpacker-packed-sample.png) |
| Debugger CPU view | ![Debugger CPU view](assets/malware-analysis-v4/12-debugger-ollydbg-cpu-view.png) |
| Dynamic function workflow | ![Dynamic function workflow](assets/malware-analysis-v4/16-dynamic-function-workflow.png) |

## Operating Notes

- Public demos are for exploration only. Do not upload private reports, client
  data, or malware samples to shared public instances.
- Docker/self-hosted mode is the private workflow for configured LLM providers,
  local LLM gateways, private reports, local IOC feeds, and malware-analysis
  labs.
- ATT&CK mapping, actor overlap, IOC enrichment, generated detections, and
  malware-analysis output are evidence organization aids. They are not final
  attribution, detection, or verdict decisions.
- Dynamic malware analysis is disabled by default and must run only in an
  explicitly isolated disposable runtime profile.
