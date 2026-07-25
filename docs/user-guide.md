# User Guide

AdversaryGraph is built around a defensive CTI workflow:

```text
client context/report -> hybrid intelligence retrieval -> cited answer or ATT&CK proposal -> analyst review -> actor/campaign/sector relevance -> IOC enrichment -> detection gaps -> exports
```

Published walkthrough and visual reference:

- Current platform guide: [`adversarygraph-platform-guide.md`](adversarygraph-platform-guide.md)
- Detailed module reference and casebook: [`module-reference.md`](module-reference.md)
- Authentication, named users, and SOC groups: [`authentication-and-users.md`](authentication-and-users.md)
- Research analysis guide: [`research-analysis-guide.md`](research-analysis-guide.md)
- Threat hunting guide: [`threat-hunting-guide.md`](threat-hunting-guide.md)
- Unified intelligence RAG and MCP guide: [`unified-rag-and-mcp.md`](unified-rag-and-mcp.md)
- MCP client setup: [`mcp-server.md`](mcp-server.md)
- v5 Attack Simulation screenshot manifest: [`assets/attack-simulation-v5/manifest.md`](assets/attack-simulation-v5/manifest.md)
- Tagged v6.0.0 UI screenshot evidence: [`assets/adversarygraph-v6/manifest.md`](assets/adversarygraph-v6/manifest.md)
- v6 reproducible case studies: [`case-studies-v6.md`](case-studies-v6.md)
- Asset Surface screenshot addendum: [`assets/adversarygraph-v4.1-platform/manifest.md`](assets/adversarygraph-v4.1-platform/manifest.md)
- Platform screenshot manifest: [`assets/adversarygraph-v4-platform/manifest.md`](assets/adversarygraph-v4-platform/manifest.md)
- Malware screenshot manifest: [`assets/malware-analysis-v4/manifest.md`](assets/malware-analysis-v4/manifest.md)
- 1200km mirror: <https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html>
- Medium article: <https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e>
- Local screenshot and infographic appendix: [`full-guide-v2.md#25-visual-appendix`](full-guide-v2.md#25-visual-appendix)

## Core Concepts

| Concept | Meaning |
|---|---|
| Technique | MITRE ATT&CK technique or sub-technique ID such as `T1566.001` |
| Evidence | The report text that supports a mapping |
| Confidence | Extraction confidence from the model plus analyst judgment |
| Similarity | Jaccard overlap between selected TTPs and a known group/campaign profile |
| Sector relevance | Local score explaining why an actor matters to selected sectors, regions, technologies, and activity windows |
| IOC | Source-backed observable linked to an actor only when the feed, import, or uploaded report provides actor evidence |
| Hybrid retrieval | Exact identifiers plus PostgreSQL full-text results, optional private vector similarity, and bounded relationship expansion combined into a ranked evidence set |
| Business profile | Private sector, region, technology, and crown-jewel context used to rerank a request; it is not evidence of targeting |
| Citation | A verified reference from an assistant answer to one indexed source excerpt and its canonical platform route |
| Navigator proposal | A persisted, expiring, checksum-bound advisory record containing locally valid ATT&CK IDs; confirmation records the analyst decision but does not save or mutate a Navigator layer |
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

For a platform walkthrough with clearly versioned screenshot packs, see the
[AdversaryGraph Platform Guide](adversarygraph-platform-guide.md). For
step-by-step inputs, outputs, permissions, limits, worked examples, and
module-specific case studies covering all 31 governed workspaces, use the
[Module Reference and Casebook](module-reference.md). The platform guide covers:

- Discover and workflow entry points
- Navigator and ATT&CK/ATLAS matrix review
- Navigator Intelligence RAG Assistant for corpus search, business-context
  ranking, grounded answers, and reviewed TTP proposals
- ATT&CK Group Library and actor/campaign pivots
- AI Analysis for report extraction
- Compare and Group vs Group similarity workflows
- Sector Intel and Sector Packs
- Asset Attack Surface Mapping for CMDB, scanner, and cloud inventory review
- Threat Hunting for scoped hypotheses, telemetry plans, findings, reviewed
  outcomes, and governed AI suggestions from stored reports or current hunt
  context
- RetroHunt Signals and Knowledge Library
- IOC Library, IOC Investigation, IOC Node Detail, and VirusTotal Lookup
- Feeds Management and Pipeline imports
- Operations and Investigation Report
- Administration for named users, SOC access groups, module/action grants,
  sessions, MFA resets, and authentication audit review
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
  evidence references, lifecycle controls, Threat Radar handoff, and governed
  AI-assistance provenance.
- A normalized RAG corpus across IOCs, CVEs, ATT&CK TTPs, actors, campaigns,
  reports, Knowledge, Threat Radar, Threat Hunting, Evidence Graph, and
  sanitized Asset Surface records.
- Exact and PostgreSQL full-text search without a model, plus optional pgvector
  retrieval through an approved private embedding endpoint.
- An optional local stdio MCP process for bounded search, grounded questions,
  indexed-entity reads, and unconfirmed Navigator proposals.
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
- Which IOCs and TTPs deserve review for this business's sector, region,
  technologies, and crown jewels?
- Which citations support a proposed ATT&CK Navigator layer?

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

### Optional: Create a Governed AI-Assisted Hunt

Threat Hunting AI works from a completed report or research session with source
text already stored in the self-hosted workspace, or from the current hunt
context. It does not fetch a new report, search a SIEM, or execute a generated
query.

1. Open the stored report and confirm that analysis is completed, source text
   is available, and it uses the Enterprise ATT&CK domain. Mobile, ICS, and
   ATLAS reports are not supported by the governed hunting assistant in the
   v6.5.0 implementation.
2. Confirm the report's authoritative handling marking. New and repaired legacy
   reports default conservatively to `TLP:AMBER+STRICT`. Only a user with
   `manage_intel` may deliberately change the stored marking after reviewing
   the source and organizational policy. An assistant request may raise that
   marking for the request, but it cannot lower it.
3. Use the default operator-configured local provider. Cloud providers are
   unavailable until an operator enables cloud use and the analyst explicitly
   acknowledges that bounded source content will leave the deployment.
   `TLP:AMBER+STRICT` and `TLP:RED` are always local-only.
4. Choose the assistant task: `hypothesis`, `plan`, `query`, `findings`, or
   `outcome`.
5. Review the generated fields, exact-matched source citations, and any
   dropped-citation or truncation warning. If the source or saved hunt changes
   while the provider is generating, the request is rejected as a stale-context
   conflict; retry against the current data.
6. Use **Apply safe fields** or **Apply safe suggestions** only after review.
   These actions copy permitted values into blank fields and merge permitted
   lists in the unsaved hunt form. For a proposed finding, **Open editable
   draft** opens the normal unsaved finding form with status `new`, verdict
   `inconclusive`, inherited hunt TLP, evidence type `analysis`, and no evidence
   reference, event time, observables, or query-version link. Add canonical
   evidence yourself.
7. Review the resulting form and use the ordinary Save action. Generation and
   safe application do not independently change the hunt, create a finding,
   save a query version, select a disposition, or advance lifecycle state.

AI output is a suggestion, not report evidence and not proof of activity in the
local environment. A report citation establishes source context only. A
finding still needs a case-safe event or evidence reference, and a query still
needs analyst-controlled execution in the approved telemetry platform.

The append-only AI-assistance record stores the optional hunt and stored-session
IDs, task/stage, `suggested` lifecycle, provider/model, prompt version, effective
TLP, sanitized source references and citation metadata, the recorded
remote-processing acknowledgment state, input/output checksums, bounded
server-validated citation excerpts of at most 300 characters each,
validated structured suggestion, warnings, and generation actor/time. It does
not store the full raw report, raw prompt, raw provider response, credentials,
or provider exception. Applying a suggestion does not mark this record
accepted; it copies safe content into an unsaved form. If the report or hunt
changes after generation, treat the earlier suggestion as stale and regenerate
or review it manually. For saved hunts, coverage warnings also disclose when
the bounded request omits older query versions or findings, or truncates query,
summary, note, or backend-assumption text.

### Optional: Search All Intelligence With RAG

Use **ATT&CK Navigator → AI RAG assistant** when the question spans
multiple modules instead of one report or IOC. An account needs `run_analysis`
to search or generate an answer, `manage_intel` to create, edit, or delete
business profiles, and `manage_feeds` to queue corpus reconciliation.

1. Confirm the assistant readiness card shows indexed documents. An empty
   corpus is not searched automatically; ask a feed manager to run **Build /
   refresh RAG index**.
2. Choose source filters. The friendly groups map to the normalized sources:
   IOCs; CVEs; ATT&CK/ATLAS techniques; groups, campaigns, and actor
   observations; reports, Knowledge, Threat Radar signals, hunts, and Evidence
   Graph nodes; and sanitized assets.
3. Optionally select a saved business profile. Include only context necessary
   for ranking. Profiles are private request context and are not copied into the
   global source documents or embeddings.
4. Start with **Search evidence**. Exact IDs and full text work when embeddings
   are disabled. If an approved private embedding model is active, the result
   also reports vector retrieval.
5. Open every material citation. Check the source route, excerpt, indexed time,
   TLP, legal-sensitive label, freshness, and relationship evidence.
6. Use **Ask grounded assistant** only when generation adds value. A remote
   provider requires a per-request acknowledgment; legal-sensitive,
   `TLP:AMBER+STRICT`, and `TLP:RED` context remains local-only.

Example IOC question:

```text
Find IOCs relevant to an Israel-based technology company using cloud identity,
Linux production systems, and public APIs. Rank them by stored evidence and
freshness. Explain the actor, campaign, CVE, and TTP relationship for every IOC.
Do not claim targeting or compromise.
```

The correct analyst outcome is a review queue, not a blocklist. A business
profile match followed by an actor-to-IOC relationship can make an indicator
worth investigating, but it does not prove that the indicator targets the
business or remains active.

Example Navigator question:

```text
Using only verified citations, propose the Enterprise ATT&CK techniques most
relevant to this business and return a Navigator proposal.
```

Review the proposal's ATT&CK version, domain, technique IDs, rationale,
citations, and expiration. **Preview** creates a temporary overlay without
changing the selection. **Confirm → Add** merges the server-verified IDs into
the current browser selection; **Confirm → Replace** replaces that selection.
Neither action saves a named layer. The assistant never creates a hunt,
executes a query, runs an attack, changes a feed, or initiates response.

MCP clients receive the same governed search and assistance boundary through a
local stdio process. MCP can return an unconfirmed proposal but cannot confirm
or apply it; repeat the reviewed proposal workflow in Navigator when a matrix
change is required.

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
- RAG ranking, vector similarity, and relationship expansion are discovery
  signals, not evidence confidence or attribution.
- Follow assistant citations to the complete source record; a verified citation
  proves provenance of the excerpt, not correctness of the model's conclusion.
- Navigator proposals expire and are not saved layers. Review the Add/Replace
  diff and save separately only after confirmation.
- Threat Hunting AI output is not evidence and cannot decide finding verdict,
  disposition, completion, escalation, containment, or detection publication.
- Review citation and truncation warnings before transferring an AI suggestion
  into a hunt field. Retry any stale-context conflict, and compare an older
  suggestion manually after a later source or hunt edit.
- Similarity scores should be explained in prose.
- Low-confidence mappings should remain in a backlog, not in final findings.
- IOC links should cite source and freshness; stale or weakly attributed IOCs
  should not be presented as current threat activity.
