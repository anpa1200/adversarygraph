# AdversaryGraph And CTI Publishing Kit

Use this file for consistent external publishing of AdversaryGraph and the
related 1200km CTI ecosystem. The core message is evidence-backed
CTI-to-detection and governed retrieval, not automated attribution or response.

## Release Accuracy

Unified RAG, the Navigator intelligence assistant, MCP, governed Threat Hunting,
the Query Library, saved-asset assessment, and SOC access groups are part of the
v6.5.0 source release. They are not part of the immutable `v6.0.0` tag. Attach
v6.5 to public artifact claims only after the v6.5 tag workflow publishes and
verifies the corresponding images, manifest, and release evidence.

## Canonical Links

- AdversaryGraph project hub: https://1200km.com/adversarygraph/
- AdversaryGraph live web workspace: https://1200km.com/threat-matrix/
- AdversaryGraph docs: https://1200km.com/adversarygraph-docs/
- AdversaryGraph GitHub: https://github.com/anpa1200/adversarygraph
- AdversaryGraph article: https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html
- CTI as a Code: https://1200km.com/CTI_as_a_Code/
- CTI Analyst Field Manual: https://1200km.com/cti-analyst-field-manual/
- Operation Desert Hydra: https://1200km.com/operation-desert-hydra/
- Israel Government Threat Actors CTI: https://1200km.com/israel-government-threat-actors-cti/
- 1200km CTI page: https://1200km.com/cti.html

## One-Line Pitch

AdversaryGraph is a self-hosted, AI-assisted CTI-to-detection workbench that
combines evidence-backed ATT&CK mapping, threat hunting, and governed retrieval
across IOCs, CVEs, TTPs, actors, reports, and operational intelligence.

## Short Description

AdversaryGraph helps analysts operationalize CTI. It extracts ATT&CK technique
candidates from reports, keeps supporting evidence visible, compares selected
TTPs against known groups and campaigns, builds threat-hunting and detection
work, and exports analyst-ready outputs. In the self-hosted Docker platform, a
normalized PostgreSQL/pgvector corpus supports exact, full-text, and optional
semantic retrieval across IOCs, CVEs, ATT&CK/ATLAS, actors, campaigns, reports,
knowledge, Threat Radar, Threat Hunting, Evidence Graph, and sanitized assets.
The Navigator assistant returns cited answers and expiring technique proposals
that require analyst confirmation. A local stdio MCP process exposes the same
bounded, advisory retrieval boundary to compatible clients. The public web
workspace remains a browser exploration surface and does not include private
Docker RAG/MCP capabilities.

## Safety And Accuracy Statement

AdversaryGraph does not perform definitive attribution. TTP overlap and group
similarity are investigation leads for analyst review, not proof of actor
identity. LLM-assisted extraction can produce false positives, false negatives,
or ambiguous technique mappings; analysts must validate every mapping against
the source evidence and ATT&CK definitions. RAG rankings and relationship links
are retrieval signals, not proof of targeting, IOC activity, CVE exploitation,
or compromise. The assistant and MCP integration do not execute queries,
confirm proposals, save layers, or perform response actions autonomously.

## Platform-Specific Copy

### Hacker News / Show HN

Title:

```text
Show HN: AdversaryGraph – self-hosted CTI retrieval, ATT&CK mapping, and hunting
```

Body:

```text
I built AdversaryGraph to reduce the manual gap between threat reports and
detection engineering.

The workflow is:
report/PDF/text -> ATT&CK candidates with evidence -> cross-source IOC/CVE/TTP
retrieval -> group/campaign comparison -> reviewed Navigator proposal -> hunt and
detection work -> analyst report.

There are two modes:
- public browser workspace for ATT&CK exploration and group comparison
- self-hosted Docker platform for AI-assisted extraction, private
  PostgreSQL/pgvector retrieval, cited Navigator assistance, APIs, and reports
- optional local stdio MCP tools for bounded read-only/advisory access

It is not an attribution or autonomous-response engine. TTP overlap, vector
similarity, and stored relationships are investigation leads, and every
AI-assisted output needs analyst validation.

Live workspace: https://1200km.com/threat-matrix/
Docs: https://1200km.com/adversarygraph-docs/
GitHub: https://github.com/anpa1200/adversarygraph
```

### Reddit r/threatintel

```text
I built AdversaryGraph as a CTI-to-detection workflow tool and would appreciate
feedback from CTI analysts.

The goal is not automated attribution. The self-hosted workflow preserves report
evidence, retrieves related IOC/CVE/TTP/actor records from a normalized corpus,
compares TTP overlap, and turns reviewed results into hunting and detection
work. The Navigator assistant cites the stored records behind its answer and
requires confirmation before applying a proposed technique set.

Public workspace: https://1200km.com/threat-matrix/
Docs: https://1200km.com/adversarygraph-docs/
GitHub: https://github.com/anpa1200/adversarygraph
```

### Reddit r/blueteamsec

```text
I released AdversaryGraph, a CTI-to-detection workbench focused on turning threat
reports into detection backlog material.

It maps report evidence to ATT&CK technique candidates, retrieves related IOCs,
CVEs, actors, campaigns, and operational records, surfaces detection gaps, and
produces reviewed Navigator views and analyst reports. The public web version is
browser-native; the Docker version adds private analysis storage, governed RAG,
and an optional stdio MCP facade.

The important constraint: it is not an attribution engine. The output is
analyst-review seed material for hunting and detection engineering.

Live: https://1200km.com/threat-matrix/
Repo: https://github.com/anpa1200/adversarygraph
```

### LinkedIn

```text
CTI should not stop at a PDF.

I built AdversaryGraph to help move from threat reports to detection-ready work:

1. ingest report text/PDF/DOCX
2. extract ATT&CK technique candidates with evidence
3. retrieve related IOC/CVE/TTP/actor evidence for a saved business profile
4. compare TTP overlap with groups and campaigns
5. review a cited, expiring Navigator proposal
6. create threat-hunting and detection work
7. export analyst-ready reports

AdversaryGraph does not perform definitive attribution. TTP overlap is an
investigation lead, and every mapping requires analyst validation.

Live workspace: https://1200km.com/threat-matrix/
Docs: https://1200km.com/adversarygraph-docs/
GitHub: https://github.com/anpa1200/adversarygraph
```

### X / Twitter Thread

```text
1/ I built AdversaryGraph: a self-hosted CTI-to-detection workbench for turning
threat evidence into ATT&CK mappings, grounded retrieval, hunts, and detection
gaps.

2/ Workflow:
report -> evidence -> ATT&CK candidates -> IOC/CVE/TTP/actor retrieval ->
group/campaign comparison -> reviewed Navigator proposal -> analyst work.

3/ Docker mode adds a normalized PostgreSQL/pgvector corpus, cited AI answers,
saved business context, and optional stdio MCP tools. Embeddings stay off until
an operator configures a reviewed private endpoint.

4/ Important limitation: AdversaryGraph is not an attribution or
autonomous-response engine. Retrieval and TTP overlap are investigation leads,
not proof.

5/ Live: https://1200km.com/threat-matrix/
Docs: https://1200km.com/adversarygraph-docs/
GitHub: https://github.com/anpa1200/adversarygraph
```

## Community Submission Copy

### OpenCTI Community

```text
I built AdversaryGraph as a CTI-to-detection workbench around ATT&CK evidence
mapping, governed IOC/CVE/TTP/actor retrieval, group/campaign comparison, threat
hunting, detection gaps, and analyst reporting. It complements OpenCTI-style
workflows by helping analysts review raw evidence and structured hypotheses
before promotion into a CTI knowledge graph. The local MCP surface is advisory;
it is not a direct database or synchronization connector.

Docs: https://1200km.com/adversarygraph-docs/
GitHub: https://github.com/anpa1200/adversarygraph
Related OpenCTI workflow: https://1200km.com/operation-desert-hydra/
```

### MISP Community

```text
AdversaryGraph is a CTI-to-detection workbench for analyst-reviewed ATT&CK
mapping, cross-source retrieval, and detection-gap analysis. It is not a MISP
replacement; the useful integration angle is reviewing report evidence,
structured technique hypotheses, and observable context before those records
feed MISP/OpenCTI-style workflows.

Project: https://github.com/anpa1200/adversarygraph
Docs: https://1200km.com/adversarygraph-docs/
```

### Sigma / Detection Engineering Communities

```text
AdversaryGraph focuses on the step before rule writing: retrieving relevant CTI
with citations, turning report evidence into ATT&CK candidates and falsifiable
hypotheses, and creating analyst-reviewed detection backlog items. It is
intended to feed Sigma/KQL/SPL work, not execute hunts or replace detection
engineering validation.

Live workspace: https://1200km.com/threat-matrix/
CTI Field Manual: https://1200km.com/cti-analyst-field-manual/
```

## Newsletter Pitch

Subject:

```text
AdversaryGraph: CTI reports to ATT&CK mapping and detection backlog
```

Body:

```text
Hi,

I released AdversaryGraph, a self-hosted CTI-to-detection workbench for mapping
threat reports to MITRE ATT&CK, retrieving related IOCs/CVEs/TTPs/actors with
provenance, comparing campaigns, creating hunts, identifying detection gaps,
and exporting analyst-ready outputs.

The project is explicitly analyst-controlled: it does not perform definitive
attribution or autonomous response, and retrieval signals are investigation
leads rather than proof. The public web version supports browser-native ATT&CK
exploration; the self-hosted Docker version adds AI-assisted extraction, a
private normalized retrieval corpus, cited Navigator assistance, optional local
MCP tools, APIs, and reporting.

Live: https://1200km.com/threat-matrix/
Docs: https://1200km.com/adversarygraph-docs/
GitHub: https://github.com/anpa1200/adversarygraph

Best,
Andrey Pautov
```

## Current External Submissions

- awesome-threat-intelligence: https://github.com/hslatman/awesome-threat-intelligence/pull/385
- awesome-mitre-attack: https://github.com/infosecn1nja/awesome-mitre-attack/pull/6
- awesome-detection-engineering: https://github.com/infosecB/awesome-detection-engineering/pull/28
- secondary awesome-threat-intelligence: https://github.com/brandonhimpfen/awesome-threat-intelligence/pull/13
- awesome threat hunting: https://github.com/threat-hunting/awesome_Threat-Hunting/pull/5

## Next Manual Publishing Targets

- LinkedIn: publish the professional launch post first.
- Hacker News: use Show HN only once the demo path is stable.
- Reddit: post different angles to `r/threatintel`, `r/blueteamsec`, and
  `r/cybersecurity`; do not repost the same text.
- OpenCTI / Filigran community: position AdversaryGraph as pre-graph analysis and
  report-to-ATT&CK workflow.
- MISP community: position it as report evidence and detection-gap workflow, not
  a replacement TIP.
- SigmaHQ / detection communities: position it as CTI-to-detection backlog
  material feeding rule development.
- CTI newsletters: pitch the workflow and the live browser workspace.
