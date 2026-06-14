# ThreatMapper And CTI Publishing Kit

Use this file for consistent external publishing of ThreatMapper and the related
1200km CTI ecosystem. The core message is CTI-to-detection, not automated
attribution.

## Canonical Links

- ThreatMapper project hub: https://1200km.com/threatmapper/
- ThreatMapper live web workspace: https://1200km.com/threat-matrix/
- ThreatMapper docs: https://1200km.com/threatmapper-docs/
- ThreatMapper GitHub: https://github.com/anpa1200/threatmapper
- ThreatMapper article: https://medium.com/@1200km/threatmapper-i-built-a-self-hosted-ai-threat-intelligence-platform-heres-how-to-use-it-0aa7673e6bd8
- CTI as a Code: https://1200km.com/CTI_as_a_Code/
- CTI Analyst Field Manual: https://1200km.com/cti-analyst-field-manual/
- Operation Desert Hydra: https://1200km.com/operation-desert-hydra/
- Israel Government Threat Actors CTI: https://1200km.com/israel-government-threat-actors-cti/
- 1200km CTI page: https://1200km.com/cti.html

## One-Line Pitch

ThreatMapper is an AI-assisted CTI-to-detection workbench that turns threat
reports into ATT&CK mappings, TTP-overlap comparisons, Navigator-style views,
detection gaps, and analyst-ready outputs.

## Short Description

ThreatMapper helps analysts operationalize CTI. It extracts ATT&CK technique
candidates from reports, keeps supporting evidence visible, compares selected
TTPs against known groups and campaigns, surfaces detection gaps, and exports
analyst-ready outputs. The web version is a public browser workspace for ATT&CK
exploration. The Docker version adds self-hosted AI extraction, private
PostgreSQL-backed analyses, APIs, and report generation.

## Safety And Accuracy Statement

ThreatMapper does not perform definitive attribution. TTP overlap and group
similarity are investigation leads for analyst review, not proof of actor
identity. LLM-assisted extraction can produce false positives, false negatives,
or ambiguous technique mappings; analysts must validate every mapping against
the source evidence and ATT&CK definitions.

## Platform-Specific Copy

### Hacker News / Show HN

Title:

```text
Show HN: ThreatMapper - CTI reports to ATT&CK mappings and detection gaps
```

Body:

```text
I built ThreatMapper to reduce the manual gap between threat reports and
detection engineering.

The workflow is:
report/PDF/text -> ATT&CK technique candidates with evidence -> group/campaign
TTP-overlap comparison -> Navigator-style layer -> detection gaps -> analyst
report.

There are two modes:
- public browser workspace for ATT&CK exploration and group comparison
- self-hosted Docker platform for AI-assisted report extraction, private
  PostgreSQL-backed analyses, APIs, and PDF reports

It is not an attribution engine. TTP overlap is an investigation lead, and every
LLM-assisted mapping needs analyst validation.

Live workspace: https://1200km.com/threat-matrix/
Docs: https://1200km.com/threatmapper-docs/
GitHub: https://github.com/anpa1200/threatmapper
```

### Reddit r/threatintel

```text
I built ThreatMapper as a CTI-to-detection workflow tool and would appreciate
feedback from CTI analysts.

The goal is not automated attribution. The goal is to make the mechanical part
of report processing easier: extract ATT&CK technique candidates, preserve
supporting evidence, compare TTP overlap with groups/campaigns, identify
detection gaps, and export analyst-ready outputs.

Public workspace: https://1200km.com/threat-matrix/
Docs: https://1200km.com/threatmapper-docs/
GitHub: https://github.com/anpa1200/threatmapper
```

### Reddit r/blueteamsec

```text
I released ThreatMapper, a CTI-to-detection workbench focused on turning threat
reports into detection backlog material.

It maps report evidence to ATT&CK technique candidates, compares TTP overlap
with groups and campaigns, surfaces gaps, and produces Navigator-style views and
analyst reports. The public web version is browser-native; the Docker version
adds self-hosted AI extraction and private analysis storage.

The important constraint: it is not an attribution engine. The output is
analyst-review seed material for hunting and detection engineering.

Live: https://1200km.com/threat-matrix/
Repo: https://github.com/anpa1200/threatmapper
```

### LinkedIn

```text
CTI should not stop at a PDF.

I built ThreatMapper to help move from threat reports to detection-ready work:

1. ingest report text/PDF/DOCX
2. extract ATT&CK technique candidates with evidence
3. compare TTP overlap with groups and campaigns
4. generate Navigator-style views
5. identify detection gaps
6. export analyst-ready reports

ThreatMapper does not perform definitive attribution. TTP overlap is an
investigation lead, and every mapping requires analyst validation.

Live workspace: https://1200km.com/threat-matrix/
Docs: https://1200km.com/threatmapper-docs/
GitHub: https://github.com/anpa1200/threatmapper
```

### X / Twitter Thread

```text
1/ I built ThreatMapper: a CTI-to-detection workbench for turning threat reports
into ATT&CK mappings, TTP-overlap comparisons, and detection gaps.

2/ Workflow:
report -> evidence -> ATT&CK technique candidates -> group/campaign comparison
-> Navigator-style layer -> analyst report.

3/ Public web mode is browser-native. Docker mode adds self-hosted AI
extraction, private PostgreSQL-backed analyses, APIs, and PDF reports.

4/ Important limitation: ThreatMapper is not an attribution engine. TTP overlap
is an investigation lead, not proof.

5/ Live: https://1200km.com/threat-matrix/
Docs: https://1200km.com/threatmapper-docs/
GitHub: https://github.com/anpa1200/threatmapper
```

## Community Submission Copy

### OpenCTI Community

```text
I built ThreatMapper as a CTI-to-detection workbench around ATT&CK evidence
mapping, group/campaign TTP-overlap comparison, detection gaps, and analyst
reporting. It complements OpenCTI-style workflows by helping analysts turn raw
reports into structured ATT&CK hypotheses before promotion into a CTI knowledge
graph.

Docs: https://1200km.com/threatmapper-docs/
GitHub: https://github.com/anpa1200/threatmapper
Related OpenCTI workflow: https://1200km.com/operation-desert-hydra/
```

### MISP Community

```text
ThreatMapper is a CTI-to-detection workbench for analyst-reviewed ATT&CK mapping
and detection-gap analysis. It is not a MISP replacement; the useful integration
angle is turning report evidence into structured technique hypotheses and
observable context that can later feed MISP/OpenCTI-style workflows.

Project: https://github.com/anpa1200/threatmapper
Docs: https://1200km.com/threatmapper-docs/
```

### Sigma / Detection Engineering Communities

```text
ThreatMapper focuses on the step before rule writing: turning CTI report
evidence into ATT&CK technique candidates, hunting hypotheses, detection gaps,
and analyst-reviewed backlog items. It is intended to feed Sigma/KQL/SPL work,
not replace detection engineering validation.

Live workspace: https://1200km.com/threat-matrix/
CTI Field Manual: https://1200km.com/cti-analyst-field-manual/
```

## Newsletter Pitch

Subject:

```text
ThreatMapper: CTI reports to ATT&CK mapping and detection backlog
```

Body:

```text
Hi,

I released ThreatMapper, an open-source CTI-to-detection workbench for mapping
threat reports to MITRE ATT&CK, comparing TTP overlap with known groups and
campaigns, identifying detection gaps, and exporting analyst-ready outputs.

The project is explicitly analyst-controlled: it does not perform definitive
attribution, and TTP overlap is treated as an investigation lead rather than
proof. The public web version supports browser-native ATT&CK exploration; the
self-hosted Docker version adds AI-assisted extraction, private analysis
storage, APIs, and PDF reporting.

Live: https://1200km.com/threat-matrix/
Docs: https://1200km.com/threatmapper-docs/
GitHub: https://github.com/anpa1200/threatmapper

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
- OpenCTI / Filigran community: position ThreatMapper as pre-graph analysis and
  report-to-ATT&CK workflow.
- MISP community: position it as report evidence and detection-gap workflow, not
  a replacement TIP.
- SigmaHQ / detection communities: position it as CTI-to-detection backlog
  material feeding rule development.
- CTI newsletters: pitch the workflow and the live browser workspace.
