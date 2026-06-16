# Open-Source ThreatMapper Bridges CTI Reports and Detection Engineering with AI-Assisted ATT&CK Mapping

**Target outlet:** The Hacker News
**Draft type:** Feature / tool release / expert insight
**Source article:** https://infosecwriteups.com/threatmapper-i-built-a-self-hosted-ai-threat-intelligence-platform-heres-how-to-use-it-0aa7673e6bd8
**Canonical project:** https://github.com/anpa1200/threatmapper
**Project hub:** https://1200km.com/threatmapper/
**Release:** https://github.com/anpa1200/threatmapper/releases/tag/v0.9.0
**External validation:** https://1200km.com/external-validation.html

## Editorial Positioning Notes

Comparable The Hacker News tool articles tend to follow this structure:

- start from a defensive operational problem, not from the product itself;
- explain why MITRE ATT&CK, threat intelligence, or threat-informed defense matters;
- introduce the tool as an implementation path;
- show screenshots for each major workflow;
- include practical deployment guidance;
- close with limitations, security considerations, and where the project fits.

Useful comparison points:

- THN's Wazuh/MITRE ATT&CK article frames Wazuh as an open-source platform with ATT&CK-oriented threat-hunting modules, then walks through the intelligence, framework, dashboard, and events views.
- THN's CTEM/threat-intelligence expert insight frames CTI as a prioritization and validation layer rather than just a feed.
- THN's MITRE ATT&CK guidance emphasizes gap analysis and atomic testing as practical ways to move from framework knowledge to defense.
- THN also covers open-source tools when there is a clear security relevance, but offensive tools need careful framing around defensive impact and risk.

For ThreatMapper, the strongest frame is:

> ThreatMapper is a self-hosted CTI-to-detection workbench that helps analysts move from narrative threat reports to ATT&CK mappings, TTP-overlap leads, detection gaps, and analyst-ready outputs while keeping review and deployment control with the operator.

## Article Draft

Cyber threat intelligence often arrives as prose: a vendor report, an incident-response summary, a malware write-up, or an internal investigation note. The hard part begins after reading it. Analysts still need to translate behavior into MITRE ATT&CK techniques, preserve evidence for each mapping, compare the resulting TTP set against known groups or campaigns, and turn the output into something a detection engineer or SOC analyst can use.

That handoff is still more manual than many teams would like.

ThreatMapper is an open-source, self-hosted CTI-to-detection workbench designed to reduce that gap. It takes threat-report text, PDFs, DOCX files, or analyst-provided notes and converts them into ATT&CK mapping candidates, supporting evidence, group and campaign similarity leads, Navigator-style layers, and report outputs.

The project is not positioned as an attribution engine. Its core design assumption is that ATT&CK mappings and TTP overlap are analyst-review material, not final truth. Similarity scores can help prioritize investigation, but they do not prove actor identity without malware, infrastructure, victimology, timing, procedure detail, and external intelligence.

![ThreatMapper overview](../screenshots/02_1x07j05Kn78RJY96S3Ga4IVQ.png)

## Why This Problem Matters

MITRE ATT&CK gives defenders a shared language for describing adversary behavior, but using it well still requires consistent mapping discipline. A report may describe scheduled-task persistence, PowerShell execution, credential dumping, encoded commands, or cloud identity abuse. Each behavior must be mapped to a technique or sub-technique, checked against source evidence, and then translated into detection or hunting work.

For one report, that is manageable. Across many reports, incidents, and threat feeds, the work becomes repetitive and easy to lose in documents, spreadsheets, and ad hoc notes.

ThreatMapper focuses on that middle layer:

1. turn report text into ATT&CK technique candidates;
2. keep the evidence visible;
3. compare selected TTPs with known group and campaign profiles;
4. identify gaps between observed behavior and a selected actor profile;
5. export layers, JSON, and analyst reports for follow-up.

![ThreatMapper workflow](../screenshots/03_1x0dTCvSgZ4dMeQDXkbutXPA.png)

## What ThreatMapper Does

ThreatMapper has two related modes.

The public browser workspace is intended for ATT&CK exploration, manual layers, group overlays, comparison workflows, and local analysis in the browser. It is useful for exploration and for reviewing the concept without deploying infrastructure.

The Docker deployment is the full self-hosted platform. It adds backend AI-assisted report extraction, PostgreSQL-backed analysis storage, API endpoints, report generation, Redis/Celery background jobs, and scheduled ATT&CK synchronization.

At a high level, the workflow looks like this:

- paste or upload a threat report;
- select an LLM provider configured by the operator;
- extract candidate ATT&CK techniques with evidence and confidence;
- inject the extracted techniques into a Navigator-style layer;
- compare the layer against group, campaign, or stored-report profiles;
- export JSON, ATT&CK Navigator layers, or analyst-ready reports.

![ThreatMapper dashboard](../screenshots/04_1x31Nq2VMJ9Mm9lgryHGJRQQ.png)

## Architecture

ThreatMapper runs as a self-hosted Docker Compose stack:

- React / Vite frontend;
- FastAPI backend;
- PostgreSQL for ATT&CK data and analysis records;
- Redis and Celery for background tasks and scheduled ATT&CK synchronization.

The backend ingests MITRE ATT&CK STIX bundles and stores tactics, techniques, groups, campaigns, and relationships in PostgreSQL. In Docker mode, report content is sent only to the LLM provider configured by the operator, such as Anthropic, OpenAI, Google Gemini, or a private/local gateway where available.

The public browser workspace does not process private reports through backend LLM extraction or store private report analyses.

![Architecture view](../screenshots/05_1x4zLLN71CBFHIMCEPOrTxmw.png)

## Report-to-ATT&CK Extraction

The analysis workflow starts with a report. Analysts can paste text or upload supported files, select an ATT&CK domain, and choose a configured provider. ThreatMapper streams the extraction result and builds a structured record of candidate techniques.

Each technique candidate includes:

- ATT&CK ID;
- technique name;
- tactic;
- confidence;
- supporting evidence;
- source-review context.

The evidence field is important. It keeps the mapping traceable to the source text, which helps analysts validate whether the model mapped an explicit behavior, inferred a behavior, or produced a weak candidate that should be rejected.

Demo video for this workflow:
[`DFIR report download to AI analysis and comparison`](../demo-videos/dfir-report-ai-analysis-compare.mp4).
It shows the practical path from indexed DFIR examples, to a local PDF upload,
to streamed ATT&CK extraction, and then selected TTP review in the workspace.
A GIF version is available at
[`../demo-videos/dfir-report-ai-analysis-compare.gif`](../demo-videos/dfir-report-ai-analysis-compare.gif).

![Analysis input](../screenshots/06_1x62_zstQMYPoqj4kSTn4nBg.png)

![Streaming analysis](../screenshots/07_1x69nMwI7Xj8eNIWHv_C_KVg.png)

![Technique extraction table](../screenshots/08_1x7jquz_YKO0Odni3r3InzYw.png)

![Technique evidence review](../screenshots/09_1x89fT-TuOac6OMSNdZ61vag.png)

## Navigator-Style ATT&CK Workspace

After extraction, analysts can inject selected techniques into the Navigator view. The matrix highlights the selected TTPs and allows analysts to manually add, remove, search, save, reload, and export layers.

This matters because ATT&CK work is rarely a one-time extraction. Analysts often need to maintain incident layers, campaign layers, detection-coverage layers, and actor-focused layers over time.

![Navigator matrix](../screenshots/10_1xCsGSK7APVQvnvTDCLxXKNA.png)

![Technique selection](../screenshots/11_1xDw7KTqHRijCEkYvUrdBMbQ.png)

![Layer controls](../screenshots/12_1xEsC2UAT23n0xRDPv29oEWg.png)

## Group and Campaign Similarity

ThreatMapper compares selected TTP sets against currently ingested ATT&CK group and campaign profiles using Jaccard overlap. The goal is not to announce attribution. The goal is to identify overlap worth investigating and to make gaps visible.

The comparison workflow has three useful modes:

- groups, for comparing against aggregate group TTP profiles;
- campaigns, for comparing against named operations where ATT&CK has campaign-level technique relationships;
- reports, for comparing against previous analyses stored in the local database.

Campaign-level comparison can be more specific than group-level comparison because a group profile often spans years of activity. A named campaign profile may better represent one operation or incident pattern.

![Group overlay](../screenshots/13_1xFpAXPkiL1j3fiuOkL7tp8A.png)

![Similarity ranking](../screenshots/14_1xJDE0azpONj0OVW95p9yZkg.png)

![Group detail view](../screenshots/15_1xQkMDTHSy82_j4PA96Q3j6A.png)

![Tactic breakdown](../screenshots/16_1xRL5VY8-RMrIQv_SIZpwPQQ.png)

![Visual diff](../screenshots/17_1xRai3eOrk1Upsd4zeHxtroA.png)

![Gap analysis](../screenshots/18_1xT8D25vI8Mt2T7iWmqEJkfA.png)

## Detection Engineering Handoff

The most useful output is not the similarity score. It is the structured backlog that follows from it.

If a report layer overlaps with a group profile, the shared techniques can support hypothesis development. Techniques present in the group profile but missing from the analyst's current layer can become a hunt checklist or detection-coverage review. Techniques present in the report but absent from a selected actor profile can signal either a weak attribution hypothesis or a change in behavior that deserves separate review.

This gives teams a defensible way to move from "this report looks similar to X" to a concrete set of questions:

- Which techniques are explicitly supported by evidence?
- Which overlaps are strong enough to investigate?
- Which ATT&CK tactics are over- or under-represented?
- Which detection gaps should be reviewed first?
- Which mappings should be rejected after analyst validation?

![Detection gap workflow](../screenshots/19_1xUp-LNxuga22bScwyZiFuHA.png)

![Evidence review workflow](../screenshots/20_1xVAfpLRWhfkB0pwRR5C4Nlw.png)

![Report library comparison](../screenshots/21_1xXfbZTKCAGTSArnhi3tiMOA.png)

![Report detail view](../screenshots/22_1x_Dlqijzjnt_Ehr1ULHPmrg.png)

## Reports, Exports, and API Usage

ThreatMapper can export analyst outputs in several formats, including ATT&CK Navigator-compatible JSON layers, plain JSON, and report views. The Docker deployment also exposes API endpoints, making it possible to integrate the workflow into internal analysis pipelines.

For teams that already maintain Navigator layers, the import/export path is useful because ThreatMapper can work with existing ATT&CK layer files rather than forcing analysts to rebuild their work from scratch.

![Export workflow](../screenshots/23_1xa6c9YTdIktlPk1w0FRQHaA.png)

![PDF report output](../screenshots/24_1xaJW4II93D-bLqFMexDlW1g.png)

![API documentation](../screenshots/25_1xaSqu_irokLlGQa1Njwa0fQ.png)

![Headless workflow](../screenshots/26_1xecTDnydMYwWX8-Ncuk8GfQ.png)

## Deployment and Security Considerations

ThreatMapper is intended for controlled environments. The default Docker Compose deployment is suitable for local labs, private analyst workstations, and internal evaluation. Internet-facing deployments require additional hardening.

Operators should review:

- TLS termination;
- authentication and authorization;
- reverse proxy configuration;
- network exposure;
- secret management;
- PostgreSQL backups and retention;
- provider data-handling terms;
- whether a private/local LLM gateway is required.

Uploaded reports should be treated as sensitive. The public workspace is for exploration; private reports should be processed only in an operator-controlled deployment.

![Settings view](../screenshots/27_1xlKoiwInK4AuBHDFSINWekA.png)

![Provider configuration](../screenshots/28_1xlLkb-oRUX5Tns2S85SS16g.png)

![Security notes](../screenshots/29_1xl_EPylZmZEnAaDF6JjQE4w.png)

## Keeping ATT&CK Data Fresh

ATT&CK changes over time as techniques, groups, campaigns, software, and relationships are updated. ThreatMapper includes scheduled synchronization so a self-hosted deployment can refresh ATT&CK data without manual reimport work.

This is especially useful for retrospective analysis. A report analyzed months ago can be compared again after ATT&CK data changes, without re-running the LLM extraction.

![ATT&CK sync](../screenshots/30_1xlp9MmZunILgId0X7JHQVbw.png)

![ATT&CK versions](../screenshots/31_1xm1Zh30Hm7e6wmzZq1Mjdog.png)

## Where It Fits

ThreatMapper is not a SIEM, not an EDR, and not a replacement for OpenCTI, MISP, ATT&CK Navigator, or commercial CTI platforms.

Its role is narrower:

- before rule writing, it helps turn CTI report evidence into ATT&CK hypotheses;
- before attribution discussion, it helps expose TTP overlap and gaps;
- before SOC handoff, it helps organize extracted techniques into reviewable outputs;
- before knowledge-graph promotion, it helps analysts validate whether the source evidence supports the mapping.

The project is open source and currently pre-v1.0. The v0.9.0 release focuses on maturity evidence: release notes, CI, documentation, screenshots, demo data, sample outputs, validation material, and a public project hub.

![Project hub](../screenshots/32_1xoyHjzN-tAx7Lx19Xg0IPyA.png)

![Documentation hub](../screenshots/33_1xq9LHKlOmbS1119qTlPKjIA.png)

![Public workspace](../screenshots/34_1xz4L2KcZIixQjdkrcBt8OlA.png)

![Ecosystem navigation](../screenshots/35_1xz711T5SOrORpjITlM2IY9A.png)

![Publication cover image](../screenshots/36_7xV1_7XP4snlmqrc_0Njontw.png)

## Availability

ThreatMapper is available on GitHub under the MIT license.

- GitHub: https://github.com/anpa1200/threatmapper
- Release v0.9.0: https://github.com/anpa1200/threatmapper/releases/tag/v0.9.0
- Project hub: https://1200km.com/threatmapper/
- Public ATT&CK workspace: https://1200km.com/threat-matrix/
- External validation and publications: https://1200km.com/external-validation.html

## Suggested Editor Summary

ThreatMapper is an open-source, self-hosted CTI-to-detection workbench that maps threat reports to MITRE ATT&CK, compares TTP overlap against group and campaign profiles, and exports analyst-ready outputs. The tool is designed around analyst validation rather than automated attribution, and the v0.9.0 release includes Docker deployment, CI, documentation, demo data, screenshots, and validation material.

## Image Checklist From Source Article

All preserved images from the InfoSec Write-ups / Medium article are referenced above:

- [x] `docs/screenshots/02_1x07j05Kn78RJY96S3Ga4IVQ.png`
- [x] `docs/screenshots/03_1x0dTCvSgZ4dMeQDXkbutXPA.png`
- [x] `docs/screenshots/04_1x31Nq2VMJ9Mm9lgryHGJRQQ.png`
- [x] `docs/screenshots/05_1x4zLLN71CBFHIMCEPOrTxmw.png`
- [x] `docs/screenshots/06_1x62_zstQMYPoqj4kSTn4nBg.png`
- [x] `docs/screenshots/07_1x69nMwI7Xj8eNIWHv_C_KVg.png`
- [x] `docs/screenshots/08_1x7jquz_YKO0Odni3r3InzYw.png`
- [x] `docs/screenshots/09_1x89fT-TuOac6OMSNdZ61vag.png`
- [x] `docs/screenshots/10_1xCsGSK7APVQvnvTDCLxXKNA.png`
- [x] `docs/screenshots/11_1xDw7KTqHRijCEkYvUrdBMbQ.png`
- [x] `docs/screenshots/12_1xEsC2UAT23n0xRDPv29oEWg.png`
- [x] `docs/screenshots/13_1xFpAXPkiL1j3fiuOkL7tp8A.png`
- [x] `docs/screenshots/14_1xJDE0azpONj0OVW95p9yZkg.png`
- [x] `docs/screenshots/15_1xQkMDTHSy82_j4PA96Q3j6A.png`
- [x] `docs/screenshots/16_1xRL5VY8-RMrIQv_SIZpwPQQ.png`
- [x] `docs/screenshots/17_1xRai3eOrk1Upsd4zeHxtroA.png`
- [x] `docs/screenshots/18_1xT8D25vI8Mt2T7iWmqEJkfA.png`
- [x] `docs/screenshots/19_1xUp-LNxuga22bScwyZiFuHA.png`
- [x] `docs/screenshots/20_1xVAfpLRWhfkB0pwRR5C4Nlw.png`
- [x] `docs/screenshots/21_1xXfbZTKCAGTSArnhi3tiMOA.png`
- [x] `docs/screenshots/22_1x_Dlqijzjnt_Ehr1ULHPmrg.png`
- [x] `docs/screenshots/23_1xa6c9YTdIktlPk1w0FRQHaA.png`
- [x] `docs/screenshots/24_1xaJW4II93D-bLqFMexDlW1g.png`
- [x] `docs/screenshots/25_1xaSqu_irokLlGQa1Njwa0fQ.png`
- [x] `docs/screenshots/26_1xecTDnydMYwWX8-Ncuk8GfQ.png`
- [x] `docs/screenshots/27_1xlKoiwInK4AuBHDFSINWekA.png`
- [x] `docs/screenshots/28_1xlLkb-oRUX5Tns2S85SS16g.png`
- [x] `docs/screenshots/29_1xl_EPylZmZEnAaDF6JjQE4w.png`
- [x] `docs/screenshots/30_1xlp9MmZunILgId0X7JHQVbw.png`
- [x] `docs/screenshots/31_1xm1Zh30Hm7e6wmzZq1Mjdog.png`
- [x] `docs/screenshots/32_1xoyHjzN-tAx7Lx19Xg0IPyA.png`
- [x] `docs/screenshots/33_1xq9LHKlOmbS1119qTlPKjIA.png`
- [x] `docs/screenshots/34_1xz4L2KcZIixQjdkrcBt8OlA.png`
- [x] `docs/screenshots/35_1xz711T5SOrORpjITlM2IY9A.png`
- [x] `docs/screenshots/36_7xV1_7XP4snlmqrc_0Njontw.png`

## Demo Video Checklist

- [x] `docs/demo-videos/dfir-report-ai-analysis-compare.mp4`
- [x] `docs/demo-videos/dfir-report-ai-analysis-compare.gif`
- [x] `docs/demo-videos/dfir-report-ai-analysis-compare-poster.png`
