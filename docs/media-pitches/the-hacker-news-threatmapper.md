# The Hacker News Pitch: ThreatMapper

Prepared: 2026-06-16

## Positioning

Pitch ThreatMapper as a new open-source CTI tool release, not as a tutorial or
portfolio update.

**Core angle:** ThreatMapper is an open-source, self-hosted AI-assisted CTI
workbench that maps threat reports to MITRE ATT&CK and supports the handoff
from threat intelligence to detection engineering.

## Recommended Subject Lines

```text
Research pitch: Open-source ThreatMapper maps threat reports to MITRE ATT&CK with self-hosted AI workflows
```

```text
Tool release: ThreatMapper helps CTI teams turn threat reports into ATT&CK mappings and detection handoff artifacts
```

```text
Open-source CTI platform ThreatMapper adds AI-assisted ATT&CK mapping and TTP comparison workflows
```

## Short Submission

```text
Hi The Hacker News team,

I’m Andrey Pautov, a Threat Intelligence Research Engineer and creator of the
1200km security research ecosystem.

I recently released ThreatMapper v2.0.0, an open-source self-hosted CTI
platform that helps analysts convert threat reports into MITRE ATT&CK mappings,
compare TTP overlap against known groups and campaigns, and generate
analyst-ready outputs for detection engineering handoff.

The project is designed for local/self-hosted workflows. It includes a Docker
deployment, public documentation, screenshots, demo data, sample outputs,
release notes, CI, and a validation page with external review evidence.

Why it may be relevant to your readers:
- bridges CTI reporting and detection engineering workflows
- maps reports to MITRE ATT&CK with analyst review in the loop
- compares extracted TTPs against ATT&CK group and campaign profiles
- supports self-hosted operation rather than a required SaaS workflow
- ships as an open-source project with release artifacts and documentation

Project:
https://github.com/anpa1200/threatmapper

Release:
https://github.com/anpa1200/threatmapper/releases/tag/v2.0.0

Project hub:
https://1200km.com/threatmapper/

External validation / publications:
https://1200km.com/external-validation.html

I can provide screenshots, a short demo flow, technical details, or an exclusive
write-up angle if useful.

Best,
Andrey Pautov
https://1200km.com/
https://github.com/anpa1200
```

## Longer Editor Pitch

```text
Hi The Hacker News team,

I’m Andrey Pautov, a Threat Intelligence Research Engineer and creator of
1200km.com, where I publish practical CTI, detection engineering, malware
analysis, OpenCTI, cloud security, and AI-assisted security tooling research.

I’m submitting ThreatMapper as a potential tool-release / research story.
ThreatMapper v2.0.0 is an open-source, self-hosted CTI-to-detection workbench
for mapping threat reports to MITRE ATT&CK, comparing extracted TTP overlap with
known groups and campaigns, and producing analyst-ready outputs.

The problem it addresses is a common CTI operations gap: threat reports often
contain useful behavioral evidence, but the path from report text to ATT&CK
mapping, group/campaign comparison, detection coverage review, and SOC handoff
is still highly manual. ThreatMapper is designed to make that workflow more
structured while keeping analyst review explicit.

The v2.0.0 release includes:
- self-hosted Docker Compose deployment
- React/Vite frontend and FastAPI backend
- ATT&CK Enterprise/Mobile/ICS data ingestion
- AI-assisted report-to-ATT&CK extraction
- TTP overlap comparison against ATT&CK groups and campaigns
- ATT&CK Navigator layer export, JSON output, and analyst report workflows
- demo dataset, expected mappings, sample outputs, screenshots, release notes,
  validation rubric, and CI

Important limitation: ThreatMapper is not an attribution engine. TTP overlap is
presented as an investigation lead, and LLM-assisted mappings require analyst
review.

Links:
- GitHub: https://github.com/anpa1200/threatmapper
- Release: https://github.com/anpa1200/threatmapper/releases/tag/v2.0.0
- Project hub: https://1200km.com/threatmapper/
- Public ATT&CK workspace: https://1200km.com/threat-matrix/
- External validation: https://1200km.com/external-validation.html

I can provide screenshots, a technical walkthrough, an exclusive article draft,
or answer questions about the design and CTI workflow.

Best,
Andrey Pautov
```

## News Story Angle

**Headline idea:**

```text
Open-Source ThreatMapper Aims to Bridge CTI Reports and Detection Engineering with ATT&CK Mapping
```

**Summary:**

ThreatMapper is a self-hosted CTI-to-detection platform that helps analysts map
threat reports to MITRE ATT&CK, compare observed TTPs with known groups and
campaigns, and produce outputs that can support detection engineering handoff.
The project emphasizes analyst review, reproducible demo data, and self-hosted
operation.

**Why now:**

The v2.0.0 release adds the maturity evidence needed for outside review:
release notes, CI, screenshots, demo data, sample outputs, validation material,
quickstart, and security/limitations documentation.

## Suggested Article Outline

1. CTI teams still struggle to move from narrative reports to detection-ready
   artifacts.
2. ThreatMapper turns report text into ATT&CK mapping candidates with analyst
   review.
3. The platform compares TTP overlap against ATT&CK groups and campaigns.
4. Analysts can export Navigator layers, JSON, reports, and coverage-gap
   artifacts.
5. The tool is self-hosted, with Docker Compose, PostgreSQL, Redis/Celery,
   FastAPI, React, and D3.js.
6. Limitations: it is not attribution automation, and AI output must be
   validated.
7. Release evidence: v2.0.0, green CI, docs, screenshots, demo data, validation
   rubric, and public project hub.

## Facts To Use

| Item | Value |
|---|---|
| Project | ThreatMapper |
| Release | v2.0.0 |
| Release date | 2026-06-16 |
| License | MIT |
| GitHub | https://github.com/anpa1200/threatmapper |
| Release URL | https://github.com/anpa1200/threatmapper/releases/tag/v2.0.0 |
| Project hub | https://1200km.com/threatmapper/ |
| Public workspace | https://1200km.com/threat-matrix/ |
| External validation | https://1200km.com/external-validation.html |
| Current GitHub stats | 8 stars, 1 fork at preparation time |
| Current CI | Pending for v2.0.0 after release push |
| Backend verification | `76 passed` |
| Frontend verification | `npm run build` passed |

## Screenshot Suggestions

Use screenshots from:

- `docs/screenshots/02_1x07j05Kn78RJY96S3Ga4IVQ.png`
- `docs/screenshots/10_1xCsGSK7APVQvnvTDCLxXKNA.png`
- `docs/screenshots/13_1xFpAXPkiL1j3fiuOkL7tp8A.png`
- `docs/screenshots/20_1xVAfpLRWhfkB0pwRR5C4Nlw.png`

Use this short workflow video when an editor asks for a demo:

- `docs/demo-videos/dfir-report-ai-analysis-compare.mp4`
- `docs/demo-videos/dfir-report-ai-analysis-compare.gif`
- `docs/demo-videos/dfir-report-ai-analysis-compare-poster.png`

Public copied versions are also available on 1200km.com:

- `https://1200km.com/assets/validation/threatmapper-dashboard.png`
- `https://1200km.com/assets/validation/threatmapper-analysis.png`

## One-Paragraph Boilerplate

```text
ThreatMapper is an open-source, self-hosted CTI-to-detection workbench created
by Andrey Pautov. It helps analysts map threat reports to MITRE ATT&CK, compare
TTP overlap with known groups and campaigns, and export analyst-ready outputs
for investigation and detection engineering workflows. The project is designed
for self-hosted use and includes release notes, CI, documentation, screenshots,
demo data, sample outputs, and validation material.
```

## Do Not Claim

- Do not claim ThreatMapper proves attribution.
- Do not claim AI mappings are fully automatic or always correct.
- Do not claim open PRs are accepted validation.
- Do not frame it as a hacking tutorial.
- Do not pitch the whole 1200km portfolio as the primary story.

## Follow-Up Assets

- Demo dataset: `docs/demo-dataset/`
- Sample outputs: `docs/sample-outputs/`
- Validation plan: `docs/validation/evaluation-plan.md`
- Mapping rubric: `docs/validation/mapping-review-rubric.md`
- Security model: `docs/security-model.md`
- Limitations: `docs/limitations.md`
- Production readiness: `docs/production-readiness.md`
