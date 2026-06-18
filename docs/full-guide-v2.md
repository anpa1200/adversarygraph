# AdversaryGraph v2.x Full Guide

![AdversaryGraph v2.0 cover](assets/adversarygraph-v2/01-31Nq2VMJ9Mm9lgryHGJRQQ.webp)

AdversaryGraph is a self-hosted CTI-to-detection workbench for turning threat
reports into MITRE ATT&CK mapping candidates, reviewing the supporting evidence,
comparing TTP overlap against known groups and campaigns, identifying detection
gaps, and exporting analyst-ready outputs.

AdversaryGraph is not an attribution engine. It helps analysts organize evidence
and investigation leads. Final mappings, similarity conclusions, and detection
handoffs require human review.

Public article and visual walkthrough:

- 1200km article: https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html
- Medium archive: https://medium.com/@1200km

## 1. Operating Modes

### Public Web Workspace

Use the public workspace for:

- ATT&CK exploration
- manual TTP layers
- group overlays
- browser-side comparison
- public ecosystem navigation

Do not upload confidential reports to public demos.

### Self-Hosted Docker Workspace

Use Docker mode for:

- private report analysis
- configured LLM providers
- local LLM gateways
- PostgreSQL-backed report history
- API-driven workflows
- PDF, Navigator, JSON, and STIX/OpenCTI exports
- scheduled ATT&CK synchronization

## 2. Installation

### Requirements

- Docker Engine
- Docker Compose v2
- 8 GB RAM available to Docker
- at least one AI provider key or a local OpenAI-compatible LLM endpoint

### Clone And Configure

```bash
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
cp .env.example .env
```

Configure at least one provider:

```env
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4.1
GEMINI_API_KEY=
```

For a local LLM:

```env
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_API_KEY=local
LOCAL_LLM_MODEL=llama3.1:8b
```

Start:

```bash
docker compose up -d --build
```

Open:

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API docs | http://localhost:8000/docs |
| Health | http://localhost:8000/api/health |
| Reference book | http://localhost:3001/anomaly-detection-atlas/ |

Health should return:

```json
{"status":"ok","version":"2.2.0"}
```

Run the built-in deployment self-test after Docker startup:

```bash
docker compose run --rm selftest
```

The self-test verifies database connectivity, Redis connectivity,
ATT&CK/ATLAS reference data, and configured provider keys without exposing
secret values. If an API request fails in the UI, the error popup shows the
request context and provides:

- `Recheck` to rerun `/api/system/selftest`
- `Open troubleshooting` to open the internal Docker troubleshooting page

When recheck passes, the popup turns green and shows `All correct.`.

Internal troubleshooting page:

```text
http://localhost:3000/troubleshooting
```

## 3. Core Concepts

![AdversaryGraph problem statement](assets/adversarygraph-v2/02-69nMwI7Xj8eNIWHv_C_KVg.webp)

| Concept | Meaning |
|---|---|
| Technique | MITRE ATT&CK technique or sub-technique such as `T1566.002` |
| Evidence | Text from the report that supports a mapping |
| Review status | Analyst state: suggested, accepted, rejected, or needs evidence |
| Similarity | Jaccard overlap between selected TTPs and a group/campaign/report profile |
| Detection gap | A mapped behavior without sufficient telemetry, detection, or validation |
| STIX export | OpenCTI-ready bundle containing report, ATT&CK attack-patterns, and similarity leads |

![AdversaryGraph workflow map](assets/adversarygraph-v2/03-7jquz_YKO0Odni3r3InzYw.webp)

## 4. Discover Intelligence

The Discover page is the starting dashboard.

![Discover Intelligence dashboard](assets/adversarygraph-v2/04-VAfpLRWhfkB0pwRR5C4Nlw.webp)

Use it to:

- start actor investigation
- launch AI analysis
- compare behavior
- review coverage
- see current ATT&CK object counts
- inspect most-referenced techniques
- open recent public intelligence examples

The page is designed for orientation, not final analysis.

## 5. AI Analysis

AI Analysis accepts:

![AI Analysis provider and upload panel](assets/adversarygraph-v2/05-Up-LNxuga22bScwyZiFuHA.webp)

- pasted report text
- PDF files
- DOCX files
- TXT files

Providers:

- Claude
- OpenAI
- Gemini
- Local OpenAI-compatible endpoint

Workflow:

1. Select framework/domain: Enterprise ATT&CK, Mobile ATT&CK, ICS ATT&CK, or MITRE ATLAS.
2. Select provider.
3. Paste text or upload a supported file.
4. Run analysis.
5. Watch streamed model output.
6. Review extracted techniques.
7. Accept, reject, or flag mappings that need evidence.
8. Inject accepted TTPs into Navigator.
9. Export PDF or STIX/OpenCTI output.

Review every mapping. The model may over-map broad behaviors, miss
sub-techniques, or infer too much from actor/tool names.

![AI Analysis workflow and extracted mappings](assets/adversarygraph-v2/15-89fT-TuOac6OMSNdZ61vag.webp)

![AI Analysis result with group similarity leads](assets/adversarygraph-v2/16-FpAXPkiL1j3fiuOkL7tp8A.webp)

![AI Analysis raw structured output](assets/adversarygraph-v2/19-T8D25vI8Mt2T7iWmqEJkfA.webp)

### Review Status

AdversaryGraph supports four analyst review states for extracted mappings:

- suggested
- accepted
- rejected
- needs-evidence

Use these states to separate raw model suggestions from analyst-reviewed
findings before exporting or injecting TTPs into Navigator.

![Review status controls](assets/adversarygraph-v2/33-Rai3eOrk1Upsd4zeHxtroA.webp)

## 6. Local LLM Mode

Local mode is for private or offline-friendly analysis using an
OpenAI-compatible endpoint.

Common options:

- Ollama
- LM Studio
- LocalAI
- vLLM

Ollama example:

```bash
ollama pull llama3.1:8b
ollama serve
```

`.env`:

```env
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_MODEL=llama3.1:8b
LOCAL_LLM_API_KEY=local
```

Use a capable model for extraction. Small models may produce incomplete JSON or
weak ATT&CK mappings.

## 7. Navigator

Navigator provides the ATT&CK matrix workspace.

![Navigator matrix workspace](assets/adversarygraph-v2/06-4zLLN71CBFHIMCEPOrTxmw.webp)

Capabilities:

- Enterprise, Mobile, ICS, and ATLAS domains
- zoom and pan matrix view
- sub-technique expansion
- technique search
- platform filtering
- manual TTP selection
- group overlay
- selected-technique side panel
- technique detail links
- import ATT&CK Navigator layer JSON
- save/load server-side layers
- export PDF
- export ATT&CK Navigator JSON

Color logic:

- red: in your selected TTP layer
- gray/blue: overlay or reference context
- amber: shared between your layer and overlay

Navigator is where reviewed AI results become an analyst-controlled TTP layer.

![Navigator selected TTP layer](assets/adversarygraph-v2/20-q9LHKlOmbS1119qTlPKjIA.webp)

![Navigator actor overlay and technique detail](assets/adversarygraph-v2/21-QkMDTHSy82_j4PA96Q3j6A.webp)

![Navigator domain and selected TTP controls](assets/adversarygraph-v2/34-lp9MmZunILgId0X7JHQVbw.webp)

## 8. ATT&CK Group Library

The group library provides enriched ATT&CK actor context.

![ATT&CK Group Library actor page](assets/adversarygraph-v2/07-Dw7KTqHRijCEkYvUrdBMbQ.webp)

Each actor page includes:

- ATT&CK group ID
- aliases
- description
- STIX ID
- ATT&CK object version
- created/modified metadata
- mapped technique count
- campaign count
- tactic coverage
- observed platforms
- technique usage evidence
- source names
- external references
- ATT&CK source link

Use it to understand actor behavior profiles and to load actor TTPs into your
working layer.

![Group tactic and platform coverage](assets/adversarygraph-v2/28-lLkb-oRUX5Tns2S85SS16g.webp)

## 9. Campaigns

AdversaryGraph ingests ATT&CK campaign objects and relationships where available.

Use campaigns when group-level profiles are too broad. Campaigns often represent
more specific operations and may be better comparison targets for one incident
or report.

## 10. Compare

Compare has three modes:

![Compare page modes](assets/adversarygraph-v2/26-aJW4II93D-bLqFMexDlW1g.webp)

- Groups
- Campaigns
- Reports

### Groups

Ranks your selected TTP layer against known ATT&CK group profiles.

Use for:

- initial lead generation
- overlap review
- detection-gap prioritization

Do not use similarity alone as attribution.

![Group comparison results](assets/adversarygraph-v2/27-_Dlqijzjnt_Ehr1ULHPmrg.webp)

### Campaigns

Ranks your TTP layer against named ATT&CK campaigns.

Use for:

- operation-specific overlap
- narrower comparison than full group profiles
- retrospective behavior matching

![Campaign comparison and overlap review](assets/adversarygraph-v2/29-0dTCvSgZ4dMeQDXkbutXPA.webp)

### Reports

Compares current TTPs against previous AI analyses stored in the local report
database.

![Stored report comparison](assets/adversarygraph-v2/30-ecTDnydMYwWX8-Ncuk8GfQ.webp)

Use for:

- cross-report correlation
- repeated behavior discovery
- local incident clustering

## 11. Group vs Group

Group vs Group compares multiple ATT&CK group profiles.

![Group vs Group comparison](assets/adversarygraph-v2/08-07j05Kn78RJY96S3Ga4IVQ.webp)

Views:

- overlap matrix
- combined ATT&CK view
- technique table

Use it to understand which actor profiles share commodity behavior and which
techniques are more distinctive.

## 12. DFIR Examples

The DFIR Examples page indexes public DFIR Report metadata.

![DFIR Examples page](assets/adversarygraph-v2/17-aSqu_irokLlGQa1Njwa0fQ.webp)

AdversaryGraph stores:

- title
- source URL
- date
- tags
- ATT&CK technique IDs
- actor mappings where available

AdversaryGraph does not mirror third-party report text, screenshots, or artifacts.

![DFIR example detail and workflow](assets/adversarygraph-v2/18-RL5VY8-RMrIQv_SIZpwPQQ.webp)

Workflow:

1. Open a source report.
2. Save a local PDF from the original source page.
3. Upload the PDF in AI Analysis.
4. Extract candidate TTPs.
5. Review evidence.
6. Compare against groups, campaigns, and previous reports.

## 13. Reference Sync

Reference Sync shows the state of ATT&CK data.

![Reference Sync page](assets/adversarygraph-v2/25-lKoiwInK4AuBHDFSINWekA.webp)

Capabilities:

- current ingested versions
- latest known versions
- stale/update-needed state
- manual sync trigger
- Enterprise, Mobile, ICS, and ATLAS domain selection
- force sync option

Scheduled sync runs through Celery Beat. Manual sync is available through the UI
and API.

## 14. Sector Intelligence

Sector Intelligence is a v2.1 workflow for client-facing relevance triage. It answers:

- which actors are relevant to a client sector
- which actors have sector or geography evidence
- which actors have recent ATT&CK campaign context
- why the actor was ranked
- which source supports the claim

The initial local sync source is MISP Galaxy threat actors. AdversaryGraph stores
observations locally, including targeted sectors, CFR target categories, suspected
victim geographies, origin metadata, motivations, aliases, and references.

Workflow:

1. Open Sector Intel.
2. Click Sync MISP Galaxy.
3. Select client sector.
4. Add optional region or geography.
5. Add environment keywords such as cloud, Kubernetes, Microsoft 365, OT, or VPN.
6. Select quarter, year, or two-year activity window.
7. Review ranked actors, reasons, and evidence.

The scoring combines:

- direct sector evidence
- broad private-sector evidence
- region/geography evidence
- recent ATT&CK campaign activity
- ATT&CK technique depth
- source confidence

Broad labels such as private sector are treated as weak supporting evidence. Direct
sector matches such as telecom, finance, energy, healthcare, or government carry
more weight.

## 15. IOC Intelligence

IOC Intelligence adds source-backed observables to actor profiles. ATT&CK provides
TTP and campaign relationships, but it does not provide live indicators. AdversaryGraph
therefore stores IOCs in a separate local database with source, freshness, confidence,
and evidence.

Initial sources:

- abuse.ch ThreatFox for recent malware-related IOCs. The recent IOC API supports
  1-7 day windows; use ThreatFox exports or custom feeds for larger windows.
- Malpedia public malware-family metadata. This sync creates `malware-family`
  enrichment records with aliases, references, and actor attribution evidence.
  These are contextual malware records, not network IOCs, and do not require an
  API key.
- AlienVault OTX actor-attributed pulses. Set `OTX_API_KEY`; AdversaryGraph searches
  actor names/aliases, imports pulse indicators, and links indicators when pulse
  adversary/title/tags match the actor.
- custom or personal JSON, CSV, and TXT IOC feeds
- manual JSON import for report, MISP, OpenCTI, or vendor CTI extracts

Before syncing ThreatFox, set:

```bash
THREATFOX_AUTH_KEY=your_abusech_auth_key
AUTO_THREATFOX_SYNC_ON_STARTUP=true
AUTO_THREATFOX_SYNC_DAYS=7
```

When enabled, AdversaryGraph runs a non-blocking ThreatFox sync after API
startup. If `THREATFOX_AUTH_KEY` is not configured, startup continues and the
automatic sync is skipped.

Actor mapping is conservative:

- direct manual imports can set `actor_attack_id` or `actor_name`
- ThreatFox IOCs are linked only when IOC metadata contains an actor name or alias
- Malpedia malware families are linked only when family attribution, aliases, or
  references match a local ATT&CK actor name or alias
- IOC records store `technique_ids` when a source explicitly provides ATT&CK IDs
  or when IDs are found in feed metadata, OTX pulses, custom records, or uploaded
  report text
- each IOC keeps source URL, first/last seen, confidence, TLP, malware family, tags,
  and the relationship evidence

Workflow:

1. Open ATT&CK Group Library.
2. Select an actor.
3. Open the IOCs tab.
4. Click Sync ThreatFox, Sync Malpedia, add a custom feed, or import
   report-backed IOCs through the API.
5. Review current IOCs, add IOC-linked TTPs to `My TTPs`, show IOC-linked TTPs
   on the matrix, and export CSV when needed.

Custom JSON/CSV feeds can include:

```text
value, type, actor_attack_id, actor_name, malware_family, campaign,
technique_ids, source_url, first_seen, last_seen, confidence, tlp, tags, description
```

TXT feeds are parsed as one IOC per line. AdversaryGraph infers basic types such as
IPv4, URL, domain, email, MD5, SHA1, and SHA256.

API:

```text
GET  /api/ioc/sources
POST /api/ioc/sources
POST /api/sync/ioc?days=7
POST /api/ioc/sync/threatfox?days=7
POST /api/ioc/sync/malpedia
POST /api/ioc/sync/otx
POST /api/ioc/sync/{source_id}
POST /api/ioc/import
POST /api/ioc/report
GET  /api/ioc/actors/counts?actor_ids=G0049
GET  /api/ioc/actors/G0049?days=180&active_only=true
GET  /api/ioc/actors/G0049/summary?days=180
GET  /api/ioc/actors/G0049/export.csv?days=180&active_only=true
```

## 16. VirusTotal IOC Lookup

VirusTotal Lookup checks one IOC at a time and turns the response into a
structured analyst view. It is an on-demand enrichment workflow and does not
store the VirusTotal response in the local IOC database.

Configure:

```env
VIRUSTOTAL_API_KEY=...
```

Open:

```text
http://localhost:3000/virustotal
```

Supported inputs:

- IP address
- domain
- URL
- MD5
- SHA1
- SHA256

The page displays:

- malicious, suspicious, harmless, and undetected verdict counts
- selected engine detections
- VirusTotal community votes, object names, tags, and threat labels
- crowdsourced YARA, IDS, and Sigma rule metadata
- sandbox verdicts and malware names when VT returns them
- DNS records, resolutions, WHOIS, ASN, registrar, and network metadata
- ATT&CK technique IDs found in VirusTotal object attributes or behavior MITRE trees
- evidence snippets explaining why each TTP was extracted
- local adversary matches when VT labels, tags, filenames, rule text, sandbox
  verdicts, malware config, or behavior context match ATT&CK group names or aliases
- evidence snippets explaining why each adversary was linked

Available actions:

- `Add to My TTPs`
- `Show on matrix`
- `Actor page`
- `Overlay actor`
- `Add actor TTPs`

## 17. Reference Book

The embedded reference book provides additional detection and anomaly context.

Use it from:

- technique detail panels
- Navigator
- actor pages
- reference links

The reference book supports paragraph-level links into relevant defensive
guidance.

## 18. Operations And Pipeline

The Operations and Pipeline areas provide a working structure for future
investigation management and intake workflows.

Current capabilities include:

- investigation records
- intake records
- detection candidates
- tracked actor records
- collection source/run models
- observable extraction
- audit-event structure
- STIX/MISP/ATLAS import endpoints for normalized report intake

Treat these as analyst workflow scaffolding and integration points.

## 19. Exports

### PDF Report

![PDF export action](assets/adversarygraph-v2/22-62_zstQMYPoqj4kSTn4nBg.webp)

From AI Analysis:

- provider/model metadata
- domain
- summary
- extracted techniques
- evidence
- group similarity leads
- tactic coverage

![Stored report PDF actions](assets/adversarygraph-v2/32-oyHjzN-tAx7Lx19Xg0IPyA.webp)

### STIX/OpenCTI

From AI Analysis:

```text
GET /api/export/analysis/{session_id}/stix
```

The STIX bundle contains:

- `report`
- ATT&CK `attack-pattern` objects
- optional `intrusion-set` objects for similarity leads
- `x_adversarygraph_*` custom metadata. These legacy STIX custom fields are kept for compatibility with existing exports after the AdversaryGraph rename.

This is not an IOC export. It is designed for report/TTP workflows in OpenCTI.
Similarity leads are not attribution.

![STIX/OpenCTI export](assets/adversarygraph-v2/23-XfbZTKCAGTSArnhi3tiMOA.webp)

### ATT&CK Navigator Layer

From Navigator:

- selected techniques
- ATT&CK domain
- Navigator-compatible JSON

### Layer PDF

From Navigator:

- selected techniques
- tactic/platform metadata
- printable working-layer summary

![ATT&CK Navigator export controls](assets/adversarygraph-v2/24-m1Zh30Hm7e6wmzZq1Mjdog.webp)

## 20. API Overview

Common endpoints:

![FastAPI Swagger documentation](assets/adversarygraph-v2/13-CsGSK7APVQvnvTDCLxXKNA.webp)

```text
GET  /api/health
GET  /api/attack/versions
GET  /api/attack/techniques
GET  /api/attack/techniques/{attack_id}
GET  /api/apt/groups
GET  /api/apt/groups/{group_id}
POST /api/apt/compare
GET  /api/apt/campaigns
POST /api/apt/campaigns/compare
POST /api/analyze
POST /api/analyze/stream
GET  /api/analyze/sessions
GET  /api/analyze/{session_id}
PATCH /api/analyze/sessions/{session_id}/techniques/{attack_id}/review
GET  /api/export/analysis/{session_id}
GET  /api/export/analysis/{session_id}/stix
POST /api/export/layer
GET  /api/sync/status
POST /api/sync/trigger
POST /api/sync/dynamic-db
GET  /api/sector/sources
GET  /api/sector/relevance
GET  /api/ioc/sources
POST /api/ioc/sync/threatfox
POST /api/ioc/import
GET  /api/ioc/actors/{actor_id}
```

![API terminal output and health checks](assets/adversarygraph-v2/09-z711T5SOrORpjITlM2IY9A.webp)

![Docker Compose startup logs](assets/adversarygraph-v2/11-z4L2KcZIixQjdkrcBt8OlA.webp)

## 21. Analyst Review Rules

![Practical attribution workflow](assets/adversarygraph-v2/31-JDE0azpONj0OVW95p9yZkg.webp)

Use these rules before promoting output:

- ATT&CK overlap is not attribution.
- Similarity scores are leads, not conclusions.
- Actor names in source text do not prove actor activity.
- Tool names do not automatically imply techniques.
- Evidence must describe behavior.
- Prefer sub-techniques when evidence supports them.
- Reject mappings without behavioral evidence.
- Document uncertainty in final reporting.

## 22. Privacy And Deployment Boundaries

Do not upload confidential reports into public demos.

For private analysis:

- self-host the Docker stack
- use local LLM mode or a provider with acceptable retention terms
- restrict network access
- place the app behind TLS and authentication
- define retention policy for uploads, raw responses, and exports
- back up PostgreSQL if report history matters

## 23. Recommended End-to-End Workflow

1. Start with a public or authorized report.
2. Run AI Analysis.
3. Review every extracted mapping.
4. Accept only evidence-backed TTPs.
5. Inject accepted TTPs into Navigator.
6. Compare against groups.
7. Compare against campaigns.
8. Compare against previous reports.
9. Review detection gaps.
10. Export PDF for analyst handoff.
11. Export STIX/OpenCTI if promoting to a CTI platform.
12. Record uncertainty and avoid attribution claims unless supported by
    independent evidence.

## 24. Visual Appendix

The following images are the screenshots, diagrams, and infographics used in
the published AdversaryGraph v2.0 article and retained here as local project
assets.

![AdversaryGraph v2.0 cover](assets/adversarygraph-v2/01-31Nq2VMJ9Mm9lgryHGJRQQ.webp)

![Problem overview](assets/adversarygraph-v2/02-69nMwI7Xj8eNIWHv_C_KVg.webp)

![AdversaryGraph pages overview](assets/adversarygraph-v2/03-7jquz_YKO0Odni3r3InzYw.webp)

![Discover dashboard](assets/adversarygraph-v2/04-VAfpLRWhfkB0pwRR5C4Nlw.webp)

![AI Analysis provider panel](assets/adversarygraph-v2/05-Up-LNxuga22bScwyZiFuHA.webp)

![Navigator matrix](assets/adversarygraph-v2/06-4zLLN71CBFHIMCEPOrTxmw.webp)

![ATT&CK Group Library](assets/adversarygraph-v2/07-Dw7KTqHRijCEkYvUrdBMbQ.webp)

![Group vs Group comparison](assets/adversarygraph-v2/08-07j05Kn78RJY96S3Ga4IVQ.webp)

![Terminal command output](assets/adversarygraph-v2/09-z711T5SOrORpjITlM2IY9A.webp)

![Architecture infographic](assets/adversarygraph-v2/10-a6c9YTdIktlPk1w0FRQHaA.webp)

![Docker startup logs](assets/adversarygraph-v2/11-z4L2KcZIixQjdkrcBt8OlA.webp)

![Discover matrix view](assets/adversarygraph-v2/12-l_EPylZmZEnAaDF6JjQE4w.webp)

![FastAPI Swagger API documentation](assets/adversarygraph-v2/13-CsGSK7APVQvnvTDCLxXKNA.webp)

![Local LLM provider selection](assets/adversarygraph-v2/14-EsC2UAT23n0xRDPv29oEWg.webp)

![AI Analysis extracted JSON](assets/adversarygraph-v2/15-89fT-TuOac6OMSNdZ61vag.webp)

![APT match tab](assets/adversarygraph-v2/16-FpAXPkiL1j3fiuOkL7tp8A.webp)

![DFIR Examples list](assets/adversarygraph-v2/17-aSqu_irokLlGQa1Njwa0fQ.webp)

![DFIR report analysis workflow](assets/adversarygraph-v2/18-RL5VY8-RMrIQv_SIZpwPQQ.webp)

![Raw analysis response](assets/adversarygraph-v2/19-T8D25vI8Mt2T7iWmqEJkfA.webp)

![Navigator selected layer](assets/adversarygraph-v2/20-q9LHKlOmbS1119qTlPKjIA.webp)

![Navigator overlay detail](assets/adversarygraph-v2/21-QkMDTHSy82_j4PA96Q3j6A.webp)

![PDF export control](assets/adversarygraph-v2/22-62_zstQMYPoqj4kSTn4nBg.webp)

![STIX/OpenCTI export flow](assets/adversarygraph-v2/23-XfbZTKCAGTSArnhi3tiMOA.webp)

![ATT&CK Navigator export controls](assets/adversarygraph-v2/24-m1Zh30Hm7e6wmzZq1Mjdog.webp)

![Reference Sync status](assets/adversarygraph-v2/25-lKoiwInK4AuBHDFSINWekA.webp)

![Compare mode landing](assets/adversarygraph-v2/26-aJW4II93D-bLqFMexDlW1g.webp)

![Group comparison graph](assets/adversarygraph-v2/27-_Dlqijzjnt_Ehr1ULHPmrg.webp)

![Tactic coverage chart](assets/adversarygraph-v2/28-lLkb-oRUX5Tns2S85SS16g.webp)

![Campaign comparison](assets/adversarygraph-v2/29-0dTCvSgZ4dMeQDXkbutXPA.webp)

![Stored report comparison](assets/adversarygraph-v2/30-ecTDnydMYwWX8-Ncuk8GfQ.webp)

![Practical attribution workflow infographic](assets/adversarygraph-v2/31-JDE0azpONj0OVW95p9yZkg.webp)

![Previous report PDF actions](assets/adversarygraph-v2/32-oyHjzN-tAx7Lx19Xg0IPyA.webp)

![Review status controls](assets/adversarygraph-v2/33-Rai3eOrk1Upsd4zeHxtroA.webp)

![Domain and selected TTP controls](assets/adversarygraph-v2/34-lp9MmZunILgId0X7JHQVbw.webp)
