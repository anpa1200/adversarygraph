# ThreatMapper

**AI-assisted CTI-to-detection workbench for MITRE ATT&CK mapping and detection-gap analysis.**

[![CI](https://github.com/anpa1200/threatmapper/actions/workflows/ci.yml/badge.svg)](https://github.com/anpa1200/threatmapper/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v2.0.0-blue)](VERSION)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Security policy](https://img.shields.io/badge/security-policy-blue)](SECURITY.md)
[![Roadmap](https://img.shields.io/badge/roadmap-public-blue)](ROADMAP.md)
[![External submissions](https://img.shields.io/badge/External%20submissions-submitted-yellow)](DISCOVERY.md)
[![Accepted upstream](https://img.shields.io/badge/Accepted%20upstream-pending-lightgrey)](DISCOVERY.md)
[![Awesome Threat Intelligence](https://img.shields.io/badge/awesome--threat--intelligence-submitted-yellow)](https://github.com/hslatman/awesome-threat-intelligence/pull/385)
[![Threat Hunting](https://img.shields.io/badge/awesome--threat--hunting-submitted-yellow)](https://github.com/threat-hunting/awesome_Threat-Hunting/pull/5)

**Current release: v2.0.0 · [Live Intelligence Workspace](https://1200km.com/threat-matrix/) · [Documentation & Usage Guide](https://1200km.com/threatmapper-docs/) · [Full v2 Guide](docs/full-guide-v2.md) · [Medium Walkthrough](https://medium.com/@1200km/threatmapper-i-built-a-self-hosted-ai-threat-intelligence-platform-heres-how-to-use-it-0aa7673e6bd8)**

ThreatMapper AI is a self-hosted CTI-to-detection workbench for mapping threat reports to MITRE ATT&CK, comparing TTP overlap with known groups and campaigns, identifying detection gaps, and exporting analyst-ready outputs.

**Live Web Workspace:** https://1200km.com/threat-matrix/

**Project Hub:** https://1200km.com/threatmapper/

**Documentation:** https://1200km.com/threatmapper-docs/

**Medium Walkthrough:** https://medium.com/@1200km/threatmapper-i-built-a-self-hosted-ai-threat-intelligence-platform-heres-how-to-use-it-0aa7673e6bd8

> **Validation and attribution limitation:** ThreatMapper assists analysts but does not replace analyst validation. LLM-generated mappings may contain false positives, false negatives, or ambiguous technique assignments. Group/campaign similarity is based on TTP overlap and is an investigation lead, not attribution proof.

## Project Maturity Evidence

ThreatMapper v2.0.0 publishes the operational evidence expected from a serious self-hosted CTI tool:

| Area | Evidence |
|---|---|
| Installability | [Quickstart](docs/quickstart.md), Docker Compose deployment, `.env.example` |
| Analyst documentation | [Full v2 guide](docs/full-guide-v2.md), [user guide](docs/user-guide.md), [comparison](docs/comparison.md), [limitations](docs/limitations.md) |
| Operations | [Admin guide](docs/admin-guide.md), [security model](docs/security-model.md), [security policy](SECURITY.md) |
| Quality | Backend unit/integration tests, frontend build, [CI workflow](.github/workflows/ci.yml) |
| Reviewability | [Demo dataset](docs/demo-dataset/public-report-excerpt.md), [expected mappings](docs/demo-dataset/expected-mappings.json), [sample outputs](docs/sample-outputs/) |
| Validation | [Evaluation plan](docs/validation/evaluation-plan.md), [mapping review rubric](docs/validation/mapping-review-rubric.md) |
| Maintenance | [Maintainers](MAINTAINERS.md), [roadmap](ROADMAP.md), [changelog](CHANGELOG.md), [contributing guide](CONTRIBUTING.md) |
| Production readiness | [Production readiness tracker](docs/production-readiness.md) |

The current documentation is intended to make external review practical rather than promotional.

## Public Demo Privacy Note

The public Web workspace is intended for exploration. Do not upload confidential, customer-sensitive, classified, or internal reports into public demos or third-party environments. Use the self-hosted Docker deployment for private analysis.

## Validation and Limitations

ThreatMapper assists analysts but does not replace analyst validation. LLM-generated ATT&CK mappings may include false positives, false negatives, or ambiguous technique assignments. Group and campaign similarity is based on TTP overlap and should be treated as an investigation lead, not attribution proof.

## Screenshots And Visual Evidence

Screenshot evidence is preserved in [`docs/screenshots/`](docs/screenshots/).
The set covers the public ATT&CK matrix workspace, group overlay workflows,
analysis views, report/evidence review, and ecosystem navigation from the
companion walkthrough.

Demo workflow video:
[`DFIR report download to AI analysis and comparison`](docs/demo-videos/dfir-report-ai-analysis-compare.mp4)
shows the end-to-end flow from indexed public report examples to local PDF
upload, streamed ATT&CK extraction, and selected TTP review. A GIF version is
also available at [`docs/demo-videos/dfir-report-ai-analysis-compare.gif`](docs/demo-videos/dfir-report-ai-analysis-compare.gif).

| Matrix and actor workflow | Analysis and review workflow |
|---|---|
| ![ThreatMapper ATT&CK matrix workspace](docs/screenshots/02_1x07j05Kn78RJY96S3Ga4IVQ.png) | ![ThreatMapper analysis workflow](docs/screenshots/10_1xCsGSK7APVQvnvTDCLxXKNA.png) |
| ![ThreatMapper actor overlay](docs/screenshots/13_1xFpAXPkiL1j3fiuOkL7tp8A.png) | ![ThreatMapper evidence review](docs/screenshots/20_1xVAfpLRWhfkB0pwRR5C4Nlw.png) |

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Navigator](#navigator)
  - [AI Analysis](#ai-analysis)
  - [ATT&CK Group Library](#attck-group-library)
  - [Compare](#compare)
  - [Export](#export)
  - [MITRE Sync](#mitre-sync)
  - [Reference Book and Exact TTP Crosslinks](#reference-book-and-exact-ttp-crosslinks)
- [Two-Database Architecture](#two-database-architecture)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Development](#development)
- [Deployment](#deployment)
- [Tech Stack](#tech-stack)
- [Changelog](#changelog)

---

## Features

| Module | Capability |
|---|---|
| **Navigator** | Full ATT&CK matrix (Enterprise, Mobile, ICS) with D3.js zoom/pan, sub-technique expansion, dual-layer colouring |
| **Threat Actor Library** | Currently ingested MITRE ATT&CK group profiles, aliases, techniques, and named campaign relationships |
| **AI Analysis** | Upload PDF/DOCX/TXT or paste text → streamed LLM extraction of ATT&CK mapping candidates via Claude, OpenAI, Gemini, or a local OpenAI-compatible LLM; results saved to Reports Library (DB 2) |
| **Compare — Groups** | Jaccard similarity ranking of your TTPs vs currently ingested group profiles; visual matrix diff, tactic breakdown, gap analysis |
| **Compare — Campaigns** | Jaccard similarity ranking of your TTPs vs every named MITRE campaign (e.g. SolarWinds C0024, Operation Ghost C0023) |
| **Compare — Reports** | Browse stored AI analyses (DB 2); re-run group-similarity comparison without re-calling the LLM |
| **DFIR Examples** | Indexed public DFIR Report examples with TTP/actor metadata and a local PDF workflow for private AI analysis |
| **Export** | ATT&CK Navigator JSON layers, PDF reports, plain JSON, and STIX 2.1 bundles for OpenCTI import |
| **Reference Sync** | Manual and scheduled MITRE ATT&CK sync for Enterprise, Mobile, and ICS with status reporting and stale-data indicators |
| **Anomaly Detection Reference Book** | Docker-served, autonomously synchronized reference catalogs with exact paragraph-level links from every mapped matrix TTP |
| **Intelligence Pipeline** | Scheduled reviewed RSS intake, STIX/TAXII, MISP and ATLAS imports, normalized observables, public enrichment, team audit trail |
| **Detection Studio** | Versioned Sigma, KQL, SPL and EQL skeleton generation with structural validation and explicit analyst-review placeholders |
| **Operations** | Investigations, evidence graphs, report intake, tracked actor changes, and detection engineering lifecycle |

---

## Architecture

## Web vs Docker

**ThreatMapper Web** is the public browser-native workspace for ATT&CK exploration, manual layers, group overlays and comparisons, local workspaces, ecosystem research, coverage-gap analysis, and browser-generated exports. It does not perform LLM report extraction or backend private-report storage.

**ThreatMapper Docker** is the full self-hosted platform for provider-configured AI extraction, private PostgreSQL-backed analyses, campaigns, APIs, PDF reports, detection-rule workflows, and scheduled ATT&CK synchronization.

ThreatMapper is self-hosted. In Docker mode, report content is sent only to the LLM provider configured by the operator. For fully private analysis, use a local or private LLM gateway. The public Web workspace does not perform LLM report extraction or backend report storage.

The Docker deployment gives the operator control over storage, networking, and provider configuration. Trusted-header authentication and roles are available when configured, but internet-facing deployments still require TLS, an authenticating reverse proxy, restricted network exposure, backups, retention controls, and secrets management.

```
┌──────────────────────────────────────────────────────────────────┐
│                         Docker Compose                           │
├────────────────┬───────────────┬──────────────┬─────────────────┤
│  React / Vite  │   FastAPI     │  PostgreSQL  │  Redis + Celery │
│  (port 3000)   │  (port 8000)  │     16       │  worker + beat  │
│                │               │              │                 │
│  Vite proxy    │  SQLAlchemy   │  DB 1: ATT&CK│  daily MITRE    │
│  /api → :8000  │  async ORM    │  DB 2: Reports  sync job       │
└────────────────┴───────────────┴──────────────┴─────────────────┘
```

**Backend** — Python 3.12, FastAPI, SQLAlchemy 2.x (async), Celery  
**Frontend** — React 18, TypeScript, Vite, D3.js, Tailwind CSS, Zustand  
**Database** — PostgreSQL 16 with JSONB for ATT&CK STIX data  
**Queue** — Redis + Celery (daily MITRE sync at 03:00 UTC)

### Data flow

```
User uploads report
        │
        ▼
  _read_input()          ← stream with 50 MB byte-cap, size-check before buffer
        │
        ▼
  LLMAdapter.extract()   ← Claude / OpenAI / Gemini / Local
        │
        ▼
  _parse_response()      ← JSON extraction with raw_decode fallback
        │
        ▼
  _rank_apt_groups()     ← Jaccard TTP overlap vs group profiles in DB 1
        │
        ▼
  AnalysisResult → DB 2  ← session + name, techniques, similarity leads, domain
        │
        ▼
  Frontend renders       ← techniques table, group similarity ranking, Navigator injection
```

### Two-database model

| Database | What it holds | Key tables |
|---|---|---|
| **DB 1 (MITRE)** | ATT&CK groups, campaigns, techniques, relationships — ingested from official STIX bundles | `apt_groups`, `campaigns`, `campaign_techniques`, `apt_group_campaigns`, `techniques` |
| **DB 2 (Reports)** | Every AI analysis you run: extracted techniques, summary, group-similarity leads, name, domain | `analysis_sessions`, `analysis_results` |

---

## Quick Start

### Prerequisites

- Docker + Docker Compose (v2)
- API key for at least one cloud LLM provider, or a local OpenAI-compatible LLM endpoint

### 1 — Clone and configure

```bash
git clone https://github.com/anpa1200/threatmapper.git
cd threatmapper
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
# Optional cloud providers
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1
GEMINI_API_KEY=AIza...

# Optional local provider: Ollama / LM Studio / LocalAI / vLLM with OpenAI-compatible API
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_API_KEY=local
LOCAL_LLM_MODEL=llama3.1:8b

# Database (defaults are fine for local use)
DB_NAME=threatmapper
DB_USER=tm_user
DB_PASS=changeme_strong_password

# ATT&CK domains to ingest (comma-separated)
ATTCK_DOMAINS=enterprise-attack,mobile-attack,ics-attack

LOG_LEVEL=info
```

> You only need one working provider. Cloud API keys can be left blank if you use the local provider.
>
> **You must create `.env` before running `docker compose up`.** Without it, cloud API keys are empty and local-provider defaults are used.

For Ollama on the same host:

```bash
ollama pull llama3.1:8b
ollama serve
```

Keep:

```env
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_MODEL=llama3.1:8b
```

For LM Studio, start its local OpenAI-compatible server and use:

```env
LOCAL_LLM_BASE_URL=http://host.docker.internal:1234/v1
LOCAL_LLM_MODEL=<model-name-shown-by-LM-Studio>
```

### 2 — Start

```bash
docker compose up
```

**First startup takes 5–15 minutes.** The API container automatically:
1. Runs `create_tables()` to initialise the PostgreSQL schema
2. Downloads the latest ATT&CK STIX bundles from MITRE's GitHub (~105 MB total for all three domains)
3. Parses the STIX 2.1 JSON directly (no third-party ATT&CK library — Python 3.12 compatible)
4. Upserts tactics, techniques, groups, campaigns, and all relationships into PostgreSQL

The `atlas-builder` container builds the embedded reference-book snapshot immediately,
then synchronizes it with the standalone Anomaly Detection Atlas repository every hour.
Set `ATLAS_SYNC_INTERVAL=0` to disable remote synchronization. Run `make sync-atlas`
to import unpushed changes from a local sibling `anomaly-detection-atlas` checkout.

Watch progress:

```bash
docker compose logs -f api
```

Expected output (v19.1):

```
Parsing enterprise-attack-19.1.json ...
  Parsed: current tactics, techniques, groups, campaigns, and relationships
  Ingested 15 tactics
  Ingested techniques from the selected ATT&CK release
  Ingested groups from the selected ATT&CK release
  Ingested campaigns from the selected ATT&CK release
  Ingested campaign-technique and group-campaign attribution links
Finished ingesting enterprise-attack v19.1
```

### 3 — Open

| Service | URL |
|---|---|
| **Frontend** | http://localhost:3000 |
| **Reference book** | http://localhost:3001/anomaly-detection-atlas/ |
| **API docs** | http://localhost:8000/docs |
| **Health** | http://localhost:8000/api/health |
| **Reference sync** | http://localhost:3000/sync |

---

## Usage Guide

### Navigator

The central workspace. The full ATT&CK matrix renders as a colour-coded heatmap.

#### Basic interaction

| Action | How |
|---|---|
| Zoom / pan | Scroll to zoom, drag to pan. Double-click resets view. |
| Select a technique | Click any cell — turns red, added to your TTP layer |
| Expand sub-techniques | Click the ▶ arrow on any parent cell |
| Open detail panel | Click a cell to open the right-side panel (full description, detection notes, data sources, exact reference paragraphs, AI assistant) |
| Search | Type in the search box to filter by name or ATT&CK ID |
| Filter by platform | Use the platform dropdown (Windows, Linux, macOS, Cloud, etc.) |
| Filter by tactic | Use the tactic dropdown to focus on a specific kill-chain phase |

#### Layer toolbar

| Button | Action |
|---|---|
| ↑ Import layer | Load an existing ATT&CK Navigator `.json` layer |
| ↓ Navigator layer | Export your TTPs + overlay as ATT&CK Navigator JSON |
| ↓ PDF | Export current layer as a formatted PDF report |
| Expand all / Collapse all | Toggle sub-technique visibility |
| Clear my TTPs | Reset your selection |
| Clear overlay | Remove the group-profile overlay |

#### Colour coding

| Colour | Meaning |
|---|---|
| Red `#e94560` | In your TTP layer |
| Blue `#3b82f6` | In the group-profile overlay only |
| Amber `#f59e0b` | In both layers (shared TTPs) |
| Dark | Not selected |

#### AI Assistant

Click any technique to open the detail panel with an embedded chat. The full ATT&CK description for the selected technique is already in context. Example prompts:

- *"What are the most common detections for this technique?"*
- *"Write a SIGMA rule skeleton for T1059.001"*
- *"What ATT&CK groups use this in combination with lateral movement?"*

### Reference Book and Exact TTP Crosslinks

ThreatMapper integrates the complete Anomaly Detection Atlas as an autonomous Docker service.
Click **Reference Book** in the sidebar to open the full documentation site.

Each matrix technique panel loads `ttp-reference-index.json` and shows links only to exact matching
paragraphs or table rows. A technique can link to multiple relevant activity descriptions, basic
detection rules, and statistical-anomaly mappings. The links use stable generated anchors such as:

```text
http://localhost:3001/anomaly-detection-atlas/attack-basic-detection-rule-catalog/#ttp-t1059-001
http://localhost:3001/anomaly-detection-atlas/attack-statistical-anomaly-mapping/#ttp-t1030
```

The embedded snapshot makes the book usable without a successful remote synchronization. The
`atlas-builder` service checks the standalone atlas repository every hour, regenerates exact TTP
anchors and the crosslink index, then atomically publishes the updated Docusaurus build.

Manual local synchronization:

```bash
make sync-atlas
docker compose up -d --build atlas-builder atlas-docs frontend
```

---

### AI Analysis

Analyse threat intelligence documents and automatically map every observable behaviour to ATT&CK. Each completed analysis is saved to the **Reports Library (DB 2)**.

#### Step-by-step

1. Click **Analyze** in the sidebar
2. Select an LLM provider and optionally specify a model
3. Choose a domain (`enterprise-attack`, `mobile-attack`, or `ics-attack`)
4. Optionally enter a **name** for this analysis (shown in the Reports Library later)
5. Either paste text or upload a file (PDF, DOCX, TXT — up to 50 MB)
6. Click **Analyse with AI**
7. Watch the live SSE token stream as the model thinks
8. Review the three tabs:

| Tab | Content |
|---|---|
| **Techniques** | ATT&CK technique mappings with confidence score, tactic, and evidence snippet |
| **Group Similarity Leads** | Top group profiles ranked by Jaccard TTP overlap |
| **Raw Response** | Full LLM JSON output for debugging |

9. Click **→ Inject into Navigator** to push all extracted techniques into your layer

#### Confidence score guide

| Score | Meaning |
|---|---|
| 90–100 % | Explicitly stated in the text |
| 70–89 % | Strongly implied |
| 40–69 % | Weakly implied or inferred from context |
| < 40 % | Speculative — treat with caution |

#### Supported file types

| Type | Notes |
|---|---|
| `.pdf` | Text extraction via PyMuPDF |
| `.docx` | Paragraphs and table cells extracted via python-docx |
| `.txt` / plain text | UTF-8, latin-1, CP1252 auto-detected |

Files are truncated at 120,000 characters before being sent to the LLM.

---

### ATT&CK Group Library

Browse the threat groups in the currently ingested ATT&CK release. Each group has two tabs:

#### Techniques tab

- All known techniques with ATT&CK IDs, tactic, and use description
- **Add all to my TTPs** — bulk-load every technique into your Navigator layer
- **Overlay on Navigator** — show the group's TTPs as a blue overlay on the matrix

#### Campaigns tab (DB 1)

Named operations attributed to this group, parsed from MITRE ATT&CK STIX data.

Each campaign card shows:
- ATT&CK campaign ID (e.g. C0024), name, and date range
- Technique count for that specific operation
- Expand to see the full technique list with tactic tags
- **Add to my TTPs** — load this campaign's specific TTP fingerprint into Navigator

> **Why campaigns matter:** A group's aggregate profile is the union of all operations over years. A campaign profile is specific to one attack. Matching against C0024 (SolarWinds Compromise) at 45% similarity is a more specific lead than matching against G0016 (APT29) at 15%.

---

### Compare

Rank ATT&CK groups and campaigns against your TTPs using Jaccard similarity.

**Jaccard similarity** = `|shared techniques| / |union of all techniques|`

Use the **mode switcher** at the top of the Compare page to choose what to compare against:

#### Mode: Groups (DB 1)

Rank every ATT&CK group against your current Navigator selection.

| Detail tab | Content |
|---|---|
| **Overview** | Similarity score, shared techniques (amber chips), your-only techniques |
| **Tactic Breakdown** | Stacked bar per kill-chain phase: shared / user-only / group-profile-only |
| **Visual Diff** | Compact matrix colour-strip showing the full overlap |
| **Gap Analysis** | Every technique in the group's profile not in your layer — your detection backlog |

**Actions:**
- **Overlay in Navigator** — visualise the overlap on the full matrix
- **↓ PDF Report** — export a formatted comparison report

#### Mode: Campaigns (DB 1)

Rank named campaigns from the currently ingested ATT&CK release against your current Navigator selection.

The detail panel shows:
- Similarity score, shared techniques highlighted in purple
- Full campaign technique list with overlap indicators
- Attribution (which group conducted this campaign)
- Date range of the campaign

#### Mode: Reports (DB 2)

Browse your stored AI analysis sessions. Click any report body to see which group and campaign profiles have the strongest TTP overlap with its extracted profile — without re-running the expensive LLM call.

Use cases:
- **Retrospective TTP-overlap review** after a new ATT&CK version is released
- **Cross-incident correlation** across multiple saved reports
- **Environmental profiling** — which groups keep appearing across your incident set

**Per-session actions:**
- **↓ PDF** — download the full analysis PDF for that session at any time
- **↓ STIX/OpenCTI** — download a STIX 2.1 bundle containing the report, ATT&CK attack-patterns, and similarity-lead intrusion sets for OpenCTI import
- **✕ Remove** — delete the session from DB 2 (browser confirm required; list refreshes automatically)

---

### Export

#### Analysis PDF

From **Analyze**, click **Download PDF** on any completed analysis. Includes:
- Cover page with provider, model, domain, session ID, timestamp
- Executive summary (AI-generated)
- Extracted techniques table sorted by confidence
- Group-similarity section with top Jaccard-overlap leads
- Tactic coverage breakdown

#### STIX 2.1 / OpenCTI Export

From **Analyze**, click **↓ STIX/OpenCTI** on a completed analysis to download a
STIX 2.1 bundle. The bundle is designed for OpenCTI import and contains:

- a STIX `report` for the ThreatMapper analysis session
- ATT&CK `attack-pattern` objects for extracted TTPs
- optional `intrusion-set` objects for group-similarity leads
- ThreatMapper custom metadata for confidence, review status, evidence source, similarity score, model, provider, and ATT&CK domain

ThreatMapper does not export IOCs here. Group matches are exported as
TTP-overlap investigation leads, not attribution claims.

#### Navigator layer PDF

From **Navigator**, click **↓ PDF** in the toolbar. Lists all techniques in your current layer with tactics and platforms.

#### ATT&CK Navigator JSON

Click **↓ Navigator layer** to download a `.json` file compatible with [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

---

### MITRE Sync

ThreatMapper tracks new ATT&CK releases automatically.

#### Automatic sync (daily)

A Celery Beat scheduler runs `check_and_sync` every day at 03:00 UTC. It queries MITRE's GitHub repository for new bundle versions and ingests updates without downtime.

#### Staleness indicator

The sidebar footer shows:
- **Green dot** — all domains are on the latest version
- **Amber pulse** — at least one domain has a newer version available

#### Manual sync

```bash
# Via API
curl -X POST http://localhost:8000/api/sync/trigger

# Check status
curl http://localhost:8000/api/sync/status
```

---

## Two-Database Architecture

### DB 1 — MITRE ATT&CK (read-only reference data)

Populated from MITRE's official STIX 2.1 bundles on startup and on each sync. Contains:

- **Groups** — named threat actors with aggregate TTP profiles from the ingested release
- **Campaigns** — named operations with per-operation TTP profiles from the ingested release
- **Attribution links** — which group conducted which campaign (`attributed-to` relationships)
- **Technique usage** — the specific techniques observed in each group/campaign with use descriptions

Built on the currently ingested MITRE ATT&CK dataset. Counts depend on the selected ATT&CK domain and ATT&CK release.

| Domain | Groups | Campaigns | Techniques |
|---|---|---|---|
| Enterprise | Dynamic | Dynamic | Dynamic |
| ICS | Dynamic | Dynamic | Dynamic |
| Mobile | Dynamic | Dynamic | Dynamic |

### DB 2 — User Report Sessions (append-only)

Created by every AI Analysis you run. Each session stores:

- `name` — the label you gave when uploading (or the filename)
- `domain` — which ATT&CK domain was used
- `provider` / `model` — which LLM was used
- `extracted_techniques` — JSON array of `{attack_id, name, tactic, confidence, evidence}`
- `apt_matches` — JSON array of the Jaccard ranking computed at analysis time
- `summary` — the AI-generated summary
- `status` — `processing` / `completed` / `failed`

Sessions in DB 2 can be re-compared at any time via `POST /api/analyze/sessions/{id}/compare` — this re-runs Jaccard against the *current* DB 1 (useful after a new ATT&CK version has been ingested).

---

## API Reference

Full interactive documentation at **http://localhost:8000/docs**.

All 21 registered routes:

### ATT&CK Data

```
GET  /api/attack/versions
GET  /api/attack/tactics?domain=enterprise-attack[&version=19.1]
GET  /api/attack/techniques?domain=enterprise-attack[&tactic=initial-access&search=phish&platform=Windows&subtechniques=true]
GET  /api/attack/techniques/{attack_id}?domain=enterprise-attack
```

### ATT&CK Group Profiles (DB 1)

```
GET  /api/apt/groups?domain=enterprise-attack[&search=APT29&version=19.1]
GET  /api/apt/groups/{attack_id}?domain=enterprise-attack
POST /api/apt/compare?domain=enterprise-attack[&top_n=10&version=19.1]
     body: { "technique_ids": ["T1566", "T1059", "T1078"] }   ← max 500 IDs
```

### Campaigns (DB 1)

```
GET  /api/apt/campaigns?domain=enterprise-attack[&group_id=G0016&search=solar&version=19.1]
GET  /api/apt/campaigns/{attack_id}?domain=enterprise-attack
POST /api/apt/campaigns/compare?domain=enterprise-attack[&top_n=20&version=19.1]
     body: { "technique_ids": ["T1566", "T1059", "T1078"] }   ← max 500 IDs
```

### Analysis

```
POST /api/analyze
     multipart: provider={claude|openai|gemini|local}, domain=enterprise-attack,
                name="My Report", text=... | file=@report.pdf

POST /api/analyze/stream          ← Server-Sent Events (same fields)

GET    /api/analyze/sessions[?limit=50&offset=0]              ← DB 2 report library
POST   /api/analyze/sessions/{session_id}/compare[?top_n=10]  ← re-run Jaccard
DELETE /api/analyze/sessions/{session_id}                     ← remove from DB 2

GET  /api/analyze/{session_id}    ← returns AnalysisOut or 202 if processing

POST /api/analyze/chat
     body: { "message": "...", "provider": "claude", "model": "...", "context": "..." }
```

> **Route order note:** `GET /analyze/sessions` must be registered before `GET /analyze/{session_id}` in the router — it is. Do not reorder these routes or the literal string `sessions` will be treated as a UUID and return 400.

#### SSE event types

| Event `type` | Payload | Meaning |
|---|---|---|
| `token` | `{"content": "..."}` | LLM token streamed in real-time |
| `result` | `{"data": AnalysisOut}` | Final parsed result |
| `error` | `{"message": "..."}` | LLM or DB failure |
| `done` | — | Chat stream completed |

### Export

```
GET  /api/export/analysis/{session_id}   → PDF download
GET  /api/export/analysis/{session_id}/stix
     → STIX 2.1 JSON bundle for OpenCTI import
POST /api/export/layer
     body: { "technique_ids": ["T1059"], "domain": "enterprise-attack" }
     → PDF download
```

### Sync

```
GET  /api/sync/status          ← source metadata, configured domains, current/latest versions
POST /api/sync/trigger         ← queue reference sync
     body: {
       "source": "mitre-attack",
       "domains": ["enterprise-attack", "mobile-attack", "ics-attack"],
       "force": false
     }
GET  /api/sync/task/{task_id}  ← poll queued sync
```

MITRE sync covers matrices, tactics, techniques, sub-techniques, APT groups,
campaigns, group-technique relationships, campaign-technique relationships,
campaign-group attribution links, and STIX external references.

### Health

```
GET  /api/health
```

---

## Configuration

All configuration is via environment variables in `.env`.

| Variable | Default | Description |
|---|---|---|
| `DB_NAME` | `threatmapper` | PostgreSQL database name |
| `DB_USER` | `tm_user` | Database user |
| `DB_PASS` | `changeme` | Database password — **change this** |
| `ANTHROPIC_API_KEY` | — | Anthropic / Claude API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4.1` | OpenAI model used when no request-level model is provided |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `LOCAL_LLM_BASE_URL` | `http://host.docker.internal:11434/v1` | OpenAI-compatible local LLM endpoint |
| `LOCAL_LLM_API_KEY` | `local` | API key placeholder for local OpenAI-compatible servers |
| `LOCAL_LLM_MODEL` | `llama3.1:8b` | Local model used when no request-level model is provided |
| `ATTCK_DOMAINS` | `enterprise-attack,mobile-attack,ics-attack` | Comma-separated domains to ingest |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warning` / `error` |

To ingest only Enterprise (faster first start):

```env
ATTCK_DOMAINS=enterprise-attack
```

---

## Development

### Project structure

```
threatmapper/
├── backend/
│   ├── app/
│   │   ├── api/routes/
│   │   │   ├── analyze.py      # /analyze, /analyze/stream, /analyze/sessions, /analyze/chat
│   │   │   ├── attack.py       # /attack/tactics, /attack/techniques
│   │   │   ├── apt.py          # /apt/groups, /apt/compare, /apt/campaigns, /apt/campaigns/compare
│   │   │   ├── export.py       # /export/analysis, /export/layer
│   │   │   └── sync.py         # /sync/status, /sync/trigger
│   │   ├── core/
│   │   │   ├── config.py       # Pydantic Settings from .env
│   │   │   └── database.py     # async engine, session factory, create_tables
│   │   ├── models/
│   │   │   ├── analysis.py     # AnalysisSession (name, domain), AnalysisResult
│   │   │   └── attack.py       # AttackVersion, Tactic, Technique, AptGroup,
│   │   │                       # Campaign, CampaignTechnique, AptGroupCampaign
│   │   ├── services/
│   │   │   ├── ai/
│   │   │   │   ├── base.py     # LLMAdapter ABC, SYSTEM_PROMPT, _parse_response (raw_decode)
│   │   │   │   ├── claude.py   # Anthropic adapter (cached client)
│   │   │   │   ├── openai.py   # OpenAI adapter (cached client)
│   │   │   │   ├── gemini.py   # Gemini adapter (cached genai instance)
│   │   │   │   └── factory.py  # get_adapter(provider, model)
│   │   │   ├── attck/
│   │   │   │   ├── downloader.py      # Fetch STIX bundles from MITRE GitHub
│   │   │   │   ├── ingestor.py        # Parse STIX 2.1, upsert groups+campaigns
│   │   │   │   └── version_checker.py
│   │   │   ├── file_parser.py  # PDF / DOCX / TXT text extraction
│   │   │   └── report_generator.py  # fpdf2 PDF builder
│   │   └── tasks/
│   │       ├── celery_app.py   # Celery + Redis config
│   │       └── sync.py         # check_and_sync Celery beat task
│   ├── main.py
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── api/client.ts       # attackApi, aptApi, reportsApi, analyzeApi, exportApi
│       ├── types/attack.ts     # TS interfaces for all DB 1 + DB 2 types
│       ├── components/
│       │   ├── Navigator/      # AttackMatrix, LayerControls, TechniquePanel, LLMChat
│       │   └── Compare/        # MatrixDiff, TacticBreakdown
│       ├── pages/
│       │   ├── Navigator.tsx
│       │   ├── APTLibrary.tsx  # Groups list + Techniques tab + Campaigns tab
│       │   ├── Analyze.tsx
│       │   └── Compare.tsx     # Mode switcher: Groups / Campaigns / Reports
│       ├── hooks/              # useAttackMatrix, useSseStream
│       └── store/              # Zustand global state (domain, version, selectedTechniques)
├── docker-compose.yml
├── Makefile
└── .env.example
```

### Makefile shortcuts

```bash
make up           # docker compose up --build
make down         # stop and remove containers
make logs         # follow api + worker logs
make shell-api    # bash into the api container
make shell-db     # psql into postgres
make ingest       # trigger ATT&CK re-ingestion manually
make reset        # tear down volumes and rebuild from scratch (destructive)
```

### Running tests

```bash
# Inside the api container (real PostgreSQL):
docker compose exec api pytest tests/ -v

# Locally (unit tests, no DB):
cd backend
pip install -r requirements.txt
PYTHONPATH=. pytest tests/unit/ -v
```

### Database schema and migrations

ThreatMapper uses SQLAlchemy `create_all()` on startup — no migration framework required for a fresh install.

If upgrading an existing deployment, apply these `ALTER TABLE` statements manually:

```sql
-- v0.2.1: stores the ATT&CK domain used for each analysis session
ALTER TABLE analysis_sessions
  ADD COLUMN IF NOT EXISTS domain VARCHAR(50) NOT NULL DEFAULT 'enterprise-attack';

-- v0.3.0: user-defined label for each report session
ALTER TABLE analysis_sessions
  ADD COLUMN IF NOT EXISTS name VARCHAR(255);

-- v0.3.0: campaigns, campaign-technique links, campaign-group attribution
-- (created automatically by create_all() if tables don't exist)
-- If upgrading a v0.2.x DB, restart the API container and it will create them.
```

### Adding a new LLM provider

1. Create `backend/app/services/ai/myprovider.py` extending `LLMAdapter`:

```python
class MyProviderAdapter(LLMAdapter):
    def __init__(self, model: str = "my-model") -> None:
        self._model = model
        self._api_client = MySDK(api_key=settings.my_provider_api_key)

    @property
    def provider(self) -> str: return "myprovider"

    @property
    def model(self) -> str: return self._model

    async def _raw_complete(self, system: str, user: str) -> str: ...
    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]: ...
```

2. Register in `factory.py`
3. Add to `ALLOWED_PROVIDERS` in `analyze.py`
4. Add to the frontend provider dropdowns in `Analyze.tsx` and `LLMChat.tsx`

---

## Deployment

### Production and Security Note

ThreatMapper is suitable for local labs, private analyst workstations, internal CTI workflows, and controlled self-hosted deployments. Internet-facing deployments require additional access control and hardening.

### Security checklist

- [ ] Set a strong `DB_PASS` in `.env`
- [ ] Never commit `.env` to git (it is in `.gitignore`)
- [ ] Do not expose PostgreSQL publicly; bind it to an internal network or localhost only
- [ ] Protect the API with a VPN, SSO, OAuth proxy, authenticating reverse proxy, or internal network controls
- [ ] Use TLS for browser and API traffic
- [ ] Restrict CORS to approved origins
- [ ] Use strong, unique secrets and rotate LLM API keys regularly
- [ ] Configure PostgreSQL backups, restore testing, retention, and deletion controls
- [ ] For any internet-facing deployment, place ThreatMapper behind nginx or Caddy with TLS and authentication
- [ ] Review trusted-header authentication and role configuration before team deployment
- [ ] API keys are read from environment variables and never stored in the database

### Scaling

- The API runs a single uvicorn worker by default. For concurrent users add `--workers 4` in `docker-compose.yml`.
- Celery workers scale horizontally — add additional `worker` service instances.
- The PostgreSQL connection pool is set to 10 connections (max 20 overflow).

## Publishing And Discovery

Use [`DISCOVERY.md`](DISCOVERY.md) for canonical links, community-specific launch
copy, newsletter pitch text, and current external submission tracking.

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend framework | FastAPI 0.115 | Async, OpenAPI auto-docs |
| ORM | SQLAlchemy 2.x (async) | asyncpg driver |
| Database | PostgreSQL 16 | JSONB for STIX arrays |
| Task queue | Celery 5.4 + Redis 7 | Daily ATT&CK sync |
| ATT&CK parsing | stdlib `json` only | No mitreattack-python; Python 3.12-compatible |
| STIX/OpenCTI export | stdlib `json` only | Report, ATT&CK attack-patterns, intrusion-set similarity leads |
| AI — Claude | `anthropic` SDK | Cached async client in `__init__` |
| AI — OpenAI | `openai` SDK | Cached client; JSON mode on non-streaming |
| AI — Gemini | `google-generativeai` | `configure()` called once in `__init__` |
| AI — Local | `openai` SDK | OpenAI-compatible local endpoint such as Ollama, LM Studio, LocalAI, or vLLM |
| File parsing | PyMuPDF (PDF), python-docx (DOCX) | Streamed with 50 MB hard cap |
| PDF reports | fpdf2 | Multi-page with tactic coverage chart |
| Frontend framework | React 18 + TypeScript | |
| Build tool | Vite 6 | |
| Visualisation | D3.js 7 | ATT&CK matrix heatmap |
| Styling | Tailwind CSS 3 | |
| State | Zustand 5 | |
| Data fetching | TanStack Query 5 | |
| Testing | pytest, pytest-asyncio, httpx | |

---

## Changelog

### v2.0.0 (2026-06-16)

**OpenCTI-ready self-hosted CTI workbench:**
- Added local LLM provider support for OpenAI-compatible endpoints such as Ollama, LM Studio, LocalAI, and vLLM
- Added STIX 2.1 export for OpenCTI import from completed AI analysis sessions
- Added DFIR Examples with indexed public report metadata, TTPs, actor mappings, and a local PDF workflow
- Added Reference Sync page and API for MITRE ATT&CK Enterprise, Mobile, and ICS status and manual sync
- Enriched ATT&CK Group Library with aliases, external references, technique evidence, tactic coverage, platform coverage, source names, and metadata
- Added cached ATT&CK bundle fallback behavior for more reliable startup and sync
- Added reviewer-facing demo video, GIF, poster, release notes, and [full v2 guide](docs/full-guide-v2.md)

### v0.7.0 (2026-06-12)

**Operational intelligence workbench:**
- Persistent campaign/investigation workspaces containing actors, TTPs, reports, evidence graph nodes/relationships, and timelines
- Analyst-reviewed CTI/IR report intake queue with source reliability and promotion/rejection states
- Tracked-actor snapshots with explainable added/removed TTP change logs
- Detection engineering lifecycle from idea and hunt through validation, production, and retirement
- Unified Operations UI and API endpoints under `/api/operations`
- Direct actor-library action to snapshot and monitor actor behavior changes

### v0.6.0 (2026-06-12)

**Web-workspace parity plus AI:**
- Added intelligence discovery dashboard and global actor/TTP/report search
- Bundled the same correlated CTI/IR report and 1200km resource indexes used by ThreatMapper Web
- Added actor report tabs and technique-level reports, practical resources, detection logic, mitigation guidance, threat-hunting hypotheses, and hunt-plan export
- Added persistent evidence, source, confidence, mapping quality, notes, and coverage maturity assessments
- Added local investigation workspaces, coverage import/visualization, detection-backlog export, shareable deep links, and investigation-report export
- Preserved Docker-only AI analysis, LLM technique assistant, private report sessions, campaigns, saved server layers, API workflows, PDF export, and automated ATT&CK synchronization

**Known parity gap:** native MITRE ATLAS matrix ingestion remains separate from the embedded Anomaly Detection Atlas reference-book integration. Enterprise, Mobile, and ICS ATT&CK domains have full Docker support.

### v0.5.0 (2026-06-12)

**Public intelligence and ecosystem release:**
- ThreatMapper Web promoted as the public intelligence workspace and primary ecosystem entry point
- Permanent crawlable actor and technique pages generated from the current public-workspace dataset
- Global actor, alias, technique, report, publisher, and evidence search
- Intelligence discovery dashboard, shareable deep links, report filtering, and event-level Google Analytics
- Correlated CTI/IR reports, defensive guidance, threat hunting, evidence assessment, and detection coverage workflows
- Strong cross-links to ThreatMapper docs, CTI Analyst Field Manual, Israel Threat Actors CTI, Anomaly Detection Atlas, ITDR Handbook, and 1200km Medium research

### v0.4.0 (2026-06-11)

**Group vs Group comparison:**
- New **Group vs Group** page (sidebar → ◉ Group vs Group): compare up to 6 ATT&CK group profiles simultaneously
- **Overlap Matrix** tab — N×N Jaccard similarity table; pairwise shared-technique cards with amber badges
- **ATT&CK View** tab — compact combined matrix filtered to techniques used by ≥ 1 selected group; each cell shows coloured dots for every group that uses the technique
- **Technique Table** tab — sortable by ID or per-group column, filterable (All / Shared 2+ / Exclusive), ✓ checkmarks per group, count column

**Clickable TTP detail panels:**
- Every technique ID throughout the UI is now a clickable link — click to open a slide-in detail panel
- Panel shows: technique name and ID, tactics, platforms, full description, detection guidance, Anomaly Detection Atlas cross-references, Ecosystem Resources section
- **Ecosystem Resources** links: Anomaly Detection Atlas (per-technique deep links), ITDR Handbook (auto-linked for identity techniques: T1078, T1098, T1110, T1111, T1136, T1531, T1539, T1550, T1552, T1555, T1556, T1558, T1606, T1621), CTI Analyst Field Manual, ThreatMapper Web Tool
- Wired in: Navigator matrix cells, ATT&CK Group Library technique list, Compare (shared/gap/overview badges), Group vs Group (overlap badges and technique table)
- Close with **Esc** or click outside

**Ecosystem integration:**
- Sidebar links added: ThreatMapper Web Tool (no-Docker browser version), CTI Knowledge Base, 1200km.com
- Anomaly Detection Atlas links now point to `https://1200km.com/anomaly-detection-atlas` (previously `localhost`) — works without running the full Docker stack

### v0.3.0 (2026-06-06)

**Two-database architecture:**
- Added `Campaign`, `CampaignTechnique`, `AptGroupCampaign` SQLAlchemy models
- STIX ingestor parses `campaign` objects and `attributed-to` / `uses` relationships from the selected ATT&CK release
- New API endpoints:
  - `GET /api/apt/campaigns` — list all campaigns, filterable by domain, group, search, version
  - `GET /api/apt/campaigns/{attack_id}` — full campaign detail with technique list
  - `POST /api/apt/campaigns/compare` — Jaccard ranking vs all campaigns (body: `{technique_ids: [...]}`)
  - `GET /api/analyze/sessions` — DB 2 report library (all completed analysis sessions)
  - `POST /api/analyze/sessions/{id}/compare` — re-run Jaccard for a stored report
- `AnalysisSession` gains `name VARCHAR(255)` column; name is set from the `name` form field or filename
- **ATT&CK Group Library** — Campaigns tab per group: expandable campaign cards with technique list, date range, "Add to my TTPs" action
- **Compare page** — three-mode switcher: Groups (DB 1) / Campaigns (DB 1) / Reports (DB 2)

**Bug fix:**
- `GET /api/analyze/sessions` was shadowed by `GET /api/analyze/{session_id}` because the wildcard route was registered first; fixed by reordering routes so static paths precede parameterised ones

### v0.2.1 (2026-06-06)

**Security fixes:**
- File uploads streamed with 64 KB chunk reader; 50 MB guard fires before entire body is buffered
- `/apt/compare` enforces max 500 technique IDs
- `ChatRequest.context` capped at 8,000 characters; `model` validated against pattern
- `_parse_response` uses `json.JSONDecoder().raw_decode()` — greedy regex replaced

**Correctness fixes:**
- Failed post-stream DB writes now set `status=failed` correctly
- `AnalysisSession` gains `domain` column; PDF exports show the actual analysis domain
- `GET /analyze/{id}` returns `JSONResponse(status_code=202)` instead of raising `HTTPException(202)`
- Layer PDF technique count derived from DB results, not raw client-supplied IDs

**Performance:**
- Anthropic, OpenAI, and Gemini SDK clients cached in `__init__`; connection pools reused across requests

### v0.2.0 (2026-06-06)

- Initial release: Navigator, AI Analysis, ATT&CK Group Library, Compare, Export, MITRE Sync
- STIX bundle parsing rewritten to use stdlib `json` only (Python 3.12, drops `mitreattack-python`)
- Fixed tactic matrix ordering: canonical ATT&CK kill-chain sort

---

## License

MIT — see [LICENSE](LICENSE).

ATT&CK® is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.
