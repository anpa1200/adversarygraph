# ThreatMapper

**AI-powered MITRE ATT&CK threat intelligence platform.**

Map adversary behaviours to ATT&CK, compare against 174+ APT group profiles and 56+ named campaigns, analyse incident reports with Claude / GPT-4o / Gemini, and export Navigator-compatible layers — all in one self-hosted tool.

---

## Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
  - [Navigator](#navigator)
  - [AI Analysis](#ai-analysis)
  - [APT Library](#apt-library)
  - [Compare](#compare)
  - [Export](#export)
  - [MITRE Sync](#mitre-sync)
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
| **APT Library** | 174+ named threat groups from MITRE ATT&CK; full TTP profiles, aliases, overlay-to-Navigator; **Campaigns tab** shows named operations per group |
| **AI Analysis** | Upload PDF/DOCX/TXT or paste text → streamed LLM extraction of ATT&CK techniques + APT attribution; results saved to Reports Library (DB 2) |
| **Compare — Groups** | Jaccard similarity ranking of your TTPs vs every APT group; visual matrix diff, tactic breakdown, gap analysis |
| **Compare — Campaigns** | Jaccard similarity ranking of your TTPs vs every named MITRE campaign (e.g. SolarWinds C0024, Operation Ghost C0023) |
| **Compare — Reports** | Browse your stored AI analyses (DB 2); re-run attribution against any saved report without re-calling the LLM |
| **Export** | ATT&CK Navigator JSON layers, PDF threat intelligence reports, plain JSON |
| **MITRE Sync** | Auto-detects new ATT&CK releases daily (Celery beat), manual sync via API; sidebar shows staleness indicator |

---

## Architecture

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
  LLMAdapter.extract()   ← Claude / GPT-4o / Gemini
        │
        ▼
  _parse_response()      ← JSON extraction with raw_decode fallback
        │
        ▼
  _rank_apt_groups()     ← Jaccard similarity vs every APT group in DB 1
        │
        ▼
  AnalysisResult → DB 2  ← session + name, techniques, APT matches, domain
        │
        ▼
  Frontend renders       ← techniques table, APT ranking, Navigator injection
```

### Two-database model

| Database | What it holds | Key tables |
|---|---|---|
| **DB 1 (MITRE)** | ATT&CK groups, campaigns, techniques, relationships — ingested from official STIX bundles | `apt_groups`, `campaigns`, `campaign_techniques`, `apt_group_campaigns`, `techniques` |
| **DB 2 (Reports)** | Every AI analysis you run: extracted techniques, summary, APT matches, name, domain | `analysis_sessions`, `analysis_results` |

---

## Quick Start

### Prerequisites

- Docker + Docker Compose (v2)
- API key for at least one LLM provider (Claude, OpenAI, or Gemini)

### 1 — Clone and configure

```bash
git clone https://github.com/anpa1200/threatmapper.git
cd threatmapper
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
# Required: at least one AI provider key
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GEMINI_API_KEY=AIza...

# Database (defaults are fine for local use)
DB_NAME=threatmapper
DB_USER=tm_user
DB_PASS=changeme_strong_password

# ATT&CK domains to ingest (comma-separated)
ATTCK_DOMAINS=enterprise-attack,mobile-attack,ics-attack

LOG_LEVEL=info
```

> You only need one LLM key. The others can be left blank — the UI only shows providers that have a key configured.
>
> **You must create `.env` before running `docker compose up`.** Without it the API keys are empty and AI Analysis will return 500.

### 2 — Start

```bash
docker compose up
```

**First startup takes 5–15 minutes.** The API container automatically:
1. Runs `create_tables()` to initialise the PostgreSQL schema
2. Downloads the latest ATT&CK STIX bundles from MITRE's GitHub (~105 MB total for all three domains)
3. Parses the STIX 2.1 JSON directly (no third-party ATT&CK library — Python 3.12 compatible)
4. Upserts tactics, techniques, groups, campaigns, and all relationships into PostgreSQL

Watch progress:

```bash
docker compose logs -f api
```

Expected output (v19.1):

```
Parsing enterprise-attack-19.1.json ...
  Parsed: 15 tactics, 760 techniques, 174 groups, 56 campaigns, 9100+ usages
  Ingested 15 tactics
  Ingested 760 techniques
  Ingested 174 APT groups
  Ingested 56 campaigns
  Ingested campaign-technique and group-campaign attribution links
Finished ingesting enterprise-attack v19.1
```

### 3 — Open

| Service | URL |
|---|---|
| **Frontend** | http://localhost:3000 |
| **API docs** | http://localhost:8000/docs |
| **Health** | http://localhost:8000/api/health |

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
| Open detail panel | Click a cell to open the right-side panel (full description, detection notes, data sources, AI assistant) |
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
| Clear overlay | Remove the APT group overlay |

#### Colour coding

| Colour | Meaning |
|---|---|
| Red `#e94560` | In your TTP layer |
| Blue `#3b82f6` | In the APT overlay only |
| Amber `#f59e0b` | In both layers (shared TTPs) |
| Dark | Not selected |

#### AI Assistant

Click any technique to open the detail panel with an embedded chat. The full ATT&CK description for the selected technique is already in context. Example prompts:

- *"What are the most common detections for this technique?"*
- *"Write a SIGMA rule skeleton for T1059.001"*
- *"What APT groups use this in combination with lateral movement?"*

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
| **APT Matches** | Top 10 APT groups ranked by Jaccard similarity |
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

### APT Library

Browse all 174+ ATT&CK threat groups. Each group has two tabs:

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
| **Tactic Breakdown** | Stacked bar per kill-chain phase: shared / user-only / APT-only |
| **Visual Diff** | Compact matrix colour-strip showing the full overlap |
| **Gap Analysis** | Every technique in the group's profile not in your layer — your detection backlog |

**Actions:**
- **Overlay in Navigator** — visualise the overlap on the full matrix
- **↓ PDF Report** — export a formatted comparison report

#### Mode: Campaigns (DB 1)

Rank every named MITRE campaign (56+ in Enterprise) against your current Navigator selection.

The detail panel shows:
- Similarity score, shared techniques highlighted in purple
- Full campaign technique list with overlap indicators
- Attribution (which group conducted this campaign)
- Date range of the campaign

#### Mode: Reports (DB 2)

Browse your stored AI analysis sessions. Click any report to see which APT groups best match its extracted TTP profile — without re-running the expensive LLM call.

Use cases:
- **Retrospective attribution** after a new ATT&CK version is released
- **Cross-incident correlation** across multiple saved reports
- **Environmental profiling** — which groups keep appearing across your incident set

---

### Export

#### Analysis PDF

From **Analyze**, click **Download PDF** on any completed analysis. Includes:
- Cover page with provider, model, domain, session ID, timestamp
- Executive summary (AI-generated)
- Extracted techniques table sorted by confidence
- APT attribution section with top 10 Jaccard matches
- Tactic coverage breakdown

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

- **Groups** (G0001–G0174+) — named threat actors with aggregate TTP profiles
- **Campaigns** (C0001–C0063+) — named operations with per-operation TTP profiles
- **Attribution links** — which group conducted which campaign (`attributed-to` relationships)
- **Technique usage** — the specific techniques observed in each group/campaign with use descriptions

**Coverage as of ATT&CK v19.1:**

| Domain | Groups | Campaigns | Techniques |
|---|---|---|---|
| Enterprise | 174 | 56 | 760+ |
| ICS | 14 | 8 | 80+ |
| Mobile | 20 | 3 | 70+ |

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

### APT Groups (DB 1)

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
     multipart: provider={claude|openai|gemini}, domain=enterprise-attack,
                name="My Report", text=... | file=@report.pdf

POST /api/analyze/stream          ← Server-Sent Events (same fields)

GET  /api/analyze/sessions[?limit=50&offset=0]    ← DB 2 report library
POST /api/analyze/sessions/{session_id}/compare[?top_n=10]  ← re-run Jaccard

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
POST /api/export/analysis/{session_id}   → PDF download
POST /api/export/layer
     body: { "technique_ids": ["T1059"], "domain": "enterprise-attack" }
     → PDF download
```

### Sync

```
GET  /api/sync/status
POST /api/sync/trigger
GET  /api/sync/task/{task_id}
```

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
| `GEMINI_API_KEY` | — | Google Gemini API key |
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

### Security checklist

- [ ] Set a strong `DB_PASS` in `.env`
- [ ] Never commit `.env` to git (it is in `.gitignore`)
- [ ] For any internet-facing deployment, place ThreatMapper behind nginx or Caddy with TLS and authentication (HTTP Basic Auth, OAuth proxy, or VPN)
- [ ] ThreatMapper has no built-in user authentication — all endpoints are open on the Docker network
- [ ] API keys are read from environment variables and never stored in the database

### Scaling

- The API runs a single uvicorn worker by default. For concurrent users add `--workers 4` in `docker-compose.yml`.
- Celery workers scale horizontally — add additional `worker` service instances.
- The PostgreSQL connection pool is set to 10 connections (max 20 overflow).

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Backend framework | FastAPI 0.115 | Async, OpenAPI auto-docs |
| ORM | SQLAlchemy 2.x (async) | asyncpg driver |
| Database | PostgreSQL 16 | JSONB for STIX arrays |
| Task queue | Celery 5.4 + Redis 7 | Daily ATT&CK sync |
| ATT&CK parsing | stdlib `json` only | No mitreattack-python; Python 3.12-compatible |
| AI — Claude | `anthropic` SDK | Cached async client in `__init__` |
| AI — OpenAI | `openai` SDK | Cached client; JSON mode on non-streaming |
| AI — Gemini | `google-generativeai` | `configure()` called once in `__init__` |
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

### v0.3.0 (2026-06-06)

**Two-database architecture:**
- Added `Campaign`, `CampaignTechnique`, `AptGroupCampaign` SQLAlchemy models
- STIX ingestor now parses `campaign` objects and `attributed-to` / `uses` relationships; 56+ named campaigns ingested for Enterprise ATT&CK v19.1
- New API endpoints:
  - `GET /api/apt/campaigns` — list all campaigns, filterable by domain, group, search, version
  - `GET /api/apt/campaigns/{attack_id}` — full campaign detail with technique list
  - `POST /api/apt/campaigns/compare` — Jaccard ranking vs all campaigns (body: `{technique_ids: [...]}`)
  - `GET /api/analyze/sessions` — DB 2 report library (all completed analysis sessions)
  - `POST /api/analyze/sessions/{id}/compare` — re-run Jaccard for a stored report
- `AnalysisSession` gains `name VARCHAR(255)` column; name is set from the `name` form field or filename
- **APT Library** — new Campaigns tab per group: expandable campaign cards with technique list, date range, "Add to my TTPs" action
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

- Initial release: Navigator, AI Analysis, APT Library, Compare, Export, MITRE Sync
- STIX bundle parsing rewritten to use stdlib `json` only (Python 3.12, drops `mitreattack-python`)
- Fixed tactic matrix ordering: canonical ATT&CK kill-chain sort

---

## License

MIT — see [LICENSE](LICENSE).

ATT&CK® is a registered trademark of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.
