# ThreatMapper

**AI-powered MITRE ATT&CK threat intelligence platform.**

Map adversary behaviours to ATT&CK, compare against 160+ APT group profiles, analyse incident reports with Claude / GPT-4o / Gemini, and export Navigator-compatible layers — all in one self-hosted tool.

---

## Features

| Module | Capability |
|---|---|
| **Navigator** | Full ATT&CK matrix (Enterprise, Mobile, ICS) with D3.js zoom/pan, sub-technique expansion, dual-layer colouring |
| **APT Library** | 160+ named threat groups from MITRE ATT&CK with full TTP profiles, aliases, and overlay-to-Navigator |
| **AI Analysis** | Upload PDF/DOCX/TXT or paste text → streamed LLM extraction of ATT&CK techniques + APT attribution |
| **Compare** | Jaccard similarity ranking of your TTPs vs every APT group; visual matrix diff, tactic breakdown, gap analysis |
| **Export** | ATT&CK Navigator JSON layers, PDF threat intelligence reports, plain JSON |
| **MITRE Sync** | Auto-detects new ATT&CK releases daily (Celery beat), manual sync via API; sidebar shows staleness indicator |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     Docker Compose                        │
├──────────────┬────────────────┬──────────┬───────────────┤
│  React/Vite  │  FastAPI       │ Postgres │ Redis+Celery  │
│  (port 3000) │  (port 8000)   │  16      │ (worker+beat) │
└──────────────┴────────────────┴──────────┴───────────────┘
```

**Backend** — Python 3.12, FastAPI, SQLAlchemy 2.x (async), Celery  
**Frontend** — React 18, TypeScript, Vite, D3.js, Tailwind CSS, Zustand  
**Database** — PostgreSQL 16 with JSONB for ATT&CK STIX data  
**Queue** — Redis + Celery workers (async LLM jobs, daily MITRE sync)

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
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
```

### 2 — Start

```bash
docker compose up
```

**First startup takes 5–15 minutes.** The API container automatically downloads the latest ATT&CK STIX bundles from MITRE's GitHub (~105 MB total for all three domains), parses them with `mitreattack-python`, and upserts everything into PostgreSQL.

Watch progress:
```bash
docker compose logs -f api
```

You will see lines like:
```
Ingesting enterprise-attack v19.1 ...
  Ingested 14 tactics
  Ingested 641 techniques
  Ingested 163 APT groups
  Ingested 8234 group-technique usages
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

The central workspace. The full ATT&CK matrix renders as a zoomable heatmap.

- **Zoom/pan** — scroll to zoom, drag to pan. Double-click resets to default zoom.
- **Select a technique** — click any cell. It turns red and is added to your TTP layer.
- **Expand sub-techniques** — click the ▶ arrow on any parent cell.
- **Open detail panel** — clicking a cell also opens the right-side detail panel showing the full ATT&CK description, detection notes, data sources, and the embedded AI assistant.
- **AI assistant** — ask any question about the selected technique. Choose Claude, GPT-4o, or Gemini.
- **Search/filter** — type in the search box to filter by technique name or ID; use the platform dropdown to filter by OS/environment.
- **Overlay an APT group** — go to APT Library, find a group, click "Overlay on Navigator". The matrix shows a blue/amber overlay of that group's known TTPs.

**Layer controls (toolbar above matrix):**

| Control | Action |
|---|---|
| ↑ Import layer | Load an existing ATT&CK Navigator `.json` layer |
| ↓ Navigator layer | Export your TTPs + overlay as ATT&CK Navigator JSON |
| ↓ JSON | Export selected technique IDs as plain JSON |
| Expand all / Collapse all | Toggle all sub-techniques at once |
| Clear my TTPs | Reset your selection |
| Clear overlay | Remove the APT group overlay |

**Colour coding:**

| Colour | Meaning |
|---|---|
| Red `#e94560` | In your TTP layer |
| Blue `#3b82f6` | In the APT overlay only |
| Amber `#f59e0b` | In both (shared) |
| Dark | In neither |

---

### AI Analysis

Upload a threat intelligence report or paste investigation notes. The AI extracts ATT&CK technique mappings with confidence scores and evidence snippets.

1. Select a provider (Claude / GPT-4o / Gemini)
2. Paste text **or** upload PDF, DOCX, or TXT (up to 50 MB)
3. Click **Analyse with AI**
4. Watch the live token stream as the model thinks
5. When complete, review:
   - **Techniques tab** — extracted mappings with confidence %
   - **APT Matches tab** — top APT groups by Jaccard similarity against extracted TTPs
   - **Raw response** — the LLM's full output
6. Click **→ Inject into Navigator** to push all extracted techniques into your Navigator layer

---

### APT Library

Browse all 160+ ATT&CK threat groups.

- **Search** by group name or ATT&CK ID
- **View full TTP profile** — every technique the group is known to use, with usage descriptions
- **Add all to my TTPs** — bulk-load a group's techniques into your Navigator layer
- **Overlay on Navigator** — show the group's TTPs as a blue overlay on the matrix
- **ATT&CK ↗** — open the official MITRE page

---

### Compare

Rank every ATT&CK group against your selected techniques by Jaccard similarity.

1. Select techniques in Navigator (or run an AI Analysis)
2. Click **Compare against all APT groups**
3. Browse the ranked list on the left
4. Click any group to open the detail view on the right:

| Tab | Content |
|---|---|
| **Overview** | Similarity score, shared technique chips, techniques unique to your layer |
| **Tactic Breakdown** | Stacked bar chart per tactic — shared / user-only / APT-only counts |
| **Visual Diff** | Compact colour-strip matrix heatmap of the overlap |
| **Gap Analysis** | Every technique in the group's profile not yet in your layer |

- **Overlay in Navigator** — send to Navigator with the group as overlay
- **↓ PDF Report** — generate a formatted PDF report

---

### MITRE Sync

ThreatMapper automatically checks for new ATT&CK releases daily at 03:00 UTC.

- The **sidebar footer** shows a green dot (up to date) or amber pulse (update available)
- **Manual sync:** `POST /api/sync/trigger` or `make ingest`
- **Check status:** `GET /api/sync/status`

---

## API Reference

All endpoints are documented interactively at **http://localhost:8000/docs**.

### ATT&CK Data

```
GET  /api/attack/versions
GET  /api/attack/tactics?domain=enterprise-attack
GET  /api/attack/techniques?domain=enterprise-attack&tactic=initial-access&search=phish
GET  /api/attack/techniques/{attack_id}
```

### APT Groups

```
GET  /api/apt/groups?domain=enterprise-attack&search=APT29
GET  /api/apt/groups/{attack_id}
POST /api/apt/compare                          body: ["T1566", "T1059", ...]
```

### Analysis

```
POST /api/analyze                              multipart: provider, domain, text|file
POST /api/analyze/stream                       SSE stream of the same
GET  /api/analyze/{session_id}
POST /api/analyze/chat                         {message, provider, context}
```

### Export

```
POST /api/export/analysis/{session_id}         → PDF download
POST /api/export/layer                         {technique_ids, domain} → PDF
```

### Sync

```
GET  /api/sync/status
POST /api/sync/trigger
GET  /api/sync/task/{task_id}
```

---

## Configuration

All configuration is via environment variables in `.env`.

| Variable | Default | Description |
|---|---|---|
| `DB_NAME` | `threatmapper` | PostgreSQL database name |
| `DB_USER` | `tm_user` | Database user |
| `DB_PASS` | `changeme` | Database password |
| `ANTHROPIC_API_KEY` | — | Claude API key |
| `OPENAI_API_KEY` | — | OpenAI API key |
| `GEMINI_API_KEY` | — | Google Gemini API key |
| `ATTCK_DOMAINS` | `enterprise-attack,mobile-attack,ics-attack` | Domains to ingest |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warning`, `error` |

---

## Development

### Project structure

```
threatmapper/
├── backend/
│   ├── app/
│   │   ├── api/routes/        # FastAPI routers (attack, apt, analyze, sync, export)
│   │   ├── core/              # Config, database engine, base model
│   │   ├── models/            # SQLAlchemy ORM models
│   │   ├── services/
│   │   │   ├── ai/            # LLM adapters (Claude, OpenAI, Gemini)
│   │   │   ├── attck/         # STIX downloader, ingestor, version checker
│   │   │   ├── file_parser.py # PDF / DOCX / TXT extraction
│   │   │   └── report_generator.py  # PDF report builder (fpdf2)
│   │   └── tasks/             # Celery tasks (analysis, sync)
│   ├── tests/
│   │   ├── unit/              # Parser, AI base, comparison logic
│   │   └── integration/       # FastAPI routes (mocked DB)
│   └── main.py
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── Navigator/     # AttackMatrix, LayerControls, LayerImport,
│       │   │                  # TechniquePanel, LLMChat, MatrixFilters
│       │   └── Compare/       # MatrixDiff, TacticBreakdown
│       ├── hooks/             # useAttackMatrix, useSseStream
│       ├── pages/             # Navigator, APTLibrary, Analyze, Compare
│       └── store/             # Zustand global state
└── docker-compose.yml
```

### Makefile shortcuts

```bash
make up          # docker compose up
make build       # rebuild all images
make down        # stop everything
make logs        # follow api + worker logs
make shell-api   # bash into the api container
make shell-db    # psql into postgres
make ingest      # trigger ATT&CK re-ingestion manually
make reset       # tear down volumes and rebuild from scratch
```

### Running tests

```bash
# Inside the api container (full integration with real PostgreSQL):
docker compose exec api pytest tests/ -v

# Locally (unit + integration with mocked DB, no PostgreSQL needed):
cd backend
PYTHONPATH=. pytest tests/ -v --no-cov
```

**Test coverage:**

| Suite | Tests | What it covers |
|---|---|---|
| `unit/test_file_parser.py` | 9 | PDF, DOCX, TXT extraction; truncation; edge cases |
| `unit/test_ai_base.py` | 11 | JSON parsing from LLM responses; fence stripping; noise extraction; prompt structure |
| `unit/test_comparison.py` | 10 | Jaccard similarity; ranking; performance |
| `integration/test_attack_routes.py` | 10 | Health, versions, tactics, techniques, groups — API shape and error paths |
| `integration/test_apt_routes.py` | 9 | Compare validation, export, analyze input checks |

### Adding a new LLM provider

1. Create `backend/app/services/ai/myprovider.py` extending `LLMAdapter`
2. Implement `_raw_complete` and `_stream_complete`
3. Add an entry in `factory.py`'s `get_adapter`
4. Add to `PROVIDERS` in `frontend/src/pages/Analyze.tsx` and `LLMChat.tsx`

---

## Deployment Notes

### Security

- Change `DB_PASS` to a strong random password before any network-exposed deployment.
- The app has no built-in authentication. For internal/intranet use it is safe as-is. For internet-facing deployments, put it behind a reverse proxy (nginx, Caddy) with TLS and HTTP Basic Auth or OAuth.
- API keys are stored in `.env` only — never committed to git (`.gitignore` excludes `.env`).

### Scaling

- The API runs a single uvicorn worker by default. For concurrent users, add `--workers 4` to the uvicorn command in `docker-compose.yml`.
- Celery workers scale horizontally — add more `worker` containers in `docker-compose.yml`.
- PostgreSQL connection pool is set to 10 (max 20 overflow) — adequate for most single-server deployments.

### Updating ATT&CK data manually

```bash
make ingest
# or
docker compose exec api python -c \
  "import asyncio; from app.services.attck.ingestor import run_ingest; asyncio.run(asyncio.coroutine(lambda: run_ingest())())"
# or simplest:
curl -X POST http://localhost:8000/api/sync/trigger
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend framework | FastAPI 0.115 |
| ORM | SQLAlchemy 2.x (async) |
| Database | PostgreSQL 16 |
| Task queue | Celery 5.4 + Redis 7 |
| ATT&CK parsing | mitreattack-python 3.x, stix2 3.x |
| AI — Claude | anthropic SDK |
| AI — OpenAI | openai SDK |
| AI — Gemini | google-generativeai SDK |
| File parsing | PyMuPDF (PDF), python-docx (DOCX) |
| PDF reports | fpdf2 |
| Frontend framework | React 18 + TypeScript |
| Build tool | Vite 6 |
| Visualisation | D3.js 7 |
| Styling | Tailwind CSS 3 |
| State | Zustand 5 |
| Data fetching | TanStack Query 5 |
| Testing | pytest, pytest-asyncio, httpx |

---

## License

MIT — see [LICENSE](LICENSE).

ATT&CK® is a registered trademark of The MITRE Corporation. This tool is not affiliated with or endorsed by MITRE.
