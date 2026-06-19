# Quickstart

This guide starts a local AdversaryGraph Docker deployment for evaluation.

For the current v2.5 capability walkthrough with screenshots and infographics,
use the 1200km mirror or Medium publication:

- <https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html>
- <https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e>

## Prerequisites

- Docker Engine and Docker Compose v2.
- 8 GB RAM available to Docker.
- At least one LLM provider key for AI report extraction.

The public browser workspace at <https://1200km.com/threat-matrix/> does not require Docker, but it also does not process private reports or store backend analyses.

## 1. Clone

```bash
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
```

## 2. Configure

```bash
cp .env.example .env
```

Edit `.env` and set at least one provider key:

```env
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
MINIMAX_API_KEY=
MINIMAX_MODEL=MiniMax-M3
MINIMAX_BASE_URL=https://api.minimax.io/v1
```

For private analysis, use an operator-controlled LLM gateway and review the provider's data-retention terms.

Optional IOC enrichment providers:

```env
# abuse.ch ThreatFox recent IOC sync
THREATFOX_AUTH_KEY=
AUTO_THREATFOX_SYNC_ON_STARTUP=true
AUTO_THREATFOX_SYNC_DAYS=7

# AlienVault OTX actor-attributed pulse enrichment
OTX_API_KEY=

# VirusTotal on-demand IOC reputation and relationship lookup
VIRUSTOTAL_API_KEY=

# Daily dynamic DB refresh schedule in UTC
DYNAMIC_DB_SYNC_HOUR=3
DYNAMIC_DB_SYNC_MINUTE=30
DYNAMIC_DB_IOC_SYNC_DAYS=7
```

Leave these blank if you only want ATT&CK/ATLAS mapping, sector relevance, and
manual/private IOC imports.

Feed and key behavior:

- MITRE ATT&CK / ATLAS sync uses public STIX bundles and does not require an API key.
- Built-in MISP Galaxy metadata sync is public and does not require a MISP key.
- `THREATFOX_AUTH_KEY` enables abuse.ch ThreatFox recent IOC sync and optional startup sync.
- `OTX_API_KEY` enables AlienVault OTX actor-attributed pulse enrichment.
- `VIRUSTOTAL_API_KEY` enables on-demand IOC checks from IOC Library and VirusTotal Lookup.
- MISP event/attribute JSON exports, STIX bundles, TAXII collection URLs, custom JSON/CSV/TXT feeds, Sigma/YARA feeds, and sandbox behavior feeds are connected from the UI or API as source URLs/tokens.
- Never commit a filled `.env` file.

When `THREATFOX_AUTH_KEY` is set, the API automatically starts a background
ThreatFox sync after Docker startup. Leave `AUTO_THREATFOX_SYNC_ON_STARTUP=true`
for that behavior, or set it to `false` for manual-only IOC syncing.

PostgreSQL data is stored outside the containers in `ADVERSARYGRAPH_DB_DIR`
(`./data/postgres` by default). This folder is created on first deployment and
must be kept when rebuilding containers. It stores private reports, custom IOCs,
custom feeds, and synced public reference data.

## 3. Start

```bash
docker compose up --build
```

First startup creates the external DB directory and ingests MITRE ATT&CK STIX
data into PostgreSQL. This can take several minutes.

## 4. Open

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API docs | http://localhost:8000/docs |
| Health | http://localhost:8000/api/health |
| Anomaly Detection Atlas | http://localhost:3001/anomaly-detection-atlas/ |

## 5. Smoke Test

```bash
curl http://localhost:8000/api/health
curl "http://localhost:8000/api/attack/versions"
```

Expected health response:

```json
{"status":"ok","version":"2.5.4"}
```

Run the deployment self-test:

```bash
docker compose run --rm selftest
```

The self-test validates API startup, database connectivity, Redis,
ATT&CK/ATLAS data ingestion, and provider key configuration without exposing
secret values. The same check is available in the UI through error-popup
`Recheck` actions and the internal troubleshooting page:

```text
http://localhost:3000/troubleshooting
```

## Troubleshooting: PostgreSQL Password Mismatch

If the API exits during startup with:

```text
asyncpg.exceptions.InvalidPasswordError: password authentication failed for user "ag_user"
```

the PostgreSQL volume was probably created with an older `DB_PASS`. Docker does
not reinitialize an existing database volume when `.env` changes.

This does not affect a fresh clone on a new machine when `.env` is created
before the first `docker compose up --build`. In that case, PostgreSQL
initializes the new volume with the current `DB_NAME`, `DB_USER`, and `DB_PASS`
values.

For a development deployment where you can discard local database state, reset
the volumes:

```bash
docker compose down -v
docker compose up --build
```

To keep the existing database, apply the current `.env` credentials to the
existing PostgreSQL role:

```bash
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend
```

Or use the wrapper script:

```bash
./scripts/apply-db-env-creds.sh
```

Manual equivalent:

```bash
docker compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v pass="$POSTGRES_PASSWORD" <<'"'"'SQL'"'"'
ALTER USER ag_user WITH PASSWORD :'"'"'pass'"'"';
SQL'
docker compose up -d --force-recreate api worker beat frontend
```

## 6. Demo Workflow

1. Open the frontend.
2. Select Enterprise ATT&CK.
3. Paste a public CTI excerpt from `docs/demo-dataset/public-report-excerpt.md`.
4. Run analysis with the configured provider.
5. Review the extracted techniques.
6. Compare against known groups and campaigns.
7. Export a Navigator layer, JSON report, or PDF report.

Do not use confidential reports in public or third-party environments.

## 7. v2.1 Sector And IOC Workflow

1. Open Feeds Management and sync MISP Galaxy sector metadata.
2. Open Sector Intel.
3. Select one or more sectors, optional regions, and optional technologies.
4. Review ranked actors and use Actor info, TTP info, IOCs, or Show on matrix.
5. Open ATT&CK Group Library and select an actor.
6. Use Feeds Management or the IOCs tab to sync ThreatFox, Malpedia, and OTX.
7. Add a custom feed, import IOCs, or upload a private report for IOC extraction.

Malpedia adds malware-family enrichment records with aliases, references, and
actor attribution evidence. These records are context, not network IOCs.

## 8. VirusTotal IOC Lookup

Set `VIRUSTOTAL_API_KEY` in `.env`, restart the API, and open:

```text
http://localhost:3000/virustotal
```

Paste an IP, domain, URL, MD5, SHA1, or SHA256. The page shows a structured
VirusTotal summary and provides actions to add found TTPs to `My TTPs`, show
found TTPs on the matrix, and open any matched local adversary profile. It also
shows VT rule, sandbox, DNS/WHOIS, and evidence snippets for extracted TTPs and
actor links when those fields are present in the VT response.
