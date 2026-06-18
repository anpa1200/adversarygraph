# Quickstart

This guide starts a local AdversaryGraph Docker deployment for evaluation.

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
```

For private analysis, use an operator-controlled LLM gateway and review the provider's data-retention terms.

Optional IOC enrichment providers:

```env
THREATFOX_AUTH_KEY=
AUTO_THREATFOX_SYNC_ON_STARTUP=true
AUTO_THREATFOX_SYNC_DAYS=7
OTX_API_KEY=
VIRUSTOTAL_API_KEY=
```

Leave these blank if you only want ATT&CK/ATLAS mapping, sector relevance, and
manual/private IOC imports.

When `THREATFOX_AUTH_KEY` is set, the API automatically starts a background
ThreatFox sync after Docker startup. Leave `AUTO_THREATFOX_SYNC_ON_STARTUP=true`
for that behavior, or set it to `false` for manual-only IOC syncing.

## 3. Start

```bash
docker compose up --build
```

First startup ingests MITRE ATT&CK STIX data into PostgreSQL. This can take several minutes.

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
{"status":"ok","version":"2.2.0"}
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

1. Open Reference Sync and sync MISP Galaxy sector metadata.
2. Open Sector Intel.
3. Select one or more sectors, optional regions, and optional technologies.
4. Review ranked actors and use Actor info, TTP info, IOCs, or Show on matrix.
5. Open ATT&CK Group Library and select an actor.
6. Use the IOCs tab to sync ThreatFox/OTX, add a custom feed, import IOCs, or
   upload a private report for IOC extraction.

## 8. VirusTotal IOC Lookup

Set `VIRUSTOTAL_API_KEY` in `.env`, restart the API, and open:

```text
http://localhost:3000/virustotal
```

Paste an IP, domain, URL, MD5, SHA1, or SHA256. The page shows a structured
VirusTotal summary and provides actions to add found TTPs to `My TTPs`, show
found TTPs on the matrix, and open any matched local adversary profile.
