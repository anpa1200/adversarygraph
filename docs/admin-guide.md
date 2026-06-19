# Admin Guide

This guide covers local and controlled self-hosted operation.

Current public documentation bundle:

- Published article mirror: <https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html>
- Medium publication: <https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e>
- Local visual appendix: [`full-guide-v2.md#24-visual-appendix`](full-guide-v2.md#24-visual-appendix)

## Services

| Service | Purpose |
|---|---|
| Frontend | React analyst workspace |
| API | FastAPI backend and OpenAPI docs |
| PostgreSQL | External persistent database for synced references and private/custom data |
| Redis | Celery broker/result backend |
| Worker | Background report analysis and collection jobs |
| Beat | Scheduled ATT&CK sync and collection jobs |
| Atlas docs | Embedded Anomaly Detection Atlas reference |

## Configuration

Create `.env` from `.env.example`.

Important settings:

| Variable | Purpose |
|---|---|
| `DB_NAME`, `DB_USER`, `DB_PASS` | PostgreSQL credentials |
| `ADVERSARYGRAPH_DB_DIR` | External persistent PostgreSQL data directory, default `./data/postgres` |
| `ANTHROPIC_API_KEY` | Claude provider |
| `OPENAI_API_KEY` | OpenAI provider |
| `OPENAI_MODEL` | OpenAI model default |
| `GEMINI_API_KEY` | Gemini provider |
| `MINIMAX_API_KEY` | MiniMax provider |
| `MINIMAX_MODEL` | MiniMax model default |
| `MINIMAX_BASE_URL` | MiniMax OpenAI-compatible API base URL |
| `LOCAL_LLM_BASE_URL` | OpenAI-compatible local LLM endpoint |
| `LOCAL_LLM_API_KEY` | Local endpoint API key placeholder |
| `LOCAL_LLM_MODEL` | Local model default |
| `ATTCK_DOMAINS` | ATT&CK/ATLAS domains to ingest, for example `enterprise-attack,mobile-attack,ics-attack,atlas` |
| `THREATFOX_AUTH_KEY` | Optional abuse.ch ThreatFox key for IOC sync |
| `AUTO_THREATFOX_SYNC_ON_STARTUP` | Run background ThreatFox IOC sync after API startup when a ThreatFox key is configured |
| `AUTO_THREATFOX_SYNC_DAYS` | ThreatFox startup sync window, clamped to 1-7 days |
| `OTX_API_KEY` | Optional AlienVault OTX key for actor pulse IOC enrichment |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal key for on-demand IOC reputation and ATT&CK context lookup |
| `DYNAMIC_DB_SYNC_HOUR`, `DYNAMIC_DB_SYNC_MINUTE` | Daily dynamic DB refresh time in UTC |
| `DYNAMIC_DB_IOC_SYNC_DAYS` | Daily IOC sync window, clamped to 1-7 days |
| `LOG_LEVEL` | API/worker log verbosity |
| `ATLAS_SYNC_INTERVAL` | Reference-book sync interval |

## Backups

Back up PostgreSQL regularly. The default data directory is external to the
containers at `./data/postgres`, but logical backups are still recommended:

```bash
docker compose exec postgres pg_dump -U "$DB_USER" "$DB_NAME" > adversarygraph-backup.sql
```

Test restore procedures before relying on backups.

## PostgreSQL Credential Rotation

`DB_PASS` is used when the PostgreSQL data directory is first initialized. If a database
directory already exists, changing `.env` updates container environment variables
but does not change the password stored inside PostgreSQL.

Fresh clones on new machines are not affected if `.env` is created before the
first startup. The mismatch only appears after an existing `data/postgres`
directory was created with one password and `.env` is later changed to another
password.

After changing `DB_PASS` for an existing volume, rotate the database role
password in place with the Compose helper:

```bash
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend
```

Or use the wrapper script:

```bash
./scripts/apply-db-env-creds.sh
```

The helper connects through a local PostgreSQL socket shared only between the
PostgreSQL container and the one-shot helper container. It applies the current
`.env` `DB_PASS` to the current `.env` `DB_USER` role without deleting data.
After changing `.env`, recreate the application containers so they receive the
new environment values:

```bash
docker compose up -d --force-recreate api worker beat frontend
```

AdversaryGraph passes `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` as
separate container variables and builds the SQLAlchemy URL inside Python. This
allows normal strong passwords with URL-special characters such as `@`, `#`,
`:`, and `/`.

Manual equivalent:

```bash
docker compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v pass="$POSTGRES_PASSWORD" <<'"'"'SQL'"'"'
ALTER USER ag_user WITH PASSWORD :'"'"'pass'"'"';
SQL'
docker compose up -d --force-recreate api worker beat frontend
```

If the data is disposable, `docker compose down -v` followed by
`docker compose up --build` recreates the database with the current `.env`
credentials.

## External DB Directory Migration

Current deployments store PostgreSQL data in `ADVERSARYGRAPH_DB_DIR`, default
`./data/postgres`. Existing deployments created before this layout may still
have a Docker-managed `pg_data` volume. Migrate it once before starting the new
Compose layout:

```bash
./scripts/migrate-postgres-volume-to-external-dir.sh
docker compose up -d
```

The script refuses to overwrite a non-empty target directory. Keep
`./data/postgres` during rebuilds and upgrades; delete it only when you
intentionally want a fresh database.

## Updates

```bash
git pull
docker compose pull
docker compose up -d --build
```

Review `CHANGELOG.md` before upgrading tagged releases.

For the current feature scope, review
[`docs/release-summary-v2.5.8.md`](release-summary-v2.5.8.md).

## Feeds Management

AdversaryGraph synchronizes MITRE ATT&CK STIX data for the configured
`ATTCK_DOMAINS`. The sync includes matrices, tactics, techniques,
sub-techniques, APT group profiles, campaigns, usage relationships, attribution
links, and STIX references.

Automatic sync runs daily at 03:00 UTC. Manual sync is available from the
Feeds Management page or through the API:

```bash
curl -X POST http://localhost:8000/api/sync/trigger \
  -H 'Content-Type: application/json' \
  -d '{"source":"mitre-attack","domains":["enterprise-attack"],"force":false}'
```

Set `force` to `true` to re-ingest the latest cached MITRE version even when the
database already reports the current version.

Dynamic DB sync runs daily at `DYNAMIC_DB_SYNC_HOUR:DYNAMIC_DB_SYNC_MINUTE` UTC.
It refreshes ATT&CK/ATLAS, MISP Galaxy actor metadata, and IOC enrichment sources
while preserving private/custom records in the external DB directory:

```bash
curl -X POST 'http://localhost:8000/api/sync/dynamic-db?days=7&force_attack=false'
```

## IOC Source Synchronization

IOC sync is separate from ATT&CK/ATLAS sync. ATT&CK gives stable TTP and actor
relationships; IOC feeds provide time-sensitive observables.

Supported operator-managed IOC sources:

- ThreatFox: `POST /api/ioc/sync/threatfox?days=7`
- Malpedia malware-family enrichment: `POST /api/ioc/sync/malpedia`
- OTX actor enrichment: `POST /api/ioc/sync/otx`
- registered custom feeds: `POST /api/ioc/sync/{source_id}`
- centralized action: `POST /api/sync/ioc?days=7`
- local IOC-to-TTP reprocessing: `POST /api/ioc/enrich/ttps?limit=20000`

Malpedia public family sync does not require an API key and creates
`malware-family` records with aliases, references, attribution evidence, and
actor links where family attribution matches local ATT&CK actor names or aliases.

Custom feeds can be registered from the UI or API. Keep feed URLs and API keys
inside `.env`, a secret manager, or another local operator-controlled channel.

If `THREATFOX_AUTH_KEY` is configured and `AUTO_THREATFOX_SYNC_ON_STARTUP=true`,
the API starts a non-blocking ThreatFox sync after ATT&CK ingestion completes.
If the key is missing, startup continues and the sync is skipped.

IOC type normalization runs during import and IOC-to-TTP enrichment. Provider
labels such as `sha256_hash`, `filehash-sha256`, `sha1_hash`, and `md5_hash`
are merged into `sha256`, `sha1`, and `md5` where possible, including duplicate
record/link consolidation.

IOC-to-TTP mapping is evidence-prioritized:

1. strict source/report evidence from explicit ATT&CK IDs in uploaded reports,
   STIX/TAXII, MISP/custom records, or feed fields
2. enrichment-platform evidence from metadata returned by ThreatFox, OTX,
   Malpedia, VirusTotal, sandbox, Sigma/YARA, or similar feeds
3. optional AI fallback only when enabled with `ai_enrich=true`

The UI exposes this as an explicit checkbox in IOC Library and Feeds
Management. The API accepts
`ai_enrich=true&ai_provider=local|claude|openai|gemini|minimax` on `/api/sync/ioc`,
`/api/ioc/sync/threatfox`, `/api/ioc/sync/otx`, `/api/ioc/sync/{source_id}`,
and `/api/ioc/enrich/ttps`.

## Sigma / YARA Rule Feed Synchronization

Detection Studio supports operator-managed Sigma and YARA rule feeds. Use the
Pipeline page to add the SigmaHQ default feed, a private raw rule file, a URL
list, or a GitHub tree URL.

Useful endpoints:

- `POST /api/pipeline/rule-feeds/defaults`
- `POST /api/pipeline/sources` with `kind` set to `sigma` or `yara`
- `POST /api/pipeline/sources/{source_id}/run`
- `GET /api/pipeline/detections/versions`

The sync imports rules into `detection_versions`, preserves the source URL in
validation metadata, and maps a rule to the first ATT&CK technique ID found in
the rule text or Sigma tags. Large feeds should use `config.limit` to keep first
syncs bounded.

## Sandbox Behavior Synchronization

Sandbox behavior sync imports malware detonation context into the pipeline
enrichment store. Add a pipeline source with `kind: sandbox` from the Pipeline
Sandbox tab or API:

```bash
curl -X POST http://localhost:8000/api/pipeline/sources \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Private CAPE Export",
    "kind": "sandbox",
    "url": "https://sandbox.local/reports.json",
    "enabled": true,
    "interval_minutes": 1440,
    "config": {"limit": 100}
  }'
```

Run the feed:

```bash
curl -X POST http://localhost:8000/api/pipeline/sources/{source_id}/run
```

The feed URL should return JSON containing a report object, an array of reports,
or an object with `reports`, `data`, `results`, `analyses`, `items`, or `tasks`.
The parser extracts hashes, verdict, score, malware family, behavior signatures,
processes, network artifacts, and ATT&CK IDs. Reports are stored as
`sandbox:<feed name>` enrichment records linked to hash observables.

## Sector Intelligence Synchronization

Sector Intelligence uses local evidence tables populated from MISP Galaxy threat
actor metadata. Sync from the Sector Intel page or API before relying on sector,
region, motivation, or technology filters.

The score shown in the UI is a relevance rank. It is not attribution confidence,
maliciousness, IOC confidence, or likelihood of compromise.

## Internet-Facing Deployments

The default Compose deployment is not a hardened public SaaS. If exposing AdversaryGraph:

- Put the frontend and API behind TLS.
- Use an authenticating reverse proxy or identity-aware gateway.
- Do not expose PostgreSQL or Redis publicly.
- Rotate default secrets.
- Restrict allowed upload size.
- Configure provider keys through a secret manager.
- Review LLM provider data handling.
- Configure logs so report contents are not accidentally retained.

## Operational Health

Useful checks:

```bash
docker compose ps
docker compose logs -f api
docker compose logs -f worker
curl http://localhost:8000/api/health
```

## Data Retention

Operators should define:

- How long uploaded reports are retained.
- Whether generated reports are stored.
- Whether STIX/OpenCTI exports may be shared outside the local environment.
- Whether raw LLM responses are retained.
- Who can delete analyses.
- How backups are purged.

## OpenCTI Export

AdversaryGraph can export a completed analysis as a STIX 2.1 JSON bundle from:

```bash
GET /api/export/analysis/{session_id}/stix
```

The bundle is report/TTP-centric:

- STIX `report` for the analysis session
- ATT&CK `attack-pattern` objects for extracted techniques
- optional `intrusion-set` objects for group-similarity leads
- `x_adversarygraph_*` custom fields for confidence, review status, model, provider, domain, and similarity metadata

This STIX export intentionally does not model IOCs. Similarity leads are
investigation leads based on TTP overlap and must not be treated as attribution.

For IOC handoff, use the actor IOC tab or:

```bash
GET /api/ioc/actors/{actor_id}/export.csv
```

## VirusTotal Lookup

VirusTotal integration is an on-demand enrichment workflow. It does not import
or persist VirusTotal responses.

Configure:

```env
VIRUSTOTAL_API_KEY=
```

Supported IOC types:

- IP address
- domain
- URL
- MD5
- SHA1
- SHA256

API:

```text
POST /api/ioc/virustotal/lookup
```

Request:

```json
{"indicator":"8.8.8.8","domain":"enterprise-attack"}
```

The response includes VirusTotal verdict counts, community votes, selected
detection rows, tags, threat labels, object names, crowdsourced YARA/IDS/Sigma
rules, sandbox verdicts, DNS/WHOIS/network metadata, extracted ATT&CK IDs, and
TTP evidence records.

Actor matching compares local ATT&CK group names and aliases with VT labels,
tags, filenames, crowdsourced rule text, sandbox verdicts, malware
configuration, and behavior context. The API returns the matched terms and
evidence field for each actor match.

In the UI, use `VirusTotal Lookup` to add found TTPs to `My TTPs`, show found
TTPs on the Navigator matrix, open a matched adversary page, or overlay a
matched adversary on the matrix.
