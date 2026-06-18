# Admin Guide

This guide covers local and controlled self-hosted operation.

## Services

| Service | Purpose |
|---|---|
| Frontend | React analyst workspace |
| API | FastAPI backend and OpenAPI docs |
| PostgreSQL | ATT&CK data and report analysis storage |
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
| `ANTHROPIC_API_KEY` | Claude provider |
| `OPENAI_API_KEY` | OpenAI provider |
| `OPENAI_MODEL` | OpenAI model default |
| `GEMINI_API_KEY` | Gemini provider |
| `LOCAL_LLM_BASE_URL` | OpenAI-compatible local LLM endpoint |
| `LOCAL_LLM_API_KEY` | Local endpoint API key placeholder |
| `LOCAL_LLM_MODEL` | Local model default |
| `ATTCK_DOMAINS` | ATT&CK/ATLAS domains to ingest, for example `enterprise-attack,mobile-attack,ics-attack,atlas` |
| `THREATFOX_AUTH_KEY` | Optional abuse.ch ThreatFox key for IOC sync |
| `AUTO_THREATFOX_SYNC_ON_STARTUP` | Run background ThreatFox IOC sync after API startup when a ThreatFox key is configured |
| `AUTO_THREATFOX_SYNC_DAYS` | ThreatFox startup sync window, clamped to 1-7 days |
| `OTX_API_KEY` | Optional AlienVault OTX key for actor pulse IOC enrichment |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal key for on-demand IOC reputation and ATT&CK context lookup |
| `LOG_LEVEL` | API/worker log verbosity |
| `ATLAS_SYNC_INTERVAL` | Reference-book sync interval |

## Backups

Back up PostgreSQL regularly:

```bash
docker compose exec postgres pg_dump -U "$DB_USER" "$DB_NAME" > adversarygraph-backup.sql
```

Test restore procedures before relying on backups.

## PostgreSQL Credential Rotation

`DB_PASS` is used when the PostgreSQL volume is first initialized. If a database
volume already exists, changing `.env` updates container environment variables
but does not change the password stored inside PostgreSQL.

Fresh clones on new machines are not affected if `.env` is created before the
first startup. The mismatch only appears after an existing `pg_data` volume was
created with one password and `.env` is later changed to another password.

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

## Updates

```bash
git pull
docker compose pull
docker compose up -d --build
```

Review `CHANGELOG.md` before upgrading tagged releases.

For the current feature scope, review
[`docs/release-summary-v2.2.0.md`](release-summary-v2.2.0.md).

## Reference Synchronization

AdversaryGraph synchronizes MITRE ATT&CK STIX data for the configured
`ATTCK_DOMAINS`. The sync includes matrices, tactics, techniques,
sub-techniques, APT group profiles, campaigns, usage relationships, attribution
links, and STIX references.

Automatic sync runs daily at 03:00 UTC. Manual sync is available from the
Reference Sync page or through the API:

```bash
curl -X POST http://localhost:8000/api/sync/trigger \
  -H 'Content-Type: application/json' \
  -d '{"source":"mitre-attack","domains":["enterprise-attack"],"force":false}'
```

Set `force` to `true` to re-ingest the latest cached MITRE version even when the
database already reports the current version.

## IOC Source Synchronization

IOC sync is separate from ATT&CK/ATLAS sync. ATT&CK gives stable TTP and actor
relationships; IOC feeds provide time-sensitive observables.

Supported operator-managed IOC sources:

- ThreatFox: `POST /api/ioc/sync/threatfox?days=7`
- OTX actor enrichment: `POST /api/ioc/sync/otx`
- registered custom feeds: `POST /api/ioc/sync/{source_id}`
- centralized action: `POST /api/sync/ioc?days=7`

Custom feeds can be registered from the UI or API. Keep feed URLs and API keys
inside `.env`, a secret manager, or another local operator-controlled channel.

If `THREATFOX_AUTH_KEY` is configured and `AUTO_THREATFOX_SYNC_ON_STARTUP=true`,
the API starts a non-blocking ThreatFox sync after ATT&CK ingestion completes.
If the key is missing, startup continues and the sync is skipped.

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

The response includes VirusTotal verdict counts, selected detection rows, tags,
threat labels, extracted ATT&CK IDs, and local actor matches when a returned
name/tag/label matches an ingested ATT&CK group name or alias.

In the UI, use `VirusTotal Lookup` to add found TTPs to `My TTPs`, show found
TTPs on the Navigator matrix, open a matched adversary page, or overlay a
matched adversary on the matrix.
