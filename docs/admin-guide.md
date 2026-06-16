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
| `ATTCK_DOMAINS` | ATT&CK domains to ingest |
| `LOG_LEVEL` | API/worker log verbosity |
| `ATLAS_SYNC_INTERVAL` | Reference-book sync interval |

## Backups

Back up PostgreSQL regularly:

```bash
docker compose exec postgres pg_dump -U "$DB_USER" "$DB_NAME" > threatmapper-backup.sql
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
password in place:

```bash
docker compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v pass="$POSTGRES_PASSWORD" <<'"'"'SQL'"'"'
ALTER USER tm_user WITH PASSWORD :'"'"'pass'"'"';
SQL'
docker compose restart api worker beat frontend
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

## Reference Synchronization

ThreatMapper synchronizes MITRE ATT&CK STIX data for the configured
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

## Internet-Facing Deployments

The default Compose deployment is not a hardened public SaaS. If exposing ThreatMapper:

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

ThreatMapper can export a completed analysis as a STIX 2.1 JSON bundle from:

```bash
GET /api/export/analysis/{session_id}/stix
```

The bundle is report/TTP-centric:

- STIX `report` for the analysis session
- ATT&CK `attack-pattern` objects for extracted techniques
- optional `intrusion-set` objects for group-similarity leads
- `x_threatmapper_*` custom fields for confidence, review status, model, provider, domain, and similarity metadata

It intentionally does not model IOCs. Similarity leads are investigation leads
based on TTP overlap and must not be treated as attribution.
