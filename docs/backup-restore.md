# Backup And Restore

Backups are mandatory for any production-like AdversaryGraph deployment. The
PostgreSQL data directory is persistent, but filesystem persistence is not a
substitute for tested logical backups.

## Backup Scope

Back up these items:

| Data | Location |
|---|---|
| PostgreSQL logical dump | `./backups/*.dump` by default |
| PostgreSQL data directory | `${ADVERSARYGRAPH_DB_DIR:-./data/postgres}` as secondary disaster recovery evidence |
| Unified RAG state | Included in the PostgreSQL dump: business profiles, derived documents/chunks/embeddings, run history, assistance provenance, and Navigator proposals |
| MalwareGraph storage | Docker volume `malwaregraph_storage` |
| Logs and attack-simulation telemetry | Docker volume `adversarygraph_logs` |
| `.env` secrets | Store in a secret manager, not in Git |

## Create A Logical Backup

```bash
./scripts/backup.sh
```

The script writes a compressed custom-format PostgreSQL dump to
`${ADVERSARYGRAPH_BACKUP_DIR:-./backups}`, verifies that `pg_restore` can read
its archive structure, and atomically creates a `.sha256` checksum file.
It uses an owner-only umask so newly created dump and checksum files are not
group- or world-readable. Encrypt backups before copying them off-host and
apply equivalent access controls to any pre-existing backup directory.

RAG rows are included automatically because they live in PostgreSQL. They are
derived but can contain sensitive excerpts, vectors, relationship context, and
generated answers, so do not exclude them casually from a production dump. If
an organization deliberately rebuilds the derived corpus instead, document the
exclusion, preserve authoritative source tables and business profiles, and
expect search/assistant downtime until reconciliation finishes.

Equivalent production-overlay helper command, when the stack is already running
with `docker-compose.prod.yml`:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile tools run --rm backup
```

For day-to-day operations, prefer `./scripts/backup.sh`; it dumps from the
currently running `postgres` service and does not recreate containers.

## Restore Drill

Use a copy of the production backup in a non-production environment first.

```bash
cp .env.example .env
# Edit .env with isolated test credentials and the exact release's seven
# ADVERSARYGRAPH_*_IMAGE digest references.
./scripts/validate-production-env.sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build postgres
CONFIRM_RESTORE=yes ./scripts/restore.sh ./backups/adversarygraph-adversarygraph-YYYYMMDDTHHMMSSZ.dump
./scripts/selftest.sh
```

The restore script:

1. requires and verifies the adjacent `.sha256` checksum;
2. requires the production environment preflight, including immutable custom
   image digest references, before destructive confirmation;
3. starts only the retained PostgreSQL image with `--no-build`, waits for it,
   and validates the archive with `pg_restore --list`;
4. stops API, worker, beat, and frontend services so no application writer can
   race the restore;
5. drops and recreates the `public` schema;
6. streams the selected dump to `pg_restore` without interpolating its filename
   into container shell code;
7. recreates API, worker, beat, and frontend containers with `--no-build` only
   after success.

If restoration fails after writers stop, they remain stopped so the platform
cannot write into a partial database. Correct the failure and restore a verified
archive before restarting them. A legacy archive without an adjacent checksum
is rejected unless an operator has verified it separately and explicitly sets
`ALLOW_UNVERIFIED_BACKUP=yes`.

## Restore Validation Checklist

- `/api/health` returns the expected version and `/api/ready` returns `ready`.
- An authenticated `/api/system/selftest` call returns JSON `status: "ok"`.
  `degraded` is not a passing restore result, and a shell-script fallback that
  checks only `/api/ready` is not the full dependency/feed self-test.
- Login works when auth is enabled.
- ATT&CK Group Library loads.
- IOC Library and CVE Library return records.
- PostgreSQL reports the expected pgvector extension version:

  ```bash
  docker compose exec -T postgres sh -lc \
    'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
    "SELECT extversion FROM pg_extension WHERE extname = '\''vector'\'';"'
  ```

- `GET /api/rag/status` reports the restored document/chunk counts and no
  unexpected failed embedding population.
- A representative exact IOC/CVE/ATT&CK lookup returns the expected canonical
  source. If the embedding endpoint, model, dimensions, or derived index schema
  changed, perform the reviewed migration and full reindex before accepting
  vector retrieval. Do not simply change `RAG_EMBEDDING_DIMENSIONS` against the
  restored column.
- The Navigator assistant can run evidence search and open a cited source. Test
  generation only with approved non-sensitive data and the exact reviewed model
  endpoint.
- Observability dashboard shows recent request traces.
- Attack Simulation page loads.
- Malware Analysis case list loads if the backup contains malware cases.

## Backup Schedule

Recommended minimums:

| Deployment | Frequency | Retention |
|---|---|---|
| Lab | Manual before upgrades | 3 latest |
| Small production | Daily | 14 days |
| Medium production | Daily plus pre-upgrade | 30 days |
| Large production | Daily plus weekly archive | 30-90 days |

Keep at least one recent backup off-host.

Automatic RAG retention affects the live database only. It does not purge
logical dumps, snapshots, replicas, exported layers, or MCP-client/model
history. Apply the same legal-hold and deletion schedule to every retained copy.
