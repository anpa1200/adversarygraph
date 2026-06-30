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
| MalwareGraph storage | Docker volume `malwaregraph_storage` |
| Logs and attack-simulation telemetry | Docker volume `adversarygraph_logs` |
| `.env` secrets | Store in a secret manager, not in Git |

## Create A Logical Backup

```bash
./scripts/backup.sh
```

The script writes a compressed custom-format PostgreSQL dump to
`${ADVERSARYGRAPH_BACKUP_DIR:-./backups}` and creates a `.sha256` checksum file.

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
# edit .env with test restore credentials
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d postgres
CONFIRM_RESTORE=yes ./scripts/restore.sh ./backups/adversarygraph-adversarygraph-YYYYMMDDTHHMMSSZ.dump
./scripts/selftest.sh
```

The restore script:

1. verifies the checksum when a `.sha256` file exists;
2. waits for PostgreSQL;
3. drops and recreates the `public` schema;
4. restores the dump with `pg_restore`;
5. recreates API, worker, beat, and frontend containers.

## Restore Validation Checklist

- `/api/health` returns the expected version.
- `/api/system/selftest` returns `ok`.
- Login works when auth is enabled.
- ATT&CK Group Library loads.
- IOC Library and CVE Library return records.
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
