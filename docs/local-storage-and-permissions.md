# Local Storage And Permissions

AdversaryGraph is designed to run after a clean clone with Docker Compose. The
repository should remain source-only; local runtime state is either in `.env`, a
host data directory, or Docker volumes.

## Configuration

| Item | Location | Notes |
|---|---|---|
| Main config and secrets | `.env` in the repository root | Created from `.env.example`; ignored by git. |
| Compose topology | `docker-compose.yml` | Defines services, volumes, localhost bindings, and internal networks. |
| Production hardening overlay | `docker-compose.prod.yml` | Optional hardened profile for controlled deployments. |
| Helm deployment config | `helm/adversarygraph/values.yaml` | Kubernetes-oriented deployment values. |

Do not commit a filled `.env`. Provider keys, database credentials, bootstrap
admin passwords, OpenCTI tokens, SIEM destinations, and proxy secrets belong in
`.env` or an external secret manager.

## Local Data Stores

| Data | Default location | Purpose | Keep for upgrade? |
|---|---|---|---|
| PostgreSQL database | `${ADVERSARYGRAPH_DB_DIR:-./data/postgres}` | Users, sessions, audit records, investigations, saved analyses, IOC/CVE/ATT&CK correlations, asset cases, attack simulation history, feed state, and private/custom records. | Yes |
| ATT&CK/ATLAS cache | Docker volume `adversarygraph_attck_data`, mounted at `/app/data/attck` | Cached public STIX bundles and ingestion scratch data. | Recommended |
| API and lab logs | Docker volume `adversarygraph_adversarygraph_logs`, mounted at `/app/logs` | API logs, attack-lab telemetry, forwarded-event evidence. | Optional, depending on retention needs |
| MalwareGraph storage | Docker volume `adversarygraph_malwaregraph_storage` | MalwareGraph quarantine/artifact workspace and generated analysis artifacts. | Case-dependent |
| Atlas docs build output | Docker volume `adversarygraph_atlas_site` | Generated static Anomaly Detection Atlas site. | Optional |
| Redis state | Container runtime only by default | Queue/broker state for worker and scheduled jobs. | No |

`./data/postgres` is intentionally ignored by git. It is normally owned by the
PostgreSQL container user, so manual host edits may require elevated
permissions. Use logical backups rather than copying live database files.

## Permissions Model

| Path or volume | Writer | Permission handling |
|---|---|---|
| `/var/lib/postgresql/data` | PostgreSQL container | Created under `${ADVERSARYGRAPH_DB_DIR}` on first startup. |
| `/app/data/attck` | API, worker, beat | One-shot `attck-data-permissions` service creates the directory and grants write access for the app UID. |
| `/app/logs` | API and attack-lab services | Docker named volume; writable by the service users. |
| `/app/storage` inside MalwareGraph | MalwareGraph service | Docker named volume; service runs with restricted capabilities. |

If `attck_storage_writable` fails in self-test, run:

```bash
docker compose run --rm attck-data-permissions
docker compose up -d --force-recreate api worker beat
```

Then validate:

```bash
curl http://localhost:3000/api/health
./scripts/selftest.sh
```

## Fresh Clone Flow

```bash
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
cp .env.example .env
docker compose up -d --build
./scripts/selftest.sh
```

Open:

- Platform: <http://localhost:3000>
- API health through frontend proxy: <http://localhost:3000/api/health>
- API docs through frontend proxy: <http://localhost:3000/docs>

The API container itself is intentionally not published to the host by the
default Compose file. The frontend container is the supported local entrypoint.
