# Upgrade Guide

This guide covers the current Docker Compose upgrade path and the tested
procedure for moving from v5 releases to v6.0.0 and later releases.

## Current Migration Model

AdversaryGraph currently uses SQLAlchemy `create_all` plus additive startup SQL
for compatibility fields. It does **not** yet ship a formal Alembic migration
chain. That means production upgrades must be protected by logical backups and
post-upgrade validation.

Formal Alembic migrations are a planned production-readiness improvement.

The v6.5 unified RAG schema adds the PostgreSQL `vector` extension, derived
document/chunk tables, a generated full-text column, GIN/HNSW indexes, index-run
state, assistance provenance, and Navigator proposals. The bundled
`adversarygraph-postgres` image installs checksum-pinned pgvector 0.8.2. An external
PostgreSQL service must make pgvector 0.5.0 or newer available to the application
database before the upgraded API starts; `CREATE EXTENSION IF NOT EXISTS
vector` cannot install operating-system extension files on a managed host.

`RAG_EMBEDDING_DIMENSIONS` is embedded in the PostgreSQL vector column type.
Changing it on an existing installation is not a configuration-only upgrade.
Keep the existing value unless the release supplies and tests an explicit
schema migration and complete reindex procedure for the new model dimension.

All current startup compatibility DDL runs inside one database transaction.
The v6.5 referential-integrity preflight aborts that
transaction if it finds a
Threat Hunting AI record whose source report no longer exists or an Evidence
Graph edge whose endpoint node no longer exists. It does not silently delete
or rewrite those investigation records. On large installations, schedule a
maintenance window because adding foreign keys can take table locks.

Before the first upgrade that includes these constraints, inspect for legacy
orphans after taking the backup:

```sql
SELECT assistance.id, assistance.source_session_id
FROM threat_hunt_ai_assistance AS assistance
WHERE assistance.source_session_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM analysis_sessions AS source
    WHERE source.id = assistance.source_session_id
  );

SELECT edge.id, edge.source_node_id, edge.target_node_id
FROM evidence_graph_edges AS edge
WHERE NOT EXISTS (
    SELECT 1 FROM evidence_graph_nodes AS node
    WHERE node.id = edge.source_node_id
  )
   OR NOT EXISTS (
    SELECT 1 FROM evidence_graph_nodes AS node
    WHERE node.id = edge.target_node_id
  );
```

An empty result is the expected state. If rows are returned, preserve an export
of them and investigate why their parent records are absent. Restore the
missing parent when possible. Only after review may an operator deliberately
set an invalid AI `source_session_id` to `NULL` (the constraint's documented
delete behavior) or remove an irrecoverable orphan edge. Restart the API after
repair; a failed startup leaves all DDL in that startup transaction rolled
back.

## Supported Upgrade Pattern

```bash
git fetch --tags origin
git checkout <reviewed-release-tag>

./scripts/backup.sh

# Copy the seven ADVERSARYGRAPH_*_IMAGE entries from the exact release's
# adversarygraph-images.env attachment into .env before validation.
AUTH_EXISTING_ADMIN_CONFIRMED=true ./scripts/validate-production-env.sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build
./scripts/selftest.sh
```

Production authentication makes the shell self-test exit `3` after confirming
readiness because it cannot inherit a browser session. Complete the gate from
the authenticated troubleshooting UI or an authenticated API client with
`run_analysis`, and require the full result to return `status=ok`.

Production upgrades consume the prebuilt image digests published and scanned
for that release. Do not rebuild from a mutable source checkout during the
rollout: doing so disconnects the deployed artifact from the retained scan
evidence.

## v5.4 To v5.5 Procedure

1. Confirm the current app is healthy:

   ```bash
   curl -fsS http://localhost:3000/api/health
   curl -fsS http://localhost:3000/api/ready
   docker compose ps
   ```

2. Create a logical backup:

   ```bash
   ./scripts/backup.sh
   ```

3. Pull the v5.5 code:

   ```bash
   git pull --ff-only
   ```

4. Validate Compose:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
   ```

5. Rebuild and restart:

   ```bash
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

6. Validate:

   ```bash
   ./scripts/selftest.sh
   curl -fsS http://localhost:3000/api/health
   curl -fsS http://localhost:3000/api/ready
   ```

   With authentication enabled, the shell self-test can report that
   `/api/ready` passed and exit `3`. Sign in with a user that has
   `run_analysis` and require the full `/api/system/selftest` result to return
   `status=ok`; `degraded` is not a passing upgrade result.

7. Open the UI and confirm:

   - login works;
   - Discover loads;
   - ATT&CK Group Library loads;
   - CVE Library loads;
   - Observability dashboard loads;
   - Attack Simulation loads.

## v5.5-v5.9.1 To A Post-v6 Hardened Release

The public `v6.0.0` release predates the immutable seven-image manifest required
by the current production preflight. For a new production upgrade, use the
next successfully gated semantic release and this guarded path until formal
migration tooling is introduced:

1. Export the current release and container state:

   ```bash
   cat VERSION
   docker compose ps
   curl -fsS http://localhost:3000/api/health
   curl -fsS http://localhost:3000/api/ready
   ```

2. Create a logical backup and keep the checksum:

   ```bash
   ./scripts/backup.sh
   ls -lh ./backups/*.dump ./backups/*.sha256
   ```

3. Check out the next reviewed release, load its published image digests, and
   validate Compose:

   ```bash
   git fetch --tags origin
   git checkout <reviewed-release-tag>
   # Set independent DB_PASS and REDIS_PASSWORD values (24+ characters), an
   # independent RATE_LIMIT_PROXY_SECRET, explicit HTTPS
   # CORS_ALLOWED_ORIGINS, AUTH_ENABLED=true, and SECURE_COOKIES=true before
   # continuing. Set a bootstrap password/proxy secret for first rollout, and
   # load all seven ADVERSARYGRAPH_*_IMAGE digest references from the release's
   # adversarygraph-images.env attachment.
   AUTH_EXISTING_ADMIN_CONFIRMED=true ./scripts/validate-production-env.sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build
   ```

4. Run the same validation gates:

   ```bash
   ./scripts/selftest.sh
   curl -fsS http://localhost:3000/api/health
   curl -fsS http://localhost:3000/api/ready
   ```

   The shell command checks readiness and exits `3` when the full self-test is
   auth-protected. Capture a separate authenticated self-test result with
   `status=ok` for the deployed revision.

   Before the first v6 production rollout, configure a strong one-time
   `AUTH_BOOTSTRAP_ADMIN_PASSWORD` or a trusted OIDC/SAML proxy with a strong
   `PROXY_SECRET`. On an established installation, confirm a permanent named
   administrator can sign in before leaving the bootstrap password empty. The
   `AUTH_EXISTING_ADMIN_CONFIRMED=true` command above is a one-shot upgrade
   assertion; omit it for a new database and do not persist it without that
   verification.

5. Confirm feature-level smoke tests:

   - authenticated login and logout;
   - create one least-privilege test user in Admin Panel, confirm its SOC group
     and effective modules, test sign-in, then disable or retain it according
     to the acceptance plan;
   - verify the Create user form displays the live password policy and returns
     explicit validation feedback rather than an unexplained disabled action;
   - Discover and ATT&CK Group Library;
   - CVE Library and IOC Library;
   - Observability summary and metrics;
   - Attack Simulation with real-time logs;
   - Malware Analysis case list when enabled.

## Post-v6 Unified RAG Upgrade Acceptance

Use these additional steps for the first release that contains unified RAG, or
whenever its schema/indexing contract changes:

1. Before rollout, record the existing PostgreSQL version, RAG settings, model
   identity/dimensions, direct or session-pooled worker database route, and the
   pre-upgrade dump checksum. Do not use PgBouncer transaction or statement
   pooling for the reconciliation worker because its session advisory lock
   spans commits on one physical connection.
2. Start with `RAG_EMBEDDING_ENABLED=false` unless the exact private embedding
   endpoint and model have already passed a deployment smoke test. This permits
   exact/full-text indexing without external model dependence.
3. After API startup, verify pgvector before queueing work:

   ```bash
   docker compose exec -T postgres sh -lc \
     'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc \
     "SELECT extversion FROM pg_extension WHERE extname = '\''vector'\'';"'
   ```

4. Open **ATT&CK Navigator → AI RAG assistant** and select **Build /
   refresh RAG index** with a `manage_feeds` account. Monitor
   `/api/rag/status` and `/api/rag/index-runs` until reconciliation is complete.
   A degraded result with failed embeddings is not semantic-search acceptance;
   lexical retrieval may still be available.
5. Run representative exact IOC/CVE/ATT&CK searches and follow each canonical
   source route. Then, if semantic retrieval is approved, enable embeddings,
   restart API/worker/beat, run a complete reindex, and verify the response
   reports vector retrieval with zero unexpected failed embeddings.
6. Create a non-sensitive test business profile, run one grounded answer, and
   preview a Navigator proposal. Verify citations, effective TLP, domain,
   ATT&CK version, expiry, Add/Replace diff, and the non-mutating confirmation
   boundary. Confirm that proposal/audit state is persisted while no named
   Navigator layer is saved.
7. If MCP is used, start the stdio process with a dedicated least-privilege
   analyst session and run its four bounded tools. Confirm it cannot reindex,
   confirm/apply a proposal, save a layer, or perform operational actions.

The scheduled reconciliation and retention jobs are part of acceptance. Verify
Celery Beat schedules them, the worker heartbeat advances, and retention values
match the organization's source, backup, legal-hold, and deletion policy.

## Rollback

If validation fails:

1. Capture logs:

   ```bash
   docker compose logs --tail=300 api worker beat postgres > upgrade-failure.log
   ```

2. Check out the previous known-good release tag and load its retained
   seven-image
   digest manifest into `.env`.
3. Run the production preflight and redeploy that immutable image set with
   `--no-build`.
4. If database state is incompatible, restore the pre-upgrade backup while the
   previous image manifest is still loaded:

   ```bash
   CONFIRM_RESTORE=yes ./scripts/restore.sh ./backups/<backup>.dump
   ```

The restore script repeats the production preflight and refuses to build a
missing image. Make sure the prior digest-pinned images remain available in the
registry before beginning an upgrade.

If the upgrade introduced pgvector tables, do not assume the upgraded database
directory is safe to attach to an older PostgreSQL image that lacks the
extension files. Roll back with the pre-upgrade logical dump and the previous
reviewed image set, or retain a pgvector-compatible database only after an
explicit compatibility test. RAG documents and embeddings are derived, but
business profiles and authoritative IOC/CVE/ATT&CK/report records still require
the normal backup/restore discipline.

## Required Future Production Step

Before claiming strict enterprise upgrade guarantees, add:

- Alembic migration baseline;
- migration tests in CI;
- backup/restore test job;
- explicit schema version table;
- downgrade/rollback policy.
