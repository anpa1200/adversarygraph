# Upgrade Guide

This guide covers the current Docker Compose upgrade path and the tested
procedure for moving from v5 releases to v6.0.0 and later releases.

## Current Migration Model

AdversaryGraph currently uses SQLAlchemy `create_all` plus additive startup SQL
for compatibility fields. It does **not** yet ship a formal Alembic migration
chain. That means production upgrades must be protected by logical backups and
post-upgrade validation.

Formal Alembic migrations are a planned production-readiness improvement.

All current startup compatibility DDL runs inside one database transaction.
The current post-v6 `main` referential-integrity preflight aborts that
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

   With authentication enabled, the shell self-test may report only that
   `/api/ready` passed. Sign in with a user that has `run_analysis` and require
   the full `/api/system/selftest` result to return `status=ok`; `degraded` is
   not a passing upgrade result.

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

   The shell command can fall back to readiness when the full self-test is
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
   - Discover and ATT&CK Group Library;
   - CVE Library and IOC Library;
   - Observability summary and metrics;
   - Attack Simulation with real-time logs;
   - Malware Analysis case list when enabled.

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

## Required Future Production Step

Before claiming strict enterprise upgrade guarantees, add:

- Alembic migration baseline;
- migration tests in CI;
- backup/restore test job;
- explicit schema version table;
- downgrade/rollback policy.
