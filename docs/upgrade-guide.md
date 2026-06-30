# Upgrade Guide

This guide covers the current Docker Compose upgrade path and the tested
procedure for moving from v5.3 to v5.4 and later releases.

## Current Migration Model

AdversaryGraph currently uses SQLAlchemy `create_all` plus additive startup SQL
for compatibility fields. It does **not** yet ship a formal Alembic migration
chain. That means production upgrades must be protected by logical backups and
post-upgrade validation.

Formal Alembic migrations are a planned production-readiness improvement.

## Supported Upgrade Pattern

```bash
git fetch --tags origin
git checkout main
git pull --ff-only

./scripts/backup.sh

docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
./scripts/selftest.sh
```

## v5.3 To v5.4 Procedure

1. Confirm the current app is healthy:

   ```bash
   curl -fsS http://localhost:3000/api/health
   docker compose ps
   ```

2. Create a logical backup:

   ```bash
   ./scripts/backup.sh
   ```

3. Pull the v5.4 code:

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
   ```

7. Open the UI and confirm:

   - login works;
   - Discover loads;
   - ATT&CK Group Library loads;
   - CVE Library loads;
   - Observability dashboard loads;
   - Attack Simulation loads.

## v5.4 To Next Release Procedure

Use the same guarded path for the next release until formal migration tooling is
introduced:

1. Export the current release and container state:

   ```bash
   cat VERSION
   docker compose ps
   curl -fsS http://localhost:3000/api/health
   ```

2. Create a logical backup and keep the checksum:

   ```bash
   ./scripts/backup.sh
   ls -lh ./backups/*.dump ./backups/*.sha256
   ```

3. Pull the next release, validate Compose, and rebuild:

   ```bash
   git pull --ff-only
   docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
   docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

4. Run the same validation gates:

   ```bash
   ./scripts/selftest.sh
   curl -fsS http://localhost:3000/api/health
   ```

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

2. Check out the previous known-good commit or tag.
3. Rebuild containers.
4. If database state is incompatible, restore the pre-upgrade backup:

   ```bash
   CONFIRM_RESTORE=yes ./scripts/restore.sh ./backups/<backup>.dump
   ```

## Required Future Production Step

Before claiming strict enterprise upgrade guarantees, add:

- Alembic migration baseline;
- migration tests in CI;
- backup/restore test job;
- explicit schema version table;
- downgrade/rollback policy.
