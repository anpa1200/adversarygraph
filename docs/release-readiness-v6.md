# AdversaryGraph v6 Release Readiness

This is the acceptance gate for a controlled self-hosted v6.0.0 deployment.
“Production ready” means every applicable item below has an owner and evidence;
it does not mean the default stack is a managed or multi-tenant SaaS.

## Automated Release Gate

Install backend and frontend dependencies, then run:

```bash
./scripts/release-readiness.sh --full
```

For a faster edit-time check:

```bash
./scripts/release-readiness.sh --quick
```

The full gate validates:

- release metadata consistency and clean patch formatting;
- default and hardened production Compose rendering;
- frontend lint, production build, and Chromium smoke tests;
- backend lint and test suite;
- available SAST, dependency, secret, Compose, and container checks.

Optional scanners are reported as skipped when they are unavailable locally.
They remain mandatory in CI where configured.

## Deployment Go/No-Go

| Gate | Go condition | Evidence |
|---|---|---|
| Scope | Controlled self-hosted workspace; no unsupported multi-tenancy claim | Approved architecture record |
| Identity | `AUTH_ENABLED=true`; named users; bootstrap credentials removed; MFA/SSO decision recorded | Admin review and auth audit |
| TLS | Trusted reverse proxy terminates TLS and normalizes forwarded/host headers | Proxy configuration and TLS test |
| Network | PostgreSQL, Redis, workers, malware service, and lab fixtures are not publicly reachable | Firewall/security-group review |
| Secrets | Strong unique database, Redis, proxy, session, API, and provider secrets are externally managed | Secret-manager references, not secret values |
| Data | Classification, allowed uploads, retention, deletion, and export rules are approved | Data-handling policy |
| Backup | Pre-upgrade logical backup exists and its SHA-256 checksum verifies | Backup file and checksum result |
| Restore | Restore procedure has been tested in a non-production environment | Restore test record |
| Capacity | CPU, memory, disk, database, and worker sizing match expected ingestion volume | Sizing worksheet and load observation |
| Monitoring | Health, self-test, logs, traces, metrics, disk, database, and job failures are monitored | Dashboard/alert references |
| Validation | Full release gate and application self-test pass | Command output and timestamp |
| Rollback | Previous tag/images, deployment config, and restore path are available | Rollback record |

Any failed mandatory gate is a no-go. Risk acceptance must name the owner,
expiry, compensating control, and rollback trigger.

## Functional Acceptance

After deployment, confirm with a non-sensitive reviewer account:

1. Login, logout, session revocation, and required MFA/SSO behavior.
2. Discover, ATT&CK Group Library, Navigator, IOC Library, and CVE Library.
3. Research upload using only approved test data and source-evidence review.
4. Threat Radar or Asset Surface import using the repository demo inventory.
5. Observability health, metrics, traces, and redacted log views.
6. Attack Simulation against an approved lab target only; confirm target-side
   telemetry and SIEM delivery labels.
7. Backup creation and checksum verification.

## Security Acceptance

- Confirm default accounts and bootstrap secrets are absent.
- Confirm authorization on administrative and state-changing routes.
- Confirm CORS uses explicit trusted origins and wildcard origins are rejected.
- Confirm proxy-auth mode requires the internal proxy secret.
- Confirm feed and SIEM destinations reject unsafe schemes and metadata/local
  destinations where required.
- Confirm logs and screenshots contain no tokens, passwords, private reports,
  customer identifiers, or cleartext simulated passwords.
- Review `.gitleaks.toml` and `.gitleaksignore` changes manually. The ignore
  file contains exact fingerprints for reviewed historical findings in archived
  third-party HTML and non-secret fixtures; new findings are not path-ignored.
  Archived strings must never be loaded as operational credentials.
- Confirm malware execution remains isolated and disabled unless an approved
  disposable runtime profile exists.
- Confirm Attack Simulation cannot execute arbitrary targets, payloads, or
  commands.

## Upgrade and Rollback

Before upgrade:

```bash
cat VERSION
docker compose ps
./scripts/backup.sh
sha256sum -c ./backups/<backup>.dump.sha256
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
```

After upgrade:

```bash
./scripts/selftest.sh
curl -fsS http://localhost:3000/api/health
docker compose ps
```

If acceptance fails, save relevant logs, return to the previous release tag or
image set, rebuild, and restore the pre-upgrade dump when database state
requires it. See [Upgrade Guide](upgrade-guide.md) and
[Backup and Restore](backup-restore.md).

## Known Boundaries

The following remain outside the v6.0.0 production claim:

- managed public SaaS and tenant isolation;
- zero-downtime or downgrade-safe schema guarantees;
- formal Alembic migration-chain guarantees;
- automatic truth or attribution from AI output;
- real exploit validation from synthetic telemetry;
- dynamic malware execution without an isolated approved runtime.

See [Validation and Limitations](validation-and-limitations.md) for the complete
analyst-facing boundary.
