# AdversaryGraph v6 Release Readiness

This is the current acceptance baseline for a controlled self-hosted release
after `v6.0.0`. “Production ready” means every applicable item below has an
owner and evidence for the exact deployed tag and images; it does not mean the
default stack is a managed or multi-tenant SaaS. The public `v6.0.0` release
predates the immutable seven-image manifest and has no attached
`adversarygraph-images.env`, so it cannot be credited with the strengthened
post-v6 automated artifact gate. Historical v6 evidence also does not validate
changes on `main`.

## Automated Release Gate

Use the same toolchain as CI:

- Python 3.12 with `backend/requirements.txt`, Ruff, Bandit, and pip-audit;
- Node.js 22 with `npm ci` completed in `frontend/` and the Playwright Chromium
  browser installed;
- Docker Engine with the Compose v2 plugin; and
- Gitleaks, Trivy, and Helm available on `PATH` for the full gate.

The backend test runner deliberately selects Python 3.12 so a different active
Conda or system interpreter cannot produce a misleading local result. It tries
`python3.12` and then `python`; set `PYTHON_BIN=/absolute/path/to/python3.12` to
choose a reviewed environment explicitly. A non-3.12 override fails before the
test suite starts.

Install the project dependencies and browser, then run:

```bash
./scripts/release-readiness.sh --full
```

Run it with the reviewed production `.env` (or equivalent exported variables).
The gate rejects copied `CHANGE_ME` credentials, reused/short DB and Redis
or rate-limit proxy secrets, Redis characters that would break its URI,
tag-based custom production images, insecure CORS, disabled production authentication,
insecure cookies, and deployments with no bootstrap, trusted proxy, or
explicitly verified existing-admin path before it renders the production
deployment.

For a faster edit-time check:

```bash
./scripts/release-readiness.sh --quick
```

The full gate validates:

- release metadata consistency and clean patch formatting;
- default, development, and hardened production Compose rendering;
- frontend lint, production build, and Chromium smoke tests;
- Anomaly Detection Atlas documentation production build with broken-link and
  broken-anchor enforcement;
- backend lint and test suite;
- Bandit SAST, backend, frontend, and anomaly-docs dependency audits, Gitleaks
  secret scanning, Helm lint/render, and Trivy scans of every custom release
  image plus the pinned Redis, BusyBox, and docs-Nginx images.
- fresh strict-scan container builds that pull current base-image metadata and
  bypass the Docker layer cache before scanning all seven custom image
  families.

The full gate is fail-closed: `bandit`, `pip-audit`, `gitleaks`, `trivy`, and
`helm` must be installed, and any failed or unavailable check stops the release.
It also requires a working Docker daemon and already-installed project
dependencies; it does not mutate the operator's Python or Node environments.
Use `make security-scan` only for a best-effort developer check; it is not
release evidence. The release workflow on current `main` independently repeats
the critical tests, deployment renders, secret scan, seven custom-image scans,
and three pinned stack-image scans before a future tag can publish packages or
release notes. Publication is
tag-only: the workflow requires an immutable `vX.Y.Z` tag whose value exactly
matches the checked-out `VERSION`; it accepts no manual version input. This is
post-v6.0.0 hardening: historical evidence for the existing `v6.0.0` tag must
be evaluated against the workflow and commit stored at that immutable tag.

### Fresh-container and publication policy on post-v6 `main`

The checked-out post-v6 implementation configures strict local container scans
with `docker build --pull --no-cache`. The CI scan matrix and tag workflow use
the equivalent Buildx `pull: true`, `no-cache: true`, and `load: true` settings.
This avoids accepting a result solely because an older local base image or
cached package layer was reused. It does not make mutable upstream tags
reproducible; digest-pinning every base image remains separate hardening work.

The runtime Dockerfiles refresh distribution packages available at build time.
Trivy then fails the strict path on `HIGH` or `CRITICAL` findings for which an
upstream fix exists. The configured `ignore-unfixed` behavior means an unfixed
finding is filtered from this gate rather than becoming an automatic failure.
Run and retain a separate unfiltered inventory when the deployment's
vulnerability and risk policy requires review of findings that have no upstream
fix. A passing gated scan therefore means no gate-blocking fixable finding was
reported under that scanner database and policy, not that the image contains no
known vulnerabilities.

For a future version tag, the current workflow is configured to build each of
the seven release image families once with both the version and `latest` local
tags, load that image into the runner, scan the versioned tag, verify that both
local tags have the same image ID, and only then push those local tags. There is
no publish-time rebuild between the scan and push steps. Treat this as release
evidence only when the workflow at the exact tag completes successfully; it is
post-v6 behavior and does not retroactively describe the existing `v6.0.0` tag.

Publication retry is fail-closed and idempotent. If a prior attempt published
only part of the version family, the workflow pulls an existing version image
only when its OCI revision, version, and source labels match the current tag,
rescans that exact candidate, and republishes the same content. A mismatch or
an ambiguous registry lookup stops the run. Recovery may resume an existing
draft release, but every already-published GitHub release is immutable and is
never modified, regardless of which assets it contains. Ambiguous registry or
GitHub release lookups stop publication, and the workflow rechecks release
state immediately before creating or updating the draft.

For Helm acceptance, render with `config.productionMode: "true"`. That mode is
deliberately fail-closed on the release image digests, remediated PostgreSQL
repository, authentication, secure cookies, HTTPS CORS, baseline
NetworkPolicies, external Secret reference, and Redis digest. It cannot inspect
the existing Secret contents or prove registry provenance, so retain those as
separate review evidence.

After publication, use the `adversarygraph-images.env` digest manifest attached
to the GitHub release and independently verify it against the registry. The
production Compose preflight requires those custom digest references and
deploys them with `--no-build`. The Helm chart renders digest references for the
PostgreSQL, backend, frontend, and MalwareGraph images and pins Redis by
default. Its upstream PostgreSQL compatibility default is also digest-pinned
for chart evaluation, but production must replace both that repository and
digest with the release's remediated `adversarygraph-postgres` artifact. For
the other custom images, a reviewed `sha256:...` value takes precedence over
the human-readable tag; an empty digest remains tag-based and is not acceptable
for the production evidence row below. Preserve the registry, architecture,
tag, digest, workflow run, and source tag/commit as evidence.

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
| Images | Fresh no-cache image scans pass; fixable high/critical findings are absent; published registry digests are recorded and used where the deployment supports them | Tag-workflow run, ten stack scan results, registry digest record, rendered deployment |
| Validation | Full release gate passes for the exact revision and an authenticated application self-test returns `status=ok` | Command output, commit/tag, and timestamp |
| Rollback | Previous tag/images, deployment config, and restore path are available | Rollback record |

Any failed mandatory gate is a no-go. Risk acceptance must name the owner,
expiry, compensating control, and rollback trigger.

### Self-test acceptance and remediation

An HTTP `200` response from `/api/system/selftest` is not sufficient evidence:
inspect the JSON `status`. `degraded` means the core checks completed but one or
more warnings remain, so it is not the required `ok` result. The shell self-test
can fall back to `/api/ready` when authentication protects the full endpoint;
that proves database-backed request readiness, not the broader self-test gate.
For release evidence, sign in with a user that has `run_analysis`, capture the
full result, and resolve or explicitly risk-accept every non-`ok` check.

For the common `taxonomy_normalized` warning, a user with `manage_feeds` can
select **Normalize Taxonomy** in the self-test popup or call
`POST /api/system/taxonomy/normalize`. Rerun the full self-test afterward and
retain both the remediation audit event and final `status=ok` result.

## Functional Acceptance

After deployment, confirm with a non-sensitive reviewer account:

1. Login, logout, session revocation, and required MFA/SSO behavior.
2. Discover, ATT&CK Group Library, Navigator, IOC Library, and CVE Library.
3. Research upload using only approved test data and source-evidence review.
4. Threat Radar or Asset Surface import using the repository demo inventory.
5. Create a Threat Hunt, save a query revision, add and review a finding, choose
   a disposition through the normal workflow, and verify the export preserves
   scope, query provenance, evidence references, review state, and limitations.
6. With approved non-sensitive input, generate a hunt hypothesis from a
   completed stored Enterprise ATT&CK report, then exercise plan, query,
   findings, and outcome assistance. Verify citations against the source and
   confirm suggestions do not execute queries, create evidence, save records,
   or make lifecycle and disposition decisions.
7. Observability health, metrics, traces, and redacted log views.
8. Attack Simulation against an approved lab target only; confirm target-side
   telemetry and SIEM delivery labels.
9. Backup creation and checksum verification.

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
- Confirm Threat Hunting AI uses the reviewed local/private provider by default
  and that remote providers remain unavailable unless the operator enables
  cloud use and the analyst acknowledges each eligible request.
- Confirm `TLP:AMBER+STRICT` and `TLP:RED` assistant context is rejected for
  every remote provider, and that stored assistance records contain bounded,
  sanitized provenance rather than raw prompts, reports, provider responses,
  credentials, or exceptions.
- Confirm strict image evidence came from fresh pull/no-cache builds and retain
  the gated Trivy output. Where policy requires an inventory of vulnerabilities
  without upstream fixes, also retain a separate scan that does not use the
  gate's `ignore-unfixed` filter.
- Confirm the tag workflow pushed the already loaded and scanned local images,
  record the resulting per-architecture registry digests, and verify the
  rendered production deployment uses the reviewed digests where configured.

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
curl -fsS http://localhost:3000/api/ready
docker compose ps
```

When authentication is enabled, `./scripts/selftest.sh` may report only that
`/api/ready` passed because the broader endpoint is protected. Complete the
acceptance check from an authenticated browser session or API client with
`run_analysis`, and require the returned self-test JSON to contain
`"status":"ok"`.

If acceptance fails, save relevant logs, return to the previous reviewed
release tag and immutable image-digest set, redeploy with `--no-build`, and
restore the pre-upgrade dump when database state requires it. See
[Upgrade Guide](upgrade-guide.md) and
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
