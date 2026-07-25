# AdversaryGraph v6 Release Readiness

This is the current acceptance baseline for the controlled self-hosted
`v6.5.0` release candidate. “Production ready” means every applicable item below has an
owner and evidence for the exact deployed tag and images; it does not mean the
default stack is a managed or multi-tenant SaaS. The public `v6.0.0` release
predates the immutable seven-image manifest and has no attached
`adversarygraph-images.env`, so it cannot be credited with the strengthened
v6.5 automated artifact gate. Historical v6 evidence also does not validate
changes in the v6.5 source.

## Automated Release Gate

Use the same toolchain as CI:

- Python 3.12 with `backend/requirements.txt`, Ruff, Bandit, and pip-audit;
- Node.js 22 with `npm ci` completed in `frontend/` and the Playwright Chromium
  browser installed;
- Docker Engine with its current, mutually compatible Compose v2 plugin (the
  documented source procedure is validated on Compose 2.40.3); and
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
- OpenAPI/frontend contract consistency and complete documentation coverage for
  every governed module;
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
release evidence. The release workflow independently repeats
the critical tests, deployment renders, secret scan, seven custom-image scans,
and three pinned stack-image scans before the v6.5 tag can publish packages or
release notes. Publication is
tag-only: the workflow requires a `vX.Y.Z` tag whose value exactly
matches the checked-out `VERSION`; it accepts no manual version input. This is
v6.5 hardening: historical evidence for the existing `v6.0.0` tag must
be evaluated against the workflow and commit stored at that tag.

### Fresh-container and v6.5 publication policy

The checked-out v6.5 source configures strict local container scans
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

For the v6.5.0 version tag, the current workflow builds each of the seven release
image families once, loads it into the runner, scans that exact local candidate,
and only then pushes its semantic-version tag. It anonymously resolves each
public manifest, verifies that its config digest matches the scanned local image
ID, and writes the immutable manifest digest to `adversarygraph-images.env`.
Shared `latest` tags are not advanced because the family cannot be updated
atomically. Treat this as release evidence only when the workflow at the exact
tag completes successfully; it is v6.5 behavior and does not retroactively
describe the existing `v6.0.0` tag.

Publication retry is fail-closed. If a prior attempt published only part of the
version family, the workflow accepts an existing version image only when its
content-addressed image ID exactly matches a fresh build from the checked-out
tag, then rescans that candidate. Labels alone are not trusted. A content
mismatch or ambiguous registry lookup stops the run and requires review and
removal of the partial registry version before retry. The workflow refuses to
modify any published GitHub release. It resumes a stopped run's draft only when
the title, release notes, and sole manifest asset exactly match the regenerated
release; a mismatch requires review and draft cleanup. Release state is checked
again immediately before publication.

The workflow also verifies that the remote release tag still resolves to the
triggering commit before builds, after image publication, and immediately
before the draft becomes public. Those checks narrow but cannot eliminate a
tag-update race. An active repository tag ruleset that blocks updates and
deletion of existing `v*` tags is therefore a mandatory external release
control. The workflow requires no-bypass `update` and `deletion` rules that
cover its exact version tag; retain the ruleset configuration with the release
evidence.

For Helm acceptance, render with `config.productionMode: "true"`. That mode is
deliberately fail-closed on the release image digests, remediated PostgreSQL
repository, authentication, secure cookies, HTTPS CORS, baseline
NetworkPolicies, external Secret reference, and Redis digest. It cannot inspect
the existing Secret contents or prove registry provenance, so retain those as
separate review evidence.

After publication, use the `adversarygraph-images.env` digest manifest attached
to the GitHub release and independently verify it against the registry. The
production Compose preflight requires those custom digest references and
deploys them with `--no-build`. The Helm chart can render digest references for
PostgreSQL, backend, frontend, and MalwareGraph. Its PostgreSQL and Redis
evaluation defaults are digest-pinned, while backend, frontend, and
MalwareGraph use the human-readable `6.5.0` candidate tag with empty digest
fields. Those tags support evaluation only; production also replaces
PostgreSQL and supplies revision-matched images with reviewed manifest digests
for all four release components.
A reviewed `sha256:...` value takes precedence over
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
| Unified RAG | pgvector is present; initial reconciliation completed; source coverage/freshness and pending/failed embeddings are reviewed; representative exact/full-text queries retain canonical provenance, plus a real vector query when embeddings are enabled in the approved scope | Authenticated RAG status, run history, query evidence, and model smoke when embeddings are enabled |
| RAG governance | Business profiles, TLP/legal gates, citation verification, stale-context rejection, retention/legal hold, and non-mutating Navigator confirmation behave as documented; proposal/audit state is persisted but no layer is saved | Functional test record and audit events |
| MCP, when enabled | Stdio-only process uses a dedicated least-privilege session and exposes only bounded advisory tools; no confirmation, reindex, arbitrary URL/SQL, or operational mutation is possible | MCP client configuration review, tool smoke, and session revocation test |
| Monitoring | Health, self-test, logs, traces, metrics, disk, database, and job failures are monitored | Dashboard/alert references |
| Images | Fresh no-cache image scans pass; fixable high/critical findings are absent; published registry digests are recorded and used where the deployment supports them | Tag-workflow run, ten stack scan results, registry digest record, rendered deployment |
| Validation | Full release gate passes for the exact revision and an authenticated application self-test returns `status=ok` | Command output, commit/tag, and timestamp |
| Rollback | Previous tag/images, deployment config, and restore path are available | Rollback record |

Any failed mandatory gate is a no-go. Risk acceptance must name the owner,
expiry, compensating control, and rollback trigger.

### Self-test acceptance and remediation

An HTTP `200` response from `/api/system/selftest` is not sufficient evidence:
inspect the JSON `status`. `degraded` means the core checks completed but one or
more warnings remain, so it is not the required `ok` result. When authentication
protects the full endpoint, the shell self-test checks `/api/ready` but exits
`3`; that proves database-backed request readiness, not the broader self-test gate.
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
8. In Navigator, queue/review a RAG reconciliation with `manage_feeds`, then run
   an exact IOC/CVE/ATT&CK search and follow every canonical source route.
   Confirm status/source counts, current indexed time, run heartbeat/attempts,
   and no unexplained failed embeddings.
9. With an approved non-sensitive business profile, ask which IOCs matter for
   the profile and why. Verify the profile changes prioritization only, all
   material claims have valid citations, and no result claims targeting,
   exploitation, active infrastructure, or compromise without evidence.
10. Request an ATT&CK Navigator proposal. Verify the domain/version/IDs,
    citations, checksum and expiry; preview it; review the Add/Replace diff; and
    confirm that the receipt reports `persisted=false`. Save a named layer only
    through the separate normal workflow if required.
11. When semantic retrieval is enabled, retain a smoke test against the exact
    private endpoint/model showing the configured dimensions and visible vector
    retrieval. Protocol-mocked tests alone are not deployment acceptance.
12. When MCP is enabled, exercise `search_intelligence`, `ask_intelligence`,
    `get_indexed_entity`, and `propose_navigator_layer` through stdio, then
    revoke the dedicated session and confirm subsequent calls fail. Confirm MCP
    did not change Navigator or another operational record.
13. Attack Simulation against an approved lab target only; confirm target-side
   telemetry and SIEM delivery labels.
14. Backup creation and checksum verification, including RAG tables and a
    documented policy for derived vectors, assistance, proposals, and MCP-client
    copies.

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
- Confirm RAG embeddings accept only the local provider and reject a public
  endpoint host. Review private model routing, authentication, TLS, egress,
  logs, retention, model provenance, and exact embedding dimensions.
- Confirm raw provider payloads, connector/authentication credential fields,
  and unrestricted asset fields are absent from RAG source allowlists and
  stored assistance provenance. Scan representative allowlisted narrative data
  for secrets because the collector is not a general DLP/redaction engine.
- Confirm legal-sensitive, `TLP:AMBER+STRICT`, and `TLP:RED` RAG generation
  stays local; every eligible remote request requires an explicit user
  acknowledgment and is audited before egress.
- Confirm the RAG worker reaches PostgreSQL directly or through PgBouncer
  session pooling; transaction/statement pooling is incompatible with the
  session advisory lock.
- Confirm MCP is stdio-only, uses a dedicated least-privilege session, keeps
  credentials out of committed configuration/logs, and cannot acknowledge cloud
  processing or invoke proposal confirmation, reindex, feed, simulation,
  detection-forwarding, or response actions.
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

When authentication is enabled and the broader endpoint is protected,
`./scripts/selftest.sh` reports that `/api/ready` passed but exits `3` because
the full gate is inconclusive. Complete the acceptance check from an
authenticated browser session or API client with `run_analysis`, and require
the returned self-test JSON to contain `"status":"ok"`.

If acceptance fails, save relevant logs, return to the previous reviewed
release tag and immutable image-digest set, redeploy with `--no-build`, and
restore the pre-upgrade dump when database state requires it. See
[Upgrade Guide](upgrade-guide.md) and
[Backup and Restore](backup-restore.md).

## Known Boundaries

The following remain outside the v6.5.0 controlled self-hosted production
claim:

- managed public SaaS and tenant isolation;
- zero-downtime or downgrade-safe schema guarantees;
- formal Alembic migration-chain guarantees;
- automatic truth or attribution from AI output;
- semantic-search readiness without a deployment-specific private model and
  first-index smoke test;
- RAG or MCP as autonomous blocking, containment, hunting execution, layer
  persistence, or response automation;
- real exploit validation from synthetic telemetry;
- dynamic malware execution without an isolated approved runtime.

See [Validation and Limitations](validation-and-limitations.md) for the complete
analyst-facing boundary.
