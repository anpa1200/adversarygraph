# Admin Guide

This guide covers local and controlled self-hosted operation.

Current public documentation bundle:

- Current platform guide: [`adversarygraph-platform-guide.md`](adversarygraph-platform-guide.md)
- Detailed module workflows and case studies: [`module-reference.md`](module-reference.md)
- v5 Attack Simulation screenshots: [`assets/attack-simulation-v5/manifest.md`](assets/attack-simulation-v5/manifest.md)
- Tagged v6.0.0 UI screenshot evidence: [`assets/adversarygraph-v6/manifest.md`](assets/adversarygraph-v6/manifest.md)
- v6 production acceptance gate: [`release-readiness-v6.md`](release-readiness-v6.md)
- Platform screenshots: [`assets/adversarygraph-v4-platform/manifest.md`](assets/adversarygraph-v4-platform/manifest.md)
- Malware screenshots: [`assets/malware-analysis-v4/manifest.md`](assets/malware-analysis-v4/manifest.md)
- Published article mirror: <https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html>
- Medium publication: <https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e>
- Local visual appendix: [`full-guide-v2.md#25-visual-appendix`](full-guide-v2.md#25-visual-appendix)

## Services

| Service | Purpose |
|---|---|
| Frontend | React analyst workspace |
| API | FastAPI backend and OpenAPI docs |
| PostgreSQL | External persistent database for synced references and private/custom data |
| Redis | Celery broker/result backend |
| Worker | Background report analysis, collection, and RAG reconciliation jobs |
| Beat | Scheduled ATT&CK sync and collection jobs |
| Atlas docs | Embedded Anomaly Detection Atlas reference |

## Configuration

Create `.env` from `.env.example`.

Important settings:

| Variable | Purpose |
|---|---|
| `DB_NAME`, `DB_USER`, `DB_PASS` | PostgreSQL credentials |
| `ADVERSARYGRAPH_DB_DIR` | External persistent PostgreSQL data directory, default `./data/postgres` |
| `ANTHROPIC_API_KEY` | Claude provider |
| `OPENAI_API_KEY` | OpenAI provider |
| `OPENAI_MODEL` | OpenAI model default |
| `GEMINI_API_KEY` | Gemini provider |
| `GEMINI_MODEL` | Gemini model default, currently `gemini-3.5-flash` |
| `MINIMAX_API_KEY` | MiniMax provider |
| `MINIMAX_MODEL` | MiniMax model default, currently `MiniMax-M2.7` |
| `MINIMAX_BASE_URL` | MiniMax OpenAI-compatible API base URL |
| `LOCAL_LLM_BASE_URL` | OpenAI-compatible local LLM/embedding endpoint; the `local` provider requires a loopback, private/link-local IP, or recognized private service DNS host |
| `LOCAL_LLM_API_KEY` | Local endpoint API key placeholder |
| `LOCAL_LLM_MODEL` | Local model default; the Compose-managed Ollama overlay pulls this model with `make local-ai-up` |
| `OLLAMA_KEEP_ALIVE` | Optional Compose-managed Ollama model retention, default `10m` |
| `OLLAMA_MEMORY_LIMIT`, `OLLAMA_CPU_LIMIT` | Optional Compose-managed Ollama resource ceilings, defaults `12g` and `8.0` CPUs |
| `THREAT_HUNTING_AI_ENABLED` | Enable governed Threat Hunting AI endpoints, default `true` |
| `THREAT_HUNTING_AI_CLOUD_ENABLED` | Permit configured remote providers for eligible markings, default `false` |
| `THREAT_HUNTING_AI_DEFAULT_PROVIDER` | Default Threat Hunting provider: `local`, `claude`, `openai`, `gemini`, or `minimax`; default `local` |
| `THREAT_HUNTING_AI_TIMEOUT_SECONDS` | Maximum governed assistant generation time; default `45` seconds, enforced range `5`–`180` |
| `THREAT_HUNTING_AI_SOURCE_CHAR_LIMIT` | Maximum raw source-text characters included in report-to-hypothesis context; default `40000`, enforced range `4000`–`80000` |
| `THREAT_HUNTING_AI_MAX_CANDIDATES` | Maximum returned report-to-hypothesis candidates; default `3`, enforced range `1`–`3` |
| `RAG_ENABLED` | Enable unified hybrid retrieval and grounded assistant endpoints; default `true` |
| `RAG_EMBEDDING_ENABLED` | Enable vector embedding/index/query calls after a private model is verified; default `false`, and lexical retrieval remains available |
| `RAG_EMBEDDING_PROVIDER` | Private embedding boundary; the v6.5 implementation accepts `local` only |
| `RAG_EMBEDDING_MODEL` | Server-controlled embedding model; default `nomic-embed-text` |
| `RAG_EMBEDDING_DIMENSIONS` | Fixed pgvector dimension for this corpus; default `768`, change only with migration and full reindex |
| `RAG_EMBEDDING_BATCH_SIZE` | Maximum texts per embedding request; default `32`, range `1`–`128` |
| `RAG_VECTOR_MAX_COSINE_DISTANCE` | Maximum accepted cosine distance before vector candidates are discarded; default `0.55`, range `0`–`2` |
| `RAG_CHUNK_CHARS`, `RAG_CHUNK_OVERLAP_CHARS` | Bounded source chunk and overlap size; defaults `3500` and `350` |
| `RAG_DEFAULT_RESULT_LIMIT` | Default hybrid retrieval result count; default `12`, maximum API result limit `25` |
| `RAG_MAX_CONTEXT_CHARS` | Hard maximum for the serialized AI user context, including question, business profile, source titles, metadata, and excerpts; default `32000`, range `4000`–`80000` |
| `RAG_RECONCILE_HOUR`, `RAG_RECONCILE_MINUTE` | Daily Celery corpus reconciliation time in UTC; defaults `04:15` |
| `RAG_TOMBSTONE_RETENTION_DAYS` | Days to retain inactive derived RAG documents and their chunks; default `30`; `0` disables this automatic deletion path |
| `RAG_ASSISTANCE_RETENTION_DAYS` | Days to retain generated assistance records and associated Navigator proposals; default `90`; `0` disables this automatic deletion path |
| `RAG_RETENTION_BATCH_SIZE`, `RAG_RETENTION_MAX_BATCHES` | Bounded deletions per table and maximum transactions per scheduled run; defaults `1000` and `20` |
| `RAG_RETENTION_HOUR`, `RAG_RETENTION_MINUTE` | Daily audited RAG retention task time in UTC; defaults `04:45` |
| `ATTCK_DOMAINS` | ATT&CK/ATLAS domains to ingest, for example `enterprise-attack,mobile-attack,ics-attack,atlas` |
| `THREATFOX_AUTH_KEY` | Optional abuse.ch ThreatFox key for IOC sync |

External PostgreSQL must provide pgvector **0.5.0 or newer** before API
startup; older versions are rejected because the RAG schema requires HNSW.
The bundled development image builds checksum-pinned pgvector **0.8.2**.
| `AUTO_IOC_FULL_SYNC_ON_STARTUP` | Run background full IOC source sync after API startup |
| `AUTO_THREATFOX_SYNC_DAYS` | Startup IOC sync window for recent IOC providers, clamped to 1-7 days |
| `OTX_API_KEY` | Optional AlienVault OTX key for actor pulse IOC enrichment |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal key for on-demand IOC reputation and ATT&CK context lookup |
| `URLSCAN_API_KEY` | Optional urlscan.io key for IOC Investigation URL/domain pivots |
| `GREYNOISE_API_KEY` | Reserved for future GreyNoise paid API support; IOC Investigation uses GreyNoise Community without a key |
| `SHODAN_API_KEY` | Optional Shodan key for exposed service, hostname, and vulnerability pivots |
| `ABUSEIPDB_API_KEY` | Optional AbuseIPDB key for IP abuse confidence, ISP, hostname, and usage-type pivots |
| `CENSYS_API_KEY` | Optional Censys Platform personal access token for host, DNS, service, ASN, and certificate pivots |
| `CENSYS_ORG_ID` | Optional Censys organization ID for organization-scoped Platform API calls |
| `ASSET_SCANNER_ENABLED` | Enable inventory-bound Threat Radar asset assessments; default `true` |
| `ASSET_SCANNER_NMAP_ENABLED` | Permit the fixed safe Nmap service-discovery stage; default `true` |
| `ASSET_SCANNER_WEB_PROBE_ENABLED` | Permit root-only HTTP(S) security-header and configuration posture checks; default `true` |
| `ASSET_SCANNER_NMAP_BINARY` | Operator-controlled Nmap executable path; default `/usr/bin/nmap` in the backend image |
| `ASSET_SCANNER_TIMEOUT_SECONDS` | Per-assessment Nmap host timeout; default `120`, allowed range `15`–`600` seconds |
| `ASSET_SCANNER_WEB_PROBE_TIMEOUT_SECONDS` | Timeout for each root-only web posture request; default `15`, allowed range `5`–`60` seconds |
| `ASSET_SCANNER_TOP_PORTS` | Bounded Nmap top-port count; default `100`, allowed range `10`–`1000` |
| `ASSET_SCANNER_MAX_RESOLVED_IPS` | Maximum authorized addresses scanned after an inventory hostname resolves; default `4`, range `1`–`16` |
| `OPENCTI_URL` | Optional OpenCTI base URL for symmetric CTI sync |
| `OPENCTI_TOKEN` | Optional OpenCTI API token for indicator, observable, label, and report sync |
| `OPENCTI_SYNC_LIMIT` | Default OpenCTI object limit per sync action |
| `OPENCTI_VERIFY_TLS` | Verify OpenCTI TLS certificates, default `true` |
| `DYNAMIC_DB_SYNC_HOUR`, `DYNAMIC_DB_SYNC_MINUTE` | Daily dynamic DB refresh time in UTC |
| `DYNAMIC_DB_IOC_SYNC_DAYS` | Daily IOC sync window, clamped to 1-7 days |
| `LOG_LEVEL` | API/worker log verbosity |
| `ATLAS_SYNC_INTERVAL` | Reference-book sync interval |

The built-in MiniMax adapter caps generated output at 2,048 completion tokens
and enables MiniMax reasoning separation. Only the final response content is
passed to AdversaryGraph's strict JSON validation; provider reasoning is not
treated as analyst-facing or machine-actionable output.

See [`local-storage-and-permissions.md`](local-storage-and-permissions.md) for
the exact local database, cache, log, and artifact storage locations.

### Unified RAG operation

The RAG corpus includes allowlisted actor sector/region/technology observations
as `actor_intel` records, stored evidence-bearing IOC/CVE actor links, and the
latest local ATT&CK group-to-technique, group-to-campaign, and
campaign-to-technique relationships. Raw provider/observation JSON is not
indexed. Actor observations have no source-level TLP column and therefore fail
closed to `TLP:AMBER+STRICT`.

When an analyst explicitly asks for IOCs, CVEs, TTPs, campaigns, or actors,
hybrid search can use shared allowlisted relationship identifiers for one
bounded full-text expansion into the requested source class. This is not a
recursive graph traversal. Operators and analysts must preserve the returned
warning: a stored link can support investigation prioritization but does not
prove current targeting, exploitation, or compromise.

`RAG_EMBEDDING_PROVIDER=local` is enforced in this release. The embedding
adapter refuses a public `LOCAL_LLM_BASE_URL`, even over HTTPS; use a loopback,
private/link-local IP, single-label service name, `host.docker.internal`, or a
recognized private service suffix. Verify model availability before setting
`RAG_EMBEDDING_ENABLED=true`.

RAG reconciliation holds a PostgreSQL session advisory lock on one dedicated
physical connection across commits. The worker database connection must
therefore be direct PostgreSQL or PgBouncer with `pool_mode=session`.
Transaction and statement pooling are unsupported for RAG workers. If the API
uses transaction pooling, configure the worker process/container separately
with a direct or session-pooled database connection. The application does not
detect or repair an incompatible PgBouncer mode.

The daily retention task uses the same corpus advisory lock. It deletes only
tombstoned derived documents older than `RAG_TOMBSTONE_RETENTION_DAYS`; active
corpus documents are never eligible. PostgreSQL cascades those deletes to the
document chunks and vectors. It separately deletes `RAGAssistance` rows older
than `RAG_ASSISTANCE_RETENTION_DAYS`, cascading to their expiring Navigator
proposals. Each bounded transaction writes a `rag.retention.purge` audit event
with counts and cutoffs, but no deleted source text or answer content.

Set either retention-day value to `0` to disable automatic deletion for that
record family. Set both to `0` for operator-controlled legal-hold mode; the
scheduled task records `rag.retention.legal_hold`. This setting does not protect
against manual database deletion and does not change snapshot, replica, export,
or backup retention. Apply the same hold/deletion policy to those systems.

For host-side MCP clients in the standard Compose deployment, set
`MCP_API_BASE_URL=http://127.0.0.1:3000`. The host does not publish API port
`8000`; that origin is only valid inside the API container or Compose network.
See [`unified-rag-and-mcp.md`](unified-rag-and-mcp.md) and
[`mcp-server.md`](mcp-server.md) for the full retrieval and integration
contracts.

### Governed Threat Hunting AI policy

Threat Hunting has a stricter AI boundary than general report extraction. The
operator-configured local OpenAI-compatible provider is the default. Cloud AI
is disabled by default for this feature even when a Claude, OpenAI, Gemini, or
MiniMax key is configured elsewhere in the deployment. Enable remote use only
after the organization approves the provider, model, data terms, processing
region, retention behavior, and permitted source markings.

The policy is enforced in two layers:

| Input or state | Permitted provider behavior |
|---|---|
| `TLP:CLEAR`, `TLP:GREEN`, or `TLP:AMBER` | Local by default; an enabled/configured remote provider also requires explicit analyst acknowledgment for the request |
| `TLP:AMBER+STRICT` or `TLP:RED` | Local-only; operator cloud enablement and analyst acknowledgment cannot override the block |
| Unsaved plan context | Local, or an enabled/configured remote provider when the draft includes an explicit eligible TLP and the analyst acknowledges remote processing; generated output remains an unsaved suggestion |
| Unsaved query, findings, or outcome context | Assistant request is blocked until the hunt exists |

The source-report selector uses completed reports or research sessions with
source text already stored in the workspace. The report carries an
authoritative server-side marking that defaults to `TLP:AMBER+STRICT`; only a
user with `manage_intel` may change it through the linked-report edit path.
Hypothesis requests may raise but cannot lower that persisted marking.
Report-to-hypothesis generation currently supports the Enterprise ATT&CK domain
only. It does not fetch an arbitrary URL or support Mobile, ICS, or ATLAS report
conversion.

Useful read-only provider discovery:

```bash
curl http://localhost:3000/api/threat-hunting/ai/providers | jq
```

Provider discovery reports four distinct states: `configured` confirms a key or
private endpoint setting is present; `available` confirms the provider may be
selected now; `status` gives a stable machine-readable reason; and `reason`
provides a safe operator-facing explanation. The local provider is checked with
a bounded, no-redirect `/models` request, including presence of
`LOCAL_LLM_MODEL`. Remote credentials are never probed merely to render the
catalog. An eligible cloud key is reported as
`status=configured_and_permitted`, not `ready`; connectivity, credential
validity, and model access are checked when a generation request runs. A cloud
key can also be `configured=true` and `available=false` with
`status=disabled_by_policy`.

Provider and model choice remains server-governed: the API rejects an
unavailable provider and a client model override that differs from the
configured model. Do not treat the `local` label as proof of network locality:
verify `LOCAL_LLM_BASE_URL`, TLS/network routing where applicable, provider-side
logging, authentication, and retention.

Before Threat Hunting sends context to a remote provider, it commits a
`threat_hunting.ai.egress.attempt` audit event containing only the correlation
ID, provider/model, effective TLP, acknowledgement state, actor, and input
checksum. A matching `threat_hunting.ai.egress.succeeded` or redacted
`threat_hunting.ai.egress.failed` event records the terminal outcome. These
events do not store the prompt, draft text, raw response, credential, or
provider exception.

For a Compose-managed private Ollama instance:

```bash
make local-ai-up
curl http://localhost:3000/api/threat-hunting/ai/providers | jq
```

The overlay is defined in `docker-compose.local-ai.yml`, uses an immutable
versioned image digest by default, stores model data in `ollama_models`, and
does not expose port `11434` on the host or LAN.

Budget CPU-hosted generation separately from cloud latency. An 8B-class model
typically needs at least 16 GB of host memory and roughly 12 GB of free disk for
the pinned runtime image, model, and update headroom. If a reviewed performance
test exceeds the default 45-second assistant deadline, raise
`THREAT_HUNTING_AI_TIMEOUT_SECONDS` for that deployment (maximum `180`) rather
than disabling request bounds.

The assistant returns `lifecycle_status=suggested` and never executes a query,
saves a hunt or finding, changes lifecycle state, selects a disposition, or
initiates an operational action. The UI's **Apply safe fields** and **Apply safe
suggestions** actions copy only permitted content into an unsaved editable hunt
draft. **Open editable draft** opens the normal unsaved finding form. The
analyst must review and save separately.

After a provider returns, the API rechecks the stored report or canonical saved
hunt used to construct the request. If it changed during generation, the API
returns a conflict and does not persist or return the stale suggestion. A later
edit does not mutate or automatically invalidate an existing append-only
assistance record; analysts must regenerate or compare that snapshot manually.

Saved-hunt requests are also bounded and disclose every active limit in the
returned and persisted warnings: 12,000 characters for the canonical query;
the newest five query versions with 6,000 query characters and 4,000
backend-assumption characters each; and the newest 50 active findings with
3,000 summary characters and 2,000 note characters each.

Each generation writes an append-only AI-assistance record containing the
optional hunt and stored-session IDs, task/stage, `suggested` lifecycle,
provider/model, prompt version, effective TLP, sanitized source references,
the recorded remote-processing acknowledgment state, citation metadata, and
bounded server-validated citation excerpts of at most 300
characters each, input/output checksums, validated structured suggestion,
warnings, and actor/time. It does not persist the raw assistant prompt, full raw
report, raw provider response, credentials, or provider exception. Continue to
protect the original report store, assistance records, hunt records, returned
citations, analyst focus text, API logs, and backups according to their
effective marking. Verify that request logging and reverse proxies do not
capture request bodies.

## Backups

Back up PostgreSQL regularly. The default data directory is external to the
containers at `./data/postgres`, but logical backups are still recommended:

```bash
./scripts/backup.sh
```

Backups are written to `${ADVERSARYGRAPH_BACKUP_DIR:-./backups}` in compressed
custom PostgreSQL format with a `.sha256` checksum. Test restore procedures
before relying on backups:

```bash
CONFIRM_RESTORE=yes ./scripts/restore.sh ./backups/adversarygraph-adversarygraph-YYYYMMDDTHHMMSSZ.dump
```

See [`backup-restore.md`](backup-restore.md) for the full procedure.

## PostgreSQL Credential Rotation

`DB_PASS` is used when the PostgreSQL data directory is first initialized. If a database
directory already exists, changing `.env` updates container environment variables
but does not change the password stored inside PostgreSQL.

Fresh clones on new machines are not affected if `.env` is created before the
first startup. The mismatch only appears after an existing `data/postgres`
directory was created with one password and `.env` is later changed to another
password.

After changing `DB_PASS` for an existing database directory in a source-build
deployment, rotate the database role password in place with the Compose helper:

```bash
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend
```

Or use the source-deployment wrapper script:

```bash
./scripts/apply-db-env-creds.sh
```

With optional authentication enabled, the wrapper reports that credential
rotation completed but exits `3` because its readiness check cannot replace an
authenticated full self-test. Complete the gate from the troubleshooting UI or
an authenticated API client with `run_analysis`, and require `status=ok`.

For a production-overlay deployment, retain both Compose files and the
`--no-build` artifact boundary throughout the rotation:

```bash
AUTH_EXISTING_ADMIN_CONFIRMED=true ./scripts/validate-production-env.sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build postgres
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile tools run --rm db-apply-env-creds
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build --force-recreate api worker beat frontend
```

The wrapper above intentionally targets source deployments; it does not infer
or add the production overlay.

The helper connects through a local PostgreSQL socket shared only between the
PostgreSQL container and the one-shot helper container. It applies the current
`.env` `DB_PASS` to the current `.env` `DB_USER` role without deleting data.
After changing `.env`, recreate the application containers so they receive the
new environment values:

```bash
docker compose up -d --force-recreate api worker beat frontend
```

AdversaryGraph passes `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASS` as
separate container variables and builds the SQLAlchemy URL inside Python. This
allows normal strong passwords with URL-special characters such as `@`, `#`,
`:`, and `/`.

Manual source-deployment equivalent:

```bash
docker compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v pass="$POSTGRES_PASSWORD" <<'"'"'SQL'"'"'
ALTER USER ag_user WITH PASSWORD :'"'"'pass'"'"';
SQL'
docker compose up -d --force-recreate api worker beat frontend
```

If the data is disposable, follow the reversible move-aside reset procedure in
[`docs/quickstart.md`](quickstart.md#troubleshooting-postgresql-password-mismatch).
`docker compose down -v` alone does not recreate PostgreSQL because the current
database is stored in the external `ADVERSARYGRAPH_DB_DIR` bind mount.

## External DB Directory Migration

Current deployments store PostgreSQL data in `ADVERSARYGRAPH_DB_DIR`, default
`./data/postgres`. Existing deployments created before this layout may still
have a Docker-managed `pg_data` volume. Migrate it once before starting the new
Compose layout:

```bash
./scripts/migrate-postgres-volume-to-external-dir.sh
docker compose up -d
```

The script refuses to overwrite a non-empty target directory. Keep
`./data/postgres` during rebuilds and upgrades; delete it only when you
intentionally want a fresh database.

## Updates

For a local source-based development environment:

```bash
git pull --ff-only
docker compose config --quiet
docker compose pull
docker compose build --pull
docker compose up -d
```

The source checkout builds the custom `adversarygraph-*:local-scan` images
locally. Their `pull_policy: never` setting makes the pull command update only
the pinned third-party runtime images rather than treating local build tags as
Docker Hub repositories. Use a current, Engine-compatible Docker Compose v2
plugin; this procedure is validated on Compose 2.40.3.

Review `CHANGELOG.md` before upgrading tagged releases.

For production-like upgrades, check out the reviewed tag and load all seven
`ADVERSARYGRAPH_*_IMAGE` digest references from that release's
`adversarygraph-images.env` attachment into `.env`, then deploy the prebuilt
artifacts without rebuilding:

```bash
./scripts/backup.sh
AUTH_EXISTING_ADMIN_CONFIRMED=true ./scripts/validate-production-env.sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-build
./scripts/selftest.sh
```

Production authentication makes the shell self-test exit `3` after confirming
readiness because it cannot inherit a browser session. Complete the gate from
the authenticated troubleshooting UI or an authenticated API client with
`run_analysis`, and require the full result to return `status=ok`.

This manifest is a v6.5 release artifact. The historical public `v6.0.0`
release does not contain it; use a later successfully gated tag or document an
equivalent independent build, scan, and digest-recording process.

For the current feature scope, review
[`docs/release-summary-v6.5.0.md`](release-summary-v6.5.0.md).

## Feeds Management

AdversaryGraph synchronizes MITRE ATT&CK STIX data for the configured
`ATTCK_DOMAINS`. The sync includes matrices, tactics, techniques,
sub-techniques, APT group profiles, campaigns, usage relationships, attribution
links, and STIX references.

Automatic sync runs daily at 03:00 UTC. Manual sync is available from the
Feeds Management page or through the API:

```bash
curl -X POST http://localhost:3000/api/sync/trigger \
  -H 'Content-Type: application/json' \
  -d '{"source":"mitre-attack","domains":["enterprise-attack"],"force":false}'
```

Set `force` to `true` to re-ingest the latest cached MITRE version even when the
database already reports the current version.

Dynamic DB sync runs daily at `DYNAMIC_DB_SYNC_HOUR:DYNAMIC_DB_SYNC_MINUTE` UTC.
It refreshes ATT&CK/ATLAS, MISP Galaxy actor metadata, and IOC enrichment sources
while preserving private/custom records in the external DB directory:

```bash
curl -X POST 'http://localhost:3000/api/sync/dynamic-db?days=7&force_attack=false'
```

## IOC Source Synchronization

IOC sync is separate from ATT&CK/ATLAS sync. ATT&CK gives stable TTP and actor
relationships; IOC feeds provide time-sensitive observables.

Supported operator-managed IOC sources:

- ThreatFox: `POST /api/ioc/sync/threatfox?days=7`
- Malpedia malware-family enrichment: `POST /api/ioc/sync/malpedia`
- OTX actor enrichment: `POST /api/ioc/sync/otx`
- registered custom feeds: `POST /api/ioc/sync/{source_id}`
- centralized action: `POST /api/sync/ioc?days=7`
- local IOC-to-TTP reprocessing: `POST /api/ioc/enrich/ttps?limit=20000`

Malpedia public family sync does not require an API key and creates
`malware-family` records with aliases, references, attribution evidence, and
actor links where family attribution matches local ATT&CK actor names or aliases.

Custom feeds can be registered from the UI or API. Keep feed URLs and API keys
inside `.env`, a secret manager, or another local operator-controlled channel.

If `AUTO_IOC_FULL_SYNC_ON_STARTUP=true`, the API starts a non-blocking full IOC
source sync after ATT&CK ingestion completes. It refreshes ThreatFox, Malpedia,
OTX, and enabled custom feeds. Missing optional API keys are reported per source
and startup continues.

IOC type normalization runs during import and IOC-to-TTP enrichment. Provider
labels such as `sha256_hash`, `filehash-sha256`, `sha1_hash`, and `md5_hash`
are merged into `sha256`, `sha1`, and `md5` where possible, including duplicate
record/link consolidation.

IOC-to-TTP mapping is evidence-prioritized:

1. strict source/report evidence from explicit ATT&CK IDs in uploaded reports,
   STIX/TAXII, MISP/custom records, or feed fields
2. enrichment-platform evidence from metadata returned by ThreatFox, OTX,
   Malpedia, VirusTotal, sandbox, Sigma/YARA, or similar feeds
3. optional AI fallback only when enabled with `ai_enrich=true`

The UI exposes this as an explicit checkbox in IOC Library and Feeds
Management. The API accepts
`ai_enrich=true&ai_provider=local|claude|openai|gemini|minimax` on `/api/sync/ioc`,
`/api/ioc/sync/threatfox`, `/api/ioc/sync/otx`, `/api/ioc/sync/{source_id}`,
and `/api/ioc/enrich/ttps`.

## Sigma / YARA / YARA-L Rule Feed Synchronization

Detection Studio supports operator-managed Sigma, YARA, and YARA-L rule feeds.
Use the Pipeline page to add the SigmaHQ default feed, the public Yara-Rules
malware feed, the Google SecOps community YARA-L tree, a private raw rule file,
a URL list, or a GitHub tree URL.

Useful endpoints:

- `POST /api/pipeline/rule-feeds/defaults`
- `POST /api/pipeline/sources` with `kind` set to `sigma`, `yara`, or `yaral`
- `POST /api/pipeline/sources/{source_id}/run`
- `GET /api/pipeline/detections/versions`

The sync imports rules into `detection_versions`, preserves the source URL in
validation metadata, and maps a rule to the first ATT&CK technique ID found in
the rule text or Sigma tags. Large feeds should use `config.limit` to keep first
syncs bounded. A successful rule-feed run also upserts the normalized Threat
Hunting Query Library index. The Query Library sync action indexes detection
versions already stored in the database without fetching external content.

Query Library access is deliberately split by permission. Analysts with
<code>run_analysis</code> can search, inspect, copy, create hunt drafts, and
build deterministic IOC queries. Indexing stored community detections requires
<code>manage_feeds</code>. See [Threat Hunting Query Library](query-library.md)
for source provenance, search syntax, API contracts, and the production review
checklist.

The Pipeline detection generator also supports YARA-L skeleton output for
Chronicle / Google SecOps-style rule handoff. Generated YARA-L rules are
structural starting points and retain the analyst-review placeholder warning.

Detection generation supports two modes:

- deterministic skeleton generation, which never calls an LLM
- AI-assisted generation through local, Claude, OpenAI, Gemini, or MiniMax
  providers

AI-generated detection content is stored as a `DetectionVersion` with generation
metadata in validation details. Treat it as analyst-review material only; test
and tune it against target telemetry before operational use.

## Sandbox Behavior Synchronization

Sandbox behavior sync imports malware detonation context into the pipeline
enrichment store. Add a pipeline source with `kind: sandbox` from the Pipeline
Sandbox tab or API:

```bash
curl -X POST http://localhost:3000/api/pipeline/sources \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "Private CAPE Export",
    "kind": "sandbox",
    "url": "https://sandbox.local/reports.json",
    "enabled": true,
    "interval_minutes": 1440,
    "config": {"limit": 100}
  }'
```

Run the feed:

```bash
curl -X POST http://localhost:3000/api/pipeline/sources/{source_id}/run
```

The feed URL should return JSON containing a report object, an array of reports,
or an object with `reports`, `data`, `results`, `analyses`, `items`, or `tasks`.
The parser extracts hashes, verdict, score, malware family, behavior signatures,
processes, network artifacts, and ATT&CK IDs. Reports are stored as
`sandbox:<feed name>` enrichment records linked to hash observables.

## Sector Intelligence Synchronization

Sector Intelligence uses local evidence tables populated from MISP Galaxy threat
actor metadata. Sync from the Sector Intel page or API before relying on sector,
region, motivation, or technology filters.

The score shown in the UI is a relevance rank. It is not attribution confidence,
maliciousness, IOC confidence, or likelihood of compromise.

## Internet-Facing Deployments

The default Compose deployment is not a hardened public SaaS. If exposing AdversaryGraph:

- Put the frontend and API behind TLS.
- Enable native authentication with `AUTH_ENABLED=true`, or use an
  authenticating reverse proxy or identity-aware gateway.
- Use the local auth guide at <http://localhost:3000/auth-guide> during setup.
- For OIDC/SAML SSO, terminate identity at a trusted reverse proxy, set
  `AUTH_SSO_MODE=oidc-proxy` or `AUTH_SSO_MODE=saml-proxy`, configure
  `PROXY_SECRET`, and forward only sanitized `X-Auth-User` / `X-Auth-Roles`
  headers to the API.
- Create permanent named admin accounts, then clear
  `AUTH_BOOTSTRAP_ADMIN_PASSWORD` and restart the API container.
- Before the first production rollout, configure either a strong temporary
  bootstrap administrator or a trusted OIDC/SAML proxy with a strong
  `PROXY_SECRET`. For later rollouts, verify that at least one named permanent
  administrator still exists before leaving the bootstrap password empty, then
  run the preflight/deployment once with
  `AUTH_EXISTING_ADMIN_CONFIRMED=true make prod`.
- Use Admin Panel to assign least-privilege SOC groups, control module access,
  review sessions, revoke sessions, reset local MFA, and inspect auth audit
  events. SOC Manager intentionally has operational and audit access without
  user, authentication, feed, or platform-configuration authority.
- To create a native user, enter a unique username, an initial password that
  satisfies the policy displayed by Admin Panel, and at least one reviewed SOC
  group. Keep the legacy role at `viewer` for ordinary group-managed accounts.
  The current form keeps **Create user** actionable and reports missing fields
  or password-policy failures immediately above it; **Creating user…** prevents
  duplicate submissions. Confirm the resulting group/module assignment and
  test sign-in in a separate private session. See the
  [complete user-creation workflow](authentication-and-users.md#create-a-named-user)
  and [troubleshooting table](authentication-and-users.md#user-creation-troubleshooting).
- Do not expose PostgreSQL or Redis publicly.
- Rotate default secrets.
- Run `./scripts/validate-production-env.sh`; it rejects known placeholders,
  short or reused database/Redis/rate-limit proxy secrets,
  wildcard/non-HTTPS CORS, disabled authentication, insecure session cookies,
  and deployments without a bootstrap/proxy/verified-existing-admin path,
  without printing secret values.
- Generate an independent `RATE_LIMIT_PROXY_SECRET` with
  `openssl rand -hex 32`. The supplied frontend Nginx overwrites any
  client-supplied rate-limit trust header and authenticates its direct TCP-peer
  IP to the API; never expose this secret to browser code or accept it from an
  outer untrusted proxy. If a TLS or identity gateway fronts the container, the
  application-level bucket normally represents that gateway. Enforce
  per-client throttling at the trusted gateway unless the original source is
  preserved through a separately reviewed connection-layer design.
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
curl http://localhost:3000/api/health
curl http://localhost:3000/api/ready
curl http://localhost:3000/api/system/selftest | jq
```

`/api/health` is a process liveness/version check. `/api/ready` also checks the
database and returns HTTP `503` when the API should not receive traffic. Use
readiness for rollout gates and load-balancer admission; use the self-test for
the broader dependency and feed diagnosis. The full self-test requires
`run_analysis` when authentication is enabled. Treat `status=degraded` as a
warning state, not a passing release result, even when every core check is
healthy.

If the self-test reports `taxonomy_normalized` as a warning, a user with
`manage_feeds` permission can select **Normalize Taxonomy** in the popup. The
same operation is available as `POST /api/system/taxonomy/normalize`; rerun the
self-test after it completes.

If `rag_index` is a warning, inspect its details before changing
configuration. A never-indexed fresh installation remains `ok` with an
instruction to run the initial reconciliation; a warning means a run or enabled
embedding path needs attention:

- `pgvector_version` is empty: deploy the bundled pgvector-capable PostgreSQL
  image or install a compatible extension on the external database, then
  restart the API;
- `documents=0`: sign in with `manage_feeds`, open **ATT&CK Navigator →
  AI RAG assistant**, and run **Build / refresh RAG index**;
- embeddings are pending/failed while lexical documents exist: keep using the
  reported exact/full-text fallback, verify the private endpoint/model and
  configured dimensions, then queue a complete retry;
- the latest run is failed or its running heartbeat is stale: review
  `/api/rag/index-runs`, worker/Redis health, and worker database pooling before
  redispatching the idempotent run.

Rerun the authenticated self-test after reconciliation and require `status=ok`
for release acceptance. Do not disable `RAG_ENABLED` merely to hide a failed
dependency unless the deployment has formally removed the feature and updated
its acceptance scope.

Open **Observability** in the sidebar, or browse directly to:

```text
http://localhost:3000/observability
```

The dashboard shows API uptime, request status counters, average and maximum API
latency, top routes, recent request traces with `X-Request-ID`, the redacted API
log tail, and a Prometheus-compatible metrics preview.

Automation endpoints:

```bash
curl http://localhost:3000/api/observability/summary | jq
curl http://localhost:3000/api/observability/traces | jq
curl http://localhost:3000/api/observability/logs | jq
curl http://localhost:3000/api/observability/metrics
```

For cloud deployments, scrape `/api/observability/metrics` through an
authenticated reverse proxy or a trusted service identity. Do not expose raw API
telemetry endpoints to the public internet.

Security validation:

```bash
make security-scan
make security-scan-strict
```

The first command is a best-effort developer scan and reports missing optional
host tools as skipped. The strict target is required for release evidence and
fails when Bandit, pip-audit, Gitleaks, Trivy, or Helm is unavailable, or when
any scan/build/render fails. `./scripts/release-readiness.sh --full` includes
that strict scan after the test and build gates.

### Reverse-proxy request boundaries

The supplied Nginx configurations cap ordinary API requests at 10 MiB and
apply explicit larger limits only to intended upload routes: 256 MiB for
MalwareGraph submissions, 64 MiB for report analysis and IOC reports, and
12 MiB for Asset Surface imports. Keep equal or tighter limits at any upstream
load balancer. Do not add a global unlimited upload exception. Within the larger
report-analysis route, `/api/analyze/chat` independently limits the analyst
message to 12,000 characters before any provider call; context and system-prompt
fields retain their smaller schema limits.

## Data Retention

Operators should define:

- How long uploaded reports are retained.
- How long append-only Threat Hunting AI-assistance records and their validated
  structured suggestions are retained.
- Whether generated reports are stored.
- Whether STIX/OpenCTI exports may be shared outside the local environment.
- Whether raw LLM responses are retained.
- Who can delete analyses.
- How backups are purged.

## OpenCTI Sync And Export

AdversaryGraph supports two OpenCTI workflows:

- **Symmetric IOC/report sync** from **Feeds Management** using:

```bash
GET  /api/ioc/opencti/status
POST /api/ioc/opencti/pull
POST /api/ioc/opencti/push
POST /api/ioc/opencti/sync
```

Pull imports OpenCTI indicators, cyber observables, labels, and reports into the
local IOC Library and analysis/report history. Push creates or updates OpenCTI
indicators and reports from local AdversaryGraph records. Bidirectional sync
pulls first, then pushes local records back out.

Configure:

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=...
OPENCTI_SYNC_LIMIT=500
OPENCTI_VERIFY_TLS=true
```

The OpenCTI token should be scoped to read indicators, observables, reports, and
labels, and to create/update indicators and reports. AdversaryGraph does not
delete OpenCTI data during sync.

When AdversaryGraph runs in Docker and OpenCTI is published on the host machine,
`OPENCTI_URL=http://localhost:8080` is automatically translated by the backend to
`http://host.docker.internal:8080` for API connectivity. The original URL is kept
as the user-facing OpenCTI URL. For a separate OpenCTI container on the same
Docker network, prefer the OpenCTI service name instead of `localhost`.

### STIX Analysis Export

AdversaryGraph can export a completed analysis as a STIX 2.1 JSON bundle from:

```bash
GET /api/export/analysis/{session_id}/stix
```

The bundle is report/TTP-centric:

- STIX `report` for the analysis session
- ATT&CK `attack-pattern` objects for extracted techniques
- optional `intrusion-set` objects for group-similarity leads
- `x_adversarygraph_*` custom fields for confidence, review status, model, provider, domain, and similarity metadata

This STIX export intentionally does not model IOCs. Similarity leads are
investigation leads based on TTP overlap and must not be treated as attribution.

For IOC handoff, use the actor IOC tab or:

```bash
GET /api/ioc/actors/{actor_id}/export.csv
```

## VirusTotal Lookup

VirusTotal integration is an on-demand enrichment workflow. It does not import
or persist VirusTotal responses.

Configure:

```env
VIRUSTOTAL_API_KEY=
```

Supported IOC types:

- IP address
- domain
- URL
- MD5
- SHA1
- SHA256

API:

```text
POST /api/ioc/virustotal/lookup
```

Request:

```json
{"indicator":"8.8.8.8","domain":"enterprise-attack"}
```

The response includes VirusTotal verdict counts, community votes, selected
detection rows, tags, threat labels, object names, crowdsourced YARA/IDS/Sigma
rules, sandbox verdicts, DNS/WHOIS/network metadata, extracted ATT&CK IDs, and
TTP evidence records.

Actor matching compares local ATT&CK group names and aliases with VT labels,
tags, filenames, crowdsourced rule text, sandbox verdicts, malware
configuration, and behavior context. The API returns the matched terms and
evidence field for each actor match.

In the UI, use `VirusTotal Lookup` to add found TTPs to `My TTPs`, show found
TTPs on the Navigator matrix, open a matched adversary page, or overlay a
matched adversary on the matrix.

## IOC Investigation

IOC Investigation is the v3.0 Tier 1 / Tier 2 / Tier 3 pivot workflow for one artifact.
It combines local IOC database evidence with configured enrichment providers and
returns source status, relationship pivots, TTP leads, actor leads, kill-chain
context, clickable graph pivots, saved investigation history, evidence ranking,
next-best pivots, timeline notes, source-conflict notes, urlscan activity
analysis, and optional AI summary output.

Optional provider settings:

| Setting | Use |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal reputation, DNS, sandbox/rule metadata, TTP evidence, and actor-alias context |
| `THREATFOX_AUTH_KEY` | ThreatFox IOC and hash lookup |
| `OTX_API_KEY` | AlienVault OTX pulse context |
| `URLSCAN_API_KEY` | Higher-limit urlscan.io search; public lookup can work without a key |
| `GREYNOISE_API_KEY` | Reserved for future GreyNoise paid API support; Community lookup is used by default without a key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP abuse confidence and ISP/hostname context |
| `SHODAN_API_KEY` | Shodan host exposure, ports, hostnames, and vulnerability context |
| `CENSYS_API_KEY` | Censys Platform host and web-property lookup pivots |
| `CENSYS_ORG_ID` | Optional Censys organization ID, sent as `X-Organization-ID`; required by Censys for broader Platform search access |

Censys Free/API-token accounts can use exact host and web-property lookup
endpoints, but broader search queries may return `403` unless the account has
an organization ID, API Access role, and a tier that includes Global Data search.
AdversaryGraph falls back to web-property lookup for domain and URL
investigations when broader Censys search is not available.

API:

```text
POST /api/ioc/investigate
```

Request:

```json
{
  "artifact": "8.8.8.8",
  "domain": "enterprise-attack",
  "depth": 2,
  "max_tier_nodes": 25,
  "ai_summarize": false,
  "ai_provider": "local"
}
```

`depth` is capped at 3 by design to keep external-provider fan-out bounded.
Missing optional keys are returned as source-level `not_configured` statuses and
do not prevent local enrichment or other configured providers from running.
