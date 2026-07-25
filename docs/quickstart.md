# Quickstart

This guide starts a local AdversaryGraph Docker deployment for evaluation.

For the public capability walkthrough with screenshots and infographics, use
the 1200km mirror or Medium publication:

- <https://1200km.com/articles/adversarygraph-v2-self-hosted-ai-cti-platform.html>
- <https://medium.com/@1200km/adversarygraph-v2-5-new-name-new-release-full-ai-cti-platform-capability-map-93cd9224127e>

## Prerequisites

- Git, `curl`, Python 3, and standard POSIX host utilities.
- Docker Engine and its current, mutually compatible Docker Compose v2 plugin.
  This guide is validated on Compose 2.40.3; do not pair an old standalone
  Compose binary with a newer Engine.
- 4 CPU cores, 8–12 GB RAM, and at least 80 GB free storage for the small
  evaluation profile.
- OpenSSL or another cryptographically secure secret generator.
- Free local ports `3000`, `3001`, and `5432`.
- Outbound HTTPS and DNS access for Docker Hub, GitHub, Debian/Alpine package
  mirrors, PyPI, and npm during the source build and first reference ingestion.
- Optional: a configured cloud or private LLM provider for AI generation.
  Provider configuration is not required for the base platform or exact/full-text
  intelligence search.

The public browser workspace at <https://1200km.com/threat-matrix/> does not require Docker, but it also does not process private reports or store backend analyses.

## 1. Clone

```bash
git clone https://github.com/anpa1200/adversarygraph.git
cd adversarygraph
```

## 2. Configure

```bash
cp .env.example .env
```

Before starting any container, configure the three required local secrets with
different random values:

```bash
openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32
```

Copy the first generated value to `DB_PASS` and the second to
`REDIS_PASSWORD`. Copy the third to `RATE_LIMIT_PROXY_SECRET`; it authenticates
the frontend's direct TCP-peer IP header to the API. With direct frontend
access that peer is the client; behind a TLS gateway it is normally the
gateway, so enforce per-client throttling there as well. The frontend
overwrites browser-supplied forwarding headers. Do not reuse any value or leave
the `CHANGE_ME...` examples in place.

To enable cloud-backed AI features, set at least one provider key; otherwise
leave these optional values empty:

```env
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
MINIMAX_API_KEY=
MINIMAX_MODEL=MiniMax-M2.7
MINIMAX_BASE_URL=https://api.minimax.io/v1
```

For private analysis, use an operator-controlled LLM gateway and review the provider's data-retention terms.

The unified intelligence index is enabled by default. It starts in lexical mode,
so no embedding service is required for the first boot:

```env
RAG_ENABLED=true
RAG_EMBEDDING_ENABLED=false
```

To add semantic vector retrieval, configure an OpenAI-compatible private
endpoint that serves both the selected chat model and a separate embedding
model. An Ollama example is:

The simplest private deployment is the included Compose overlay. It does not
publish Ollama outside the Compose network:

```bash
make local-ai-up
```

This starts Ollama, pulls `LOCAL_LLM_MODEL`, and recreates the application
services that use it. For an 8B-class CPU model, allocate at least 16 GB of host
memory and roughly 12 GB of free disk for the runtime image, model, and update
headroom. To use the same endpoint for semantic RAG, pull the
embedding model and then enable embeddings:

```bash
docker compose -f docker-compose.yml -f docker-compose.local-ai.yml exec ollama ollama pull nomic-embed-text
```

If Ollama is already installed directly on the Docker host, use the host-managed
alternative instead:

```bash
ollama pull llama3.1:8b
ollama pull nomic-embed-text
```

```env
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_API_KEY=local
LOCAL_LLM_MODEL=llama3.1:8b
RAG_EMBEDDING_ENABLED=true
RAG_EMBEDDING_PROVIDER=local
RAG_EMBEDDING_MODEL=nomic-embed-text
RAG_EMBEDDING_DIMENSIONS=768
```

The local adapter rejects public endpoint hosts. Confirm the model's output
dimension before first indexing; changing `RAG_EMBEDDING_DIMENSIONS` on an
existing database requires an explicit schema migration and complete reindex.
Keep embeddings disabled when no reviewed private service is available—exact
identifier and PostgreSQL full-text search continue to work.

Threat Hunting provider discovery reports separate `configured`, `available`,
`status`, and `reason` values. `configured=true` confirms a credential or a
private endpoint setting exists; it does not prove the endpoint is reachable or
permitted by policy. Check the live result after startup:

```bash
curl http://localhost:3000/api/threat-hunting/ai/providers | jq
```

Optional native authentication:

```env
AUTH_ENABLED=true
AUTH_DEFAULT_ROLE=viewer
AUTH_SESSION_MINUTES=720
AUTH_BOOTSTRAP_ADMIN_USERNAME=admin
AUTH_BOOTSTRAP_ADMIN_PASSWORD=replace-with-a-strong-temporary-password
```

After startup, open <http://localhost:3000/auth-guide> for the local
authentication setup guide. Sign in with the bootstrap admin, create permanent
named admin users from **Admin Panel**, then clear
`AUTH_BOOTSTRAP_ADMIN_PASSWORD` and restart the API container.

In **Admin Panel → Create user**, supply a unique username and an initial
password that meets the displayed policy (12 characters by default), select
the least-privilege SOC group, and keep the advanced legacy role at `viewer`
for normal group-managed accounts. The action reports incomplete fields and
policy failures above the button. Confirm the new row and test sign-in before
removing the bootstrap credential. If an upgraded browser still shows a
silently disabled Create action, rebuild/recreate `frontend` and hard-refresh
the page. See
[Authentication and User Management](authentication-and-users.md#create-a-named-user).

For a production-overlay deployment, authentication is mandatory. Set an
HTTPS `CORS_ALLOWED_ORIGINS`, keep `SECURE_COOKIES=true`, and configure either
a strong one-time bootstrap administrator or a trusted OIDC/SAML proxy with a
strong `PROXY_SECRET`. An upgrade with an already verified permanent named
administrator may use the one-shot
`AUTH_EXISTING_ADMIN_CONFIRMED=true` override. Validate before rollout:

```bash
./scripts/validate-production-env.sh
make prod
```

Production deployment also requires all seven `ADVERSARYGRAPH_*_IMAGE` values
from the exact release's attached `adversarygraph-images.env`. Each value is an
immutable `repository@sha256:...` reference; `make prod` deliberately uses
`--no-build` so the deployed artifacts remain the ones covered by the release
scan evidence.

The manifest is produced by the v6.5 tag workflow and is not attached to the
historical `v6.0.0` GitHub release. Do not invent digest values or transfer scan
evidence from another build. Use the next successfully gated semantic release,
or retain an independently built, scanned, and pinned artifact set under an
equivalent local release process.

For that one-shot upgrade override, run
`AUTH_EXISTING_ADMIN_CONFIRMED=true make prod` only after confirming the named
administrator can sign in. Do not persist the override as an authentication
substitute.

Optional IOC enrichment providers:

```env
# abuse.ch ThreatFox recent IOC sync
THREATFOX_AUTH_KEY=
AUTO_IOC_FULL_SYNC_ON_STARTUP=true
AUTO_THREATFOX_SYNC_DAYS=7

# AlienVault OTX actor-attributed pulse enrichment
OTX_API_KEY=

# VirusTotal on-demand IOC reputation and relationship lookup
VIRUSTOTAL_API_KEY=

# Optional IOC Investigation pivots
URLSCAN_API_KEY=
# GreyNoise Community is used by default; no key is needed for baseline lookup.
GREYNOISE_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
CENSYS_API_KEY=
CENSYS_ORG_ID=

# OpenCTI symmetric sync
OPENCTI_URL=
OPENCTI_TOKEN=
OPENCTI_SYNC_LIMIT=500
OPENCTI_VERIFY_TLS=true

# Daily dynamic DB refresh schedule in UTC
DYNAMIC_DB_SYNC_HOUR=3
DYNAMIC_DB_SYNC_MINUTE=30
DYNAMIC_DB_IOC_SYNC_DAYS=7
```

Leave these blank if you only want ATT&CK/ATLAS mapping, sector relevance, and
manual/private IOC imports.

Feed and key behavior:

- MITRE ATT&CK / ATLAS sync uses public STIX bundles and does not require an API key.
- Built-in MISP Galaxy metadata sync is public and does not require a MISP key.
- `AUTO_IOC_FULL_SYNC_ON_STARTUP=true` starts a non-blocking IOC source sync after API startup.
- `THREATFOX_AUTH_KEY` enables abuse.ch ThreatFox recent IOC sync.
- `OTX_API_KEY` enables AlienVault OTX actor-attributed pulse enrichment.
- `VIRUSTOTAL_API_KEY` enables on-demand IOC checks from IOC Library and VirusTotal Lookup.
- `URLSCAN_API_KEY`, `SHODAN_API_KEY`, `ABUSEIPDB_API_KEY`, `CENSYS_API_KEY`,
  and optional `CENSYS_ORG_ID` enable IOC Investigation pivots. Public urlscan
  responses may work without a key within provider limits. GreyNoise Community
  is used by default without a key. Shodan, AbuseIPDB, and Censys require keys
  for their API paths.
- `OPENCTI_URL` and `OPENCTI_TOKEN` enable Feeds Management actions for OpenCTI pull, push, and bidirectional sync.
- MISP event/attribute JSON exports, STIX bundles, TAXII collection URLs, custom JSON/CSV/TXT feeds, Sigma/YARA feeds, and sandbox behavior feeds are connected from the UI or API as source URLs/tokens.
- Never commit a filled `.env` file.

When `AUTO_IOC_FULL_SYNC_ON_STARTUP=true`, the API automatically starts a background
full IOC source sync after Docker startup. It refreshes ThreatFox, Malpedia, OTX,
and enabled custom feeds. Missing optional API keys are reported per source and
do not block startup.

PostgreSQL data is stored outside the containers in `ADVERSARYGRAPH_DB_DIR`
(`./data/postgres` by default). This folder is created on first deployment and
must be kept when rebuilding containers. It stores private reports, custom IOCs,
custom feeds, and synced public reference data.

## 3. Start

```bash
docker compose config --quiet
docker compose pull
docker compose up -d --build
docker compose ps
```

The default checkout is a source-build stack. `docker compose pull` refreshes
the pinned BusyBox, Redis, and Nginx runtime images and skips every buildable
`adversarygraph-*:local-scan` target. The following `up --build` command builds
the seven custom image families locally. It does not require Docker Hub
repositories named `adversarygraph-*`.

Do not point source installs at mutable GHCR `latest` tags. The historical
`v6.0.0` release contains only five of the seven current image families and has
no `adversarygraph-images.env` digest manifest. A prebuilt production rollout
requires a later successfully gated release—or an independently built, scanned,
and digest-pinned artifact set. The release workflow currently publishes
Linux/AMD64 images; other architectures use an independently validated source
build until a multi-architecture release gate is implemented.

First startup creates the external DB directory, installs the bundled pgvector
extension, creates the RAG tables and indexes, and ingests MITRE ATT&CK STIX
data into PostgreSQL. This can take several minutes. Source ingestion does not
automatically mean the derived RAG corpus is ready; queue the first
reconciliation after startup.

## 4. Open

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| API docs | http://localhost:3000/docs |
| Liveness | http://localhost:3000/api/health |
| Readiness | http://localhost:3000/api/ready |
| Anomaly Detection Atlas | http://localhost:3001/anomaly-detection-atlas/ |

The Compose ports bind to server loopback by design. From a remote workstation,
use an SSH tunnel for evaluation instead of opening the ports publicly:

```bash
ssh -L 3000:127.0.0.1:3000 -L 3001:127.0.0.1:3001 user@server
```

Then open `http://localhost:3000` on the workstation. For shared or production
access, use a reviewed authenticated TLS reverse proxy rather than a public
Docker port.

## 5. Smoke Test

```bash
curl http://localhost:3000/api/health
curl http://localhost:3000/api/ready
curl "http://localhost:3000/api/attack/versions"
curl http://localhost:3000/api/rag/status
```

Expected health response:

```json
{"status":"ok","version":"6.5.0"}
```

The readiness response is `200` with `status: "ready"` when the database can
serve traffic and `503` with `status: "not_ready"` otherwise.

Run the deployment self-test:

```bash
docker compose run --rm selftest
```

The self-test validates API startup, database connectivity, Redis,
ATT&CK/ATLAS data ingestion, the pgvector extension, RAG corpus state, and
provider key configuration without exposing secret values. A fresh deployment
waits up to fifteen minutes for reference ingestion before evaluating the full
self-test; set `SELFTEST_TIMEOUT` when the host wrapper needs a longer window.
The containerized self-test uses the same fifteen-minute startup gate. A fresh
deployment with no RAG run and an empty corpus remains `ok` and tells the
operator to run the initial reconciliation. The RAG check becomes degraded
after a failed or degraded run, a completed-but-empty run, failed embeddings,
or enabled embeddings without completed vectors. The same check is available
in the UI through error-popup `Recheck` actions and the internal troubleshooting
page:

```text
http://localhost:3000/troubleshooting
```

When authentication is enabled, the container command checks database-backed
`/api/ready` if `/api/system/selftest` is protected, reports that the full gate
is inconclusive, and exits `3`. Sign in with a user that has `run_analysis` and
confirm the full result is `status=ok`; `degraded` means at least one warning
still needs remediation or explicit risk acceptance.

The API service is intentionally not published as `localhost:8000` by the
default Compose file. Use the frontend proxy at `localhost:3000/api/...` unless
you deliberately add a development override.

Queue the initial corpus from **ATT&CK Navigator → AI RAG assistant →
Build / refresh RAG index**. This action requires `manage_feeds` when
authentication is enabled. An unauthenticated local evaluation can use the API:

```bash
curl -sS -X POST http://localhost:3000/api/rag/reindex \
  -H 'Content-Type: application/json' \
  --data '{"source_types":[],"include_embeddings":true}'
```

Poll `GET /api/rag/status` or review `GET /api/rag/index-runs?limit=10` until the
run is complete. With embeddings disabled, `include_embeddings` is safely
reduced to lexical indexing. With authentication enabled, use the UI or add a
valid session bearer token from a least-privilege account; never paste a token
into documentation, shell history, or screenshots.

## Troubleshooting: PostgreSQL Password Mismatch

If the API exits during startup with:

```text
asyncpg.exceptions.InvalidPasswordError: password authentication failed for user "ag_user"
```

the external PostgreSQL data directory was probably created with an older
`DB_PASS`. Docker does not reinitialize an existing database directory when
`.env` changes.

This does not affect a fresh clone on a new machine when `.env` is created
before the first `docker compose up --build`. In that case, PostgreSQL
initializes the new directory with the current `DB_NAME`, `DB_USER`, and `DB_PASS`
values.

For a development deployment where you can discard local database state, stop
the stack and move the database directory aside. The move is intentionally
reversible:

```bash
docker compose down
mv ./data "${HOME}/adversarygraph-data-pre-reset-$(date -u +%Y%m%dT%H%M%SZ)"
docker compose up -d --build
```

Moving the whole default `./data` tree from the repository-owned parent works
even when PostgreSQL created container-owned children. The destination is
outside the Git checkout so the private database cannot become an accidental
untracked commit. Store it on a protected filesystem with adequate capacity. If
`ADVERSARYGRAPH_DB_DIR` points elsewhere, move that configured directory from
a writable parent instead; an administrator may need to perform the move.

`docker compose down -v` alone does **not** reset PostgreSQL because the
database is a host bind mount. It removes other named runtime volumes while
leaving the password mismatch intact.

To keep the existing database, apply the current `.env` credentials to the
existing PostgreSQL role:

```bash
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend
```

Or use the wrapper script:

```bash
./scripts/apply-db-env-creds.sh
```

With optional authentication enabled, the wrapper reports that credential
rotation completed but exits `3` because its readiness check cannot replace an
authenticated full self-test. Complete the gate from the troubleshooting UI or
an authenticated API client with `run_analysis`, and require `status=ok`.

Manual equivalent:

```bash
docker compose exec -T postgres sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v pass="$POSTGRES_PASSWORD" <<'"'"'SQL'"'"'
ALTER USER ag_user WITH PASSWORD :'"'"'pass'"'"';
SQL'
docker compose up -d --force-recreate api worker beat frontend
```

## 6. Demo Workflow

1. Open the frontend.
2. Select Enterprise ATT&CK.
3. Paste a public CTI excerpt from `docs/demo-dataset/public-report-excerpt.md`.
4. Run analysis with the configured provider.
5. Review the extracted techniques.
6. Compare against known groups and campaigns.
7. Export a Navigator layer, JSON report, or PDF report.

Do not use confidential reports in public or third-party environments.

## 7. v2.1 Sector And IOC Workflow

1. Open Feeds Management and sync MISP Galaxy sector metadata.
2. Open Sector Intel.
3. Select one or more sectors, optional regions, and optional technologies.
4. Review ranked actors and use Actor info, TTP info, IOCs, or Show on matrix.
5. Open ATT&CK Group Library and select an actor.
6. Use Feeds Management or the IOCs tab to sync ThreatFox, Malpedia, and OTX.
7. Add a custom feed, import IOCs, or upload a private report for IOC extraction.

Malpedia adds malware-family enrichment records with aliases, references, and
actor attribution evidence. These records are context, not network IOCs.

## 8. VirusTotal IOC Lookup

Set `VIRUSTOTAL_API_KEY` in `.env`, restart the API, and open:

```text
http://localhost:3000/virustotal
```

Paste an IP, domain, URL, MD5, SHA1, or SHA256. The page shows a structured
VirusTotal summary and provides actions to add found TTPs to `My TTPs`, show
found TTPs on the matrix, and open any matched local adversary profile. It also
shows VT rule, sandbox, DNS/WHOIS, and evidence snippets for extracted TTPs and
actor links when those fields are present in the VT response.

## 9. IOC Investigation

Open:

```text
http://localhost:3000/ioc-investigation
```

Paste an IP, domain, URL, hash, or suspicious artifact. Select Tier 1, Tier 2,
or Tier 3 expansion. AdversaryGraph checks the local IOC database and configured
enrichment sources, then returns source status, relationship pivots, ATT&CK TTP
leads, possible actor leads, kill-chain/tactic context, source-conflict notes,
next-best pivots, and optional AI summary input.

Useful actions after a result:

- show discovered TTPs on Navigator
- add discovered TTPs to `My TTPs`
- search the artifact in IOC Library
- continue in VirusTotal Lookup
- save, reopen, or delete the investigation
- open graph nodes as follow-up IOC pages

## 10. Business-Context RAG And Navigator Workflow

1. Open **ATT&CK Navigator** and select **AI RAG assistant**.
2. Confirm the readiness card reports a non-empty corpus. If not, ask a user
   with `manage_feeds` to queue reconciliation and wait for completion.
3. Create a business profile such as:
   - name: `Israel Technology Company`
   - sector: `technology`
   - region: `Israel`
   - technologies: the organization's actual cloud, identity, endpoint, and
     product stack
   - crown jewels: the systems or data classes that matter most
4. Select the profile and the **IOCs**, **Actors**, **Reports**, **CVEs**, and
   **TTPs** source filters.
5. Search without generation first:

   ```text
   Find IOCs relevant to this business. Explain which stored actor, campaign,
   CVE, or TTP relationship caused each result to rank.
   ```

6. Open the cited platform records. Validate indicator type, source, confidence,
   freshness, TLP, relationship evidence, and whether the source actually
   describes the organization's operating context.
7. Run the grounded assistant only after retrieval looks useful. Remote provider
   use requires explicit acknowledgment and remains blocked for local-only
   handling markings.
8. Ask for a matrix proposal:

   ```text
   Propose all ATT&CK techniques relevant to this business from the cited
   evidence and preview them on Navigator.
   ```

9. Review the citation set and temporary overlay. Confirm **Add** or **Replace**
   only if the proposal is appropriate. Save a named Navigator layer separately
   if the reviewed selection should persist.

Business-profile and relationship matches are prioritization signals, not proof
of targeting, active infrastructure, exploitation, or compromise. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md) for the complete
data, security, retention, and troubleshooting contract.
