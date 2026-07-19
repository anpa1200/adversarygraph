# AdversaryGraph MCP server

The AdversaryGraph MCP server gives a local MCP client governed access to the
unified IOC, CVE, ATT&CK/ATLAS, actor sector/region/technology observation,
report, knowledge, signal, hunt, evidence, and sanitized asset index. Saved
client profiles are private request context, not corpus documents. The server
is an advisory facade over the existing AdversaryGraph REST API; it does not
connect to the database directly.

## Contents

1. [Security model](#security-model)
2. [Available tools](#available-tools)
3. [Tool contract and limits](#tool-contract-and-limits)
4. [Index lifecycle](#index-lifecycle)
5. [Prerequisites](#prerequisites)
6. [Configuration](#configuration)
7. [Start the server](#start-the-server)
8. [MCP client configuration](#mcp-client-configuration)
9. [Example workflows](#example-workflows)
10. [Operational verification](#operational-verification)
11. [Troubleshooting](#troubleshooting)

## Security model

The MCP process supports **stdio only**. It refuses to start when
`MCP_TRANSPORT` is `sse`, `streamable-http`, or any other value. AdversaryGraph
does not expose an unauthenticated remote MCP listener and does not treat a
static bearer token as sufficient protection for remote MCP transport.

The process can call only these fixed API routes:

- `POST /api/rag/search`
- `POST /api/rag/assist`
- `GET /api/rag/entity/{source_type}/{source_id}`

Redirect following and environment HTTP proxies are disabled. The configured
API URL must be an HTTP(S) origin without credentials, a path, a query, or a
fragment. Dynamic entity path segments are allowlisted, length-bounded, and
percent-encoded.

There is deliberately no MCP tool for proposal confirmation, layer saving,
RAG reindexing, feed management, attack simulation, detection forwarding, or
response action. `propose_navigator_layer` returns a reviewable suggestion only;
it never calls `/api/rag/proposals/{id}/confirm` and never changes Navigator.

`search_intelligence` and `get_indexed_entity` are read-only. The two AI tools
are non-destructive and advisory, but the governed `/rag/assist` API records an
assistance/audit artifact and can store an expiring unconfirmed proposal. Their
MCP annotations describe that distinction accurately.

All AI calls made through MCP are pinned to the configured **local** provider.
The MCP server never acknowledges cloud processing on a person's behalf. TLP
policy, local ATT&CK validation, citation binding, client-profile handling,
permissions, rate limits, and audit behavior remain enforced by the API.
The configured local OpenAI-compatible endpoint must pass the API's
loopback/private-IP/private-service-DNS check; a public model endpoint cannot be
relabeled as `local`.

Treat the MCP client and every model that receives tool results as part of the
same data-processing boundary. A `TLP:AMBER` or legally sensitive excerpt does
not become unrestricted because it was returned through MCP.

## Available tools

| Tool | Required API permission | Behavior |
|---|---|---|
| `search_intelligence` | `run_analysis` | Hybrid exact, PostgreSQL full-text, and vector retrieval with source provenance |
| `ask_intelligence` | `run_analysis` | Citation-bound local RAG answer; no operational action |
| `get_indexed_entity` | `run_analysis` | One sanitized indexed entity with bounded chunks and hashes |
| `propose_navigator_layer` | `run_analysis` | Expiring evidence-backed suggestion; never confirms, applies, or saves it |

Inputs and outputs have hard size and count limits. Supported source filters
are `attack_technique`, `attack_group`, `attack_campaign`, `actor_intel`, `ioc`,
`cve`, `analysis_report`, `knowledge`, `threat_signal`, `threat_hunt`,
`evidence_node`, and `asset`. A saved client profile is selected with
`client_profile_id`; it is private request context and is not an indexed corpus
source. Supported domains are `enterprise-attack`, `mobile-attack`,
`ics-attack`, and `atlas`.

Search can perform one bounded relationship expansion when the request
explicitly names a target class such as IOCs, CVEs, TTPs, campaigns, or actors
and that target source type is selected. The API builds that single extra
full-text search only from allowlisted identifiers on the initially retrieved
records; it does not recursively traverse a graph. Returned relationship
signals therefore require source review and are not targeting, exploitation,
attribution, or compromise proof.

See [Unified Intelligence RAG and MCP](unified-rag-and-mcp.md#indexed-source-coverage)
for the exact fields, relationships, canonical routes, handling defaults, and
exclusions for every source type. “All sources” means all twelve implemented
allowlisted collectors, not every table, raw provider response, or file on the
AdversaryGraph host.

## Tool contract and limits

| Tool | Inputs | Returned evidence | Side effects and exclusions |
|---|---|---|---|
| `search_intelligence` | `query`, optional `source_types`, `domain`, `client_profile_id`, `limit` | Bounded source cards with excerpt, route, TLP, legal flag, scores, retrieval signals, content hash, index time, and sanitized metadata | No chat generation; vector search can call the configured private embedding endpoint |
| `ask_intelligence` | `question` plus the same filters | Local-provider answer, verified citations, normalized entities, cautions, warnings, effective TLP, and optional unconfirmed proposal | Creates an assistance/audit record; never confirms or applies a proposal |
| `get_indexed_entity` | `source_type`, `source_id` | One active sanitized document and bounded chunks with hashes and embedding status | No raw authoritative row, provider JSON, secret, or arbitrary path read |
| `propose_navigator_layer` | `objective`, `domain`, optional `client_profile_id` | Local-provider answer, citations, cautions, warnings, and optional expiring proposal | Searches all enabled corpus source types; cannot accept a source filter, confirm, apply, or save |

Local MCP validation enforces these bounds before the API call:

- question, query, or objective: 1–2,000 characters;
- source ID: 1–255 characters;
- source filters: at most the twelve unique allowlisted values;
- result limit: 1–25;
- client profile ID: a positive 32-bit integer;
- domains: `enterprise-attack`, `mobile-attack`, `ics-attack`, or `atlas`;
- search response: at most 2 MiB; assistance/entity response: at most 4 MiB;
- redirects and environment proxy variables: ignored; and
- returned strings, arrays, object depth, object keys, chunk count, and total
  entity text: bounded again before reaching the MCP client.

The MCP tools do not accept `attack_version`. They operate against the current
local catalog used by the API. A proposal records that version and expires; the
browser workflow independently rechecks the active Navigator version before
application. Use the web assistant when an interactive version-pinned preview
and Add/Replace confirmation are required.

A selected `client_profile_id` must already exist. MCP can use a profile but
cannot list, create, update, or delete profiles. Create and review it in the
Navigator assistant with `manage_intel`, then give only its numeric ID to the
dedicated MCP client.

## Index lifecycle

MCP never builds or repairs the corpus. An authorized operator queues
reconciliation in Navigator or with `POST /api/rag/reindex`; Celery performs the
work. A run is persisted as `queued`, moves to `running`, and ends as
`completed`, `degraded` (lexical data usable but at least one requested
embedding failed), or `failed`.

The UI/API reuses an active run. A queued or two-hour-stale running run can be
redispatched, while a PostgreSQL session advisory lock prevents concurrent
corpus writers. Run history exposes attempt count and heartbeat. The daily
schedule reconciles source updates and tombstones removed records; a separate
daily retention task purges expired tombstones and assistance/proposal records
under the configured policy. MCP reads only active, sanitized documents.

If embedding is disabled or unavailable, exact identifier and PostgreSQL
full-text search remain valid and the response reports the actual retrieval
mode. MCP does not fabricate semantic vectors or silently switch embeddings to
a cloud service.

## Prerequisites

Before connecting a client:

1. Start AdversaryGraph and confirm `/api/ready` reports ready.
2. Reconcile the unified RAG index from the administration workflow. Empty
   retrieval is refused rather than sent to an AI model without evidence.
   RAG workers must connect directly to PostgreSQL or use PgBouncer
   `pool_mode=session`; transaction/statement pooling cannot preserve the
   worker's session advisory lock across commits.
3. Configure and verify the local LLM provider used by the RAG assistant.
4. Install the backend dependencies, including the pinned stable MCP Python
   SDK v1 release.
5. When authentication is enabled, create a dedicated account whose effective
   permissions match the tools you intend to use. Protect and rotate its
   session token.

An AdversaryGraph session token inherits the account's full permissions; it is
not a separately scoped MCP credential. Do not reuse a human administrator
token. The token also follows the configured session expiry and revocation
rules.

## Configuration

The MCP subprocess reads only these four settings; it does not require or load
database, Redis, feed, or provider credentials:

```dotenv
MCP_TRANSPORT=stdio
MCP_API_BASE_URL=http://127.0.0.1:3000
MCP_API_TOKEN=
AUTH_ENABLED=false
```

`MCP_API_BASE_URL` is the API origin, not an API route. For example, use
`https://adversarygraph.example.com`, not
`https://adversarygraph.example.com/api/rag`.

For the standard Compose deployment and an MCP client running on the Docker
host, the correct value is **`http://127.0.0.1:3000`**. Do not use host port
`8000`: the API container is intentionally not published there.

When `AUTH_ENABLED=true`, `MCP_API_TOKEN` is mandatory and must be a valid
AdversaryGraph bearer session token. The MCP process refuses to start without
it. All exposed MCP tools require `run_analysis`, so use a dedicated analyst
account with only the permissions required by this integration. Keep
`AUTH_ENABLED` consistent between the API and MCP process.

`AUTH_ENABLED=false` permits tokenless calls only for a trusted local
development instance. Never expose such an API to an untrusted network.

## Start the server

Run the process from the backend directory in the same Python environment as
the API:

```bash
cd backend
MCP_TRANSPORT=stdio \
MCP_API_BASE_URL=http://127.0.0.1:3000 \
MCP_API_TOKEN="${ADVERSARYGRAPH_SESSION_TOKEN:-}" \
python -m app.mcp_server
```

The process writes MCP protocol messages to stdout. Do not wrap it in a script
that prints banners, diagnostics, or shell tracing to stdout. Safe startup
errors are written to stderr and the process exits with status 2.

The standard Compose deployment publishes the frontend/API proxy on host port
`3000`, so a host-side MCP process uses `http://127.0.0.1:3000`. If the MCP
subprocess runs inside the API container, use `http://127.0.0.1:8000`. If it
runs in a separate Compose service, use the internal origin `http://api:8000`.
Public origins must use HTTPS; the server rejects plain HTTP outside private or
loopback networks so bearer tokens cannot cross an unencrypted public link.

## MCP client configuration

Point the client directly at the Python process. Adapt the Python path and
repository path to the installation:

```json
{
  "mcpServers": {
    "adversarygraph": {
      "command": "/opt/adversarygraph/.venv/bin/python",
      "args": ["-m", "app.mcp_server"],
      "cwd": "/opt/adversarygraph/backend",
      "env": {
        "MCP_TRANSPORT": "stdio",
        "MCP_API_BASE_URL": "http://127.0.0.1:3000",
        "MCP_API_TOKEN": "REDACTED_SESSION_TOKEN",
        "AUTH_ENABLED": "true"
      }
    }
  }
}
```

This example is the standard host-side Compose path. If the API is instead
reached through a reviewed external reverse proxy, replace the origin with its
HTTPS origin and keep the path empty; this does not change MCP's stdio-only
transport.

Store the token using the client's secret-management facility when available.
Do not commit it to a client configuration file. Restrict filesystem access to
any configuration that contains a token, and restart the MCP client after
rotating or revoking the session.

## Example workflows

### Business-relevant indicators

First create a saved profile in **ATT&CK Navigator → AI RAG assistant**, for
example:

```text
Name: Israel technology company
Sector: technology
Region: Israel
Technologies: Microsoft 365, Entra ID, AWS, Kubernetes
Crown jewels: source-code repositories, CI/CD signing, customer identity
```

Use representative categories instead of copying credentials, personal data,
or unneeded secrets into the profile. A selected profile is legally sensitive,
forces local AI, and stays outside the globally retrievable corpus.

Ask the client to call `search_intelligence` with:

```json
{
  "query": "Find IOCs relevant to an Israel-based technology company and explain the relevance signals",
  "source_types": ["actor_intel", "ioc", "attack_group", "attack_campaign", "threat_signal"],
  "domain": "enterprise-attack",
  "client_profile_id": 4,
  "limit": 20
}
```

A saved client profile is authoritative business context for reranking. Text in
the question alone is contextual, not proof that an actor targets the company.
Review source freshness, TLP, feed provenance, and the cited evidence before
blocking or escalating an indicator.

If an `actor_intel` result identifies a stored Israel/technology observation,
the API may use its allowlisted actor ID/name for one bounded search of IOC
records that store the same actor link. The observation and IOC relationship
are separate cited facts. Their combination does not prove that the IOC targets
the saved company, is currently active, or should be blocked.

Recommended review sequence:

1. Confirm the result includes the expected profile-driven
   `business_context` retrieval signal where applicable and note whether vector
   or relationship retrieval contributed.
2. Open the actor observation and IOC routes returned by the tool. Compare each
   excerpt, actor ID, relationship, source, confidence, and first/last-seen value
   with the authoritative records.
3. Call `get_indexed_entity` for a material IOC only when the bounded source
   card is insufficient. Match its content hash and source ID to the search
   result.
4. Use `ask_intelligence` only after reviewing retrieval when a cited synthesis
   is useful. Require every operational claim to map to a returned citation.
5. Create any block, hunt, incident, or response decision in its governed
   workflow. No MCP RAG tool performs that action.

### Evidence-grounded vulnerability answer

Call `ask_intelligence`:

```json
{
  "question": "Which indexed CVEs affect technologies in our saved profile, and what evidence supports prioritization?",
  "source_types": ["cve", "asset", "knowledge"],
  "domain": "enterprise-attack",
  "client_profile_id": 4,
  "limit": 20
}
```

The response retains verified `S#` citations, source identifiers, excerpts,
routes, TLP labels, retrieval mode, and cautions. Vector similarity is a
retrieval signal, not evidence of exploitation or compromise.

### Navigator suggestion

Call `propose_navigator_layer`:

```json
{
  "objective": "Map the ATT&CK techniques supported by the retrieved campaigns and reports that are relevant to our profile",
  "domain": "enterprise-attack",
  "client_profile_id": 4
}
```

The response explicitly reports `confirmation_performed=false`,
`navigator_state_changed=false`, and `saved_layer_created=false`. Review its
citations and technique list in the MCP client. The MCP surface intentionally
does not expose proposal confirmation or a web-UI handoff; generate the request
again in Navigator when browser preview/application is required. Saving a layer
is always a separate user action.

For browser application, open the matching domain and current catalog in
Navigator, select the same profile and evidence filters, and regenerate the
grounded proposal. Review every citation, select **Preview _N_ on Navigator**,
then **Review Add / Replace diff**. Only after evidence acknowledgment and the
server's freshness/version/checksum checks may the browser update its in-memory
selection. Select **Save layer** separately. The MCP proposal and regenerated
browser proposal are independent snapshots and may differ if the corpus or
catalog changed; never substitute one proposal's ID or checksum for the other.

## Operational verification

For a release or deployment review, verify all of the following:

- `MCP_TRANSPORT=stdio` is set and a non-stdio value exits before the SDK starts.
- The API origin is expected and contains no embedded credentials or path.
- The credential belongs to the intended dedicated account and has not expired.
- A token without `run_analysis` cannot invoke any MCP intelligence tool.
- An analyst token can call the tools and the resulting audit entry names the
  dedicated account.
- Every AI answer contains verified citations and each citation maps to an
  indexed source ID and content excerpt.
- Any `relationship` retrieval signal has the API warning and source evidence
  needed to distinguish a stored link from a targeting or compromise claim.
- MCP Navigator proposals remain unconfirmed advisory output; browser
  preview/application requires a new request from the Navigator assistant.
- MCP configuration and process logs do not expose the bearer token.
- Revoking the AdversaryGraph session immediately prevents subsequent MCP API
  calls.

The unit suite for this server uses no network and checks endpoint allowlisting,
input limits, path encoding, redirect/proxy disabling, credential requirements,
stdio-only startup, sanitized failures, provenance preservation, and the absence
of confirmation or mutation endpoints.

## Troubleshooting

### `MCP_API_TOKEN is required because AUTH_ENABLED=true`

Provide a non-expired bearer session token for a dedicated account. Do not turn
authentication off to bypass the error on an exposed deployment.

### `Only MCP stdio transport is supported`

Set `MCP_TRANSPORT=stdio`. Remote MCP requires a separate OAuth-protected design
and is intentionally not enabled by this server.

### `AdversaryGraph API rejected the MCP credentials or permissions`

The session may be expired/revoked, or the account lacks `run_analysis`.
Confirm the account in AdversaryGraph and issue a new session.
The MCP server intentionally does not return raw authentication response bodies.

### `Indexed evidence is unavailable or changed`

Run the governed RAG reconciliation from AdversaryGraph, wait for it to finish,
and repeat the request. The assistant refuses empty evidence and rejects an
answer if its source content changed during generation.

### The client reports malformed MCP messages

Ensure nothing writes ordinary output to stdout before or during the MCP
process. Send diagnostics and wrapper logs to stderr. Also confirm the client is
launching the backend environment that contains the pinned MCP SDK.

### Local AI is unavailable

Verify the configured local model endpoint and chat model from the RAG status
and provider diagnostics. MCP deliberately cannot switch to a cloud provider or
acknowledge cloud processing.

### Search is lexical-only or vector retrieval is unavailable

This is an explicit degraded mode, not an automatic cloud fallback. Confirm
`RAG_EMBEDDING_ENABLED`, the private endpoint and model, vector dimensions, and
the latest reconciliation's embedding counters. Exact and full-text results can
still be reviewed; repeat the reconciliation after correcting the model when
semantic retrieval is required.

### The selected business profile is rejected

Confirm that the numeric profile still exists and that the MCP session can use
`run_analysis`. MCP cannot create or discover profiles. Review or create the
profile in Navigator, then update `client_profile_id` in the tool call.

### Plain HTTP API origin is rejected

Use loopback/private service HTTP only, or an HTTPS origin for a public reverse
proxy. `MCP_API_BASE_URL` must be an origin with no `/api` path, credentials,
query, or fragment. This restriction cannot be bypassed with an environment
proxy because MCP disables proxy inheritance.
