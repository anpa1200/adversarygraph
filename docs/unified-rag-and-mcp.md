# Unified Intelligence RAG and MCP

AdversaryGraph can build one provenance-preserving retrieval corpus over its
IOC, CVE, ATT&CK, actor, actor sector/region/technology observations, campaign,
report, knowledge, Threat Radar, Threat Hunting, Evidence Graph, and sanitized
asset records. A selected client profile is used as private
reranking/generation context but is not added to the globally retrievable
corpus. The Navigator-level AI assistant uses that corpus to answer questions
with exact source cards and to propose ATT&CK techniques for explicit analyst
confirmation.

This feature is advisory. Search and generation do not contact an IOC, execute
a query, exploit a CVE, change Navigator state, save a layer, or perform a
response action.

## Contents

1. [Architecture](#architecture)
2. [Indexed source coverage](#indexed-source-coverage)
3. [Security and governance](#security-and-governance)
4. [Configure embeddings](#configure-embeddings)
5. [Build and maintain the corpus](#build-and-maintain-the-corpus)
6. [Business-context IOC workflow](#business-context-ioc-workflow)
7. [Navigator TTP proposal workflow](#navigator-ttp-proposal-workflow)
8. [REST API](#rest-api)
9. [MCP server](#mcp-server)
10. [Operations](#operations)
11. [Troubleshooting](#troubleshooting)
12. [Known boundaries](#known-boundaries)

## Architecture

```text
Authoritative AdversaryGraph tables
  -> allowlisted source collectors (never raw provider JSON)
  -> canonical RAG documents
  -> bounded, overlapping source chunks
  -> PostgreSQL full-text index + pgvector HNSW cosine index
  -> exact identifier lookup + lexical search + vector search
  -> reciprocal-rank fusion + business-profile relevance reranking
  -> optional bounded one-hop expansion over allowlisted relationship IDs
  -> source excerpts, routes, TLP, freshness, scores, and warnings
  -> governed AI synthesis with mandatory verified citations
  -> optional expiring Navigator proposal
  -> explicit analyst preview and Add/Replace confirmation
```

Vectors stay in the same PostgreSQL boundary as the source records. This keeps
transaction, backup, deletion, and provenance behavior together. The vector is
a retrieval aid; it is not evidence confidence or attribution probability.

The corpus is normalized instead of adding an embedding column to every source
table. Source updates change the document hash, replace its chunks, and make old
chunks unavailable. Removed records are tombstoned during reconciliation.

### Relationship-aware retrieval

The normalized corpus retains specific relationships already present in the
authoritative tables:

- `actor_intel` documents contain stored actor sector, region, and technology
  observations, including confidence, dates, stored evidence when present,
  and a sanitized source reference. Their raw JSON is never indexed. Because
  the source model has no per-observation TLP field, these documents fail closed
  to `TLP:AMBER+STRICT`.
- IOC documents include stored actor-link identifiers, relationship type,
  confidence, source ID, and evidence. CVE documents include their stored
  actor, IOC, and ATT&CK-technique link records with the same evidence fields.
- The latest local ATT&CK technique, group, and campaign documents include the
  normalized group-to-technique `uses`, group-to-campaign `attributed-to`, and
  campaign-to-technique `uses` relationships and their available usage text.

After exact/full-text/vector fusion, a question that explicitly asks for IOCs,
CVEs, TTPs/techniques, campaigns, or actors can run one additional full-text
search for that requested entity class. The expansion uses only allowlisted
relationship metadata from at most 24 initial candidates and at most 32 shared
identifiers. It does not traverse the newly found records again, execute an
arbitrary graph query, or infer an unrecorded multi-hop path. The requested
target source type must also be enabled in the request's `source_types` filter.

Expanded results carry the `relationship` retrieval signal and a warning. A
shared actor or technique identifier is a review lead: it does not establish
that an actor targets the selected business, that an IOC is currently active
against it, that a CVE was exploited, or that compromise occurred. Indexing a
stored relationship also does not independently approve or re-verify its
source evidence.

## Indexed source coverage

“Unified” means one search contract over the following implemented,
field-allowlisted collectors. It does **not** mean that every database table or
every column is embedded. Each result links back to its authoritative platform
record; the RAG document and chunks are derived search data.

| API source type | Included records and fields | Important stored relationships | Default route and handling |
|---|---|---|---|
| `attack_technique` | Latest, non-deprecated ATT&CK/ATLAS technique description, parent, platforms, data sources, tactics, and detection text | Stored ATT&CK group-use descriptions and actor IDs | Navigator technique; `TLP:CLEAR` |
| `attack_group` | Latest group description, aliases, dates, and ATT&CK usage | Technique and attributed-campaign IDs with available ATT&CK usage text | APT group view; `TLP:CLEAR` |
| `attack_campaign` | Latest campaign description, first/last seen, actors, and ATT&CK usage | Group and technique IDs with available ATT&CK usage text | APT campaign view; `TLP:CLEAR` |
| `actor_intel` | Stored sector, region, and technology observations, confidence, dates, evidence, and sanitized source reference | Actor ATT&CK ID and name | APT group or Sector Intelligence; forced `TLP:AMBER+STRICT` |
| `ioc` | Observable, type, description, malware/campaign labels, ATT&CK IDs, dates, confidence, source name, and tags | Stored actor links and available source evidence | IOC record; normalized stored TLP, malformed/unknown values fail closed |
| `cve` | CVE description, status, CVSS, CWEs, CPEs, KEV fields, dates, and tags | Stored technique, actor, and IOC-record links with available source evidence | CVE search; public-only records are `TLP:CLEAR`, linked IOC markings are inherited, and actor/unresolved relationship provenance fails closed to `TLP:AMBER+STRICT`; actor/IOC relationship evidence is legal-sensitive |
| `analysis_report` | Completed stored report source text, generated summary, extracted technique IDs, and actor candidates | Extracted technique and actor identifiers | Analysis report; stored report TLP |
| `knowledge` | Article title, summary, body, category, tags, and publication date | No graph expansion beyond identifiers present in the text | Knowledge article; `TLP:CLEAR` |
| `threat_signal` | Signal description, state, severity, confidence, CVEs, TTPs, IOCs, actors, sectors, tags, and source name | Stored CVE, technique, IOC, actor, and sector values | Threat Radar signal; stored TLP and legal-sensitive flag |
| `threat_hunt` | Canonical hunt hypothesis, scope, status, priority, telemetry, current query, expected evidence, assumptions, result, disposition, and tags | Stored technique and tactic IDs | Threat Hunt; stored TLP and always legal-sensitive |
| `evidence_node` | Evidence Graph statement, behavior, observable, technique, data, detection, scenario, decision, rationale, and review fields | Stored technique identifier | Evidence Graph node; forced `TLP:AMBER+STRICT` and legal-sensitive |
| `asset` | Sanitized inventory identity, exposure, criticality, addresses, domains, ports, technologies, products, supply chain, risk, and tags | Stored technique IDs | Asset Surface record; forced `TLP:AMBER+STRICT` and legal-sensitive |

The collectors deliberately exclude connector/authentication credential
fields, feed configuration, authentication and audit tables, raw feed/provider
JSON, arbitrary metadata, raw model prompts/responses, and arbitrary filesystem
content. They do not run a general DLP or secret-redaction engine over
allowlisted source text. A stored report, Knowledge article, evidence statement,
IOC description, or other included narrative can therefore carry whatever the
operator stored in it. Remove unnecessary secrets and set the correct TLP/legal
marking before ingestion. In this feature, `sanitized` means the document was
built through a field allowlist and normalization policy; it is not a guarantee
that free text contains no sensitive value. The canonical Threat Hunt collector
does not independently ingest all query-version or finding rows.

## Security and governance

The implementation applies these controls before provider output reaches the
UI:

- Only curated, allowlisted fields are indexed. Raw IOC, CVE, feed, STIX, asset,
  or provider payloads are not copied into embedding input, but allowlisted
  narrative fields are not automatically DLP-redacted.
- Unsanitized documents are excluded from exact, lexical, vector, and entity
  reads before ranking.
- Every chunk retains source type, stable source ID, canonical route, TLP,
  content hash, source version, and index time.
- Asset inventory and selected client-profile context is treated as legally
  sensitive and `TLP:AMBER+STRICT` for provider-egress decisions. Client
  profiles are not indexed as globally retrievable corpus documents.
- Actor-intelligence observations are also indexed as `TLP:AMBER+STRICT` because
  their source table does not store a validated per-observation distribution
  marking.
- `TLP:AMBER+STRICT`, `TLP:RED`, and legally sensitive results cannot be sent to
  a cloud model. Selecting a remote provider cannot override this rule.
- Eligible cloud generation is disabled until the operator enables the existing
  governed cloud-AI boundary, and every request needs analyst acknowledgment.
- Retrieved text is placed in an explicitly untrusted-data section. Instructions
  inside reports or feeds do not become system instructions or tool calls.
- Provider output must match a strict JSON schema, cite known `[S#]` source
  references, and use those markers in the answer. Unknown citations fail the
  request.
- Every proposed ATT&CK ID is verified against the selected domain's current
  local catalog. Model-invented, deprecated, malformed, cross-domain, or stale
  IDs are removed or reject the proposal.
- The API rechecks chunk hashes after generation. If the corpus changed during
  the provider call, the answer is rejected as stale.
- Assistance and proposal records preserve checksums, provider/model, TLP,
  source references, retrieval mode, warnings, and audit attribution. A remote
  provider attempt is audited before egress so a timeout or rejected output
  cannot erase that fact. Provider error bodies and raw prompts are not
  persisted.

AdversaryGraph remains a single-workspace application. It does not currently
provide tenant-level ownership on every source table. Do not use one instance
to isolate mutually untrusted customers. Deploy separate instances when a hard
customer boundary is required.

## Configure embeddings

Embeddings are disabled by default. When enabled, the configured default is a
private OpenAI-compatible endpoint using `nomic-embed-text` with 768
dimensions. For Ollama on the Docker host:

```bash
ollama pull nomic-embed-text
```

Relevant `.env` settings:

```dotenv
LOCAL_LLM_BASE_URL=http://host.docker.internal:11434/v1
LOCAL_LLM_API_KEY=local

RAG_ENABLED=true
# Change to true after the private model is pulled and reachable.
RAG_EMBEDDING_ENABLED=false
RAG_EMBEDDING_PROVIDER=local
RAG_EMBEDDING_MODEL=nomic-embed-text
RAG_EMBEDDING_DIMENSIONS=768
RAG_EMBEDDING_BATCH_SIZE=32
RAG_VECTOR_MAX_COSINE_DISTANCE=0.55
RAG_CHUNK_CHARS=3500
RAG_CHUNK_OVERLAP_CHARS=350
RAG_DEFAULT_RESULT_LIMIT=12
RAG_MAX_CONTEXT_CHARS=32000
RAG_RECONCILE_HOUR=4
RAG_RECONCILE_MINUTE=15
RAG_TOMBSTONE_RETENTION_DAYS=30
RAG_ASSISTANCE_RETENTION_DAYS=90
RAG_RETENTION_BATCH_SIZE=1000
RAG_RETENTION_MAX_BATCHES=20
RAG_RETENTION_HOUR=4
RAG_RETENTION_MINUTE=45
```

`RAG_EMBEDDING_PROVIDER` is deliberately restricted to `local` in this
release. The adapter also refuses `LOCAL_LLM_BASE_URL` unless its host is a
loopback, private/link-local IP, single-label private service name,
`host.docker.internal`, or a recognized private service suffix such as
`.internal`, `.local`, `.localhost`, `.svc`, or `.test`. A public endpoint cannot
be made eligible by naming the provider `local`. The URL may include the
OpenAI-compatible API path (for example `/v1`) but must not contain credentials,
a query, or a fragment.

Corpus records and analyst search text are therefore not sent to a cloud
embedding service. Remote chat generation remains a separate governed boundary
with operator enablement, per-request acknowledgement, and TLP/legal policy
enforcement.

`RAG_EMBEDDING_DIMENSIONS` is part of the PostgreSQL column definition. Do not
change it on an existing corpus without a reviewed schema migration and full
reindex. Startup fails with an explicit mismatch instead of querying a column
with the wrong dimensions. The embedding endpoint must return exactly that many
finite numeric values for every input.

`RAG_VECTOR_MAX_COSINE_DISTANCE` drops weak semantic neighbours before rank
fusion. Lower values are stricter. Tune it with reviewed relevance fixtures;
never present the rank-fusion score as confidence or attribution probability.

Set `RAG_EMBEDDING_ENABLED=false` when no approved embedding service is
available. Exact-identifier and full-text search continue to work, and API/UI
responses explicitly report lexical-only retrieval. AdversaryGraph does not
substitute a deterministic hash and call it a semantic embedding.

After verifying the private embedding endpoint, set
`RAG_EMBEDDING_ENABLED=true`, restart the API/worker/beat services, and queue a
full reconciliation. Compose and Helm default this setting to `false` so a
missing model does not degrade a fresh production deployment.

For the standard Compose deployment, apply the PostgreSQL image and RAG
configuration together, then verify readiness before queuing the corpus:

```bash
docker compose up -d --build postgres api worker beat frontend
docker compose ps postgres api worker beat frontend
curl -sS http://127.0.0.1:3000/api/ready
curl -sS http://127.0.0.1:3000/api/rag/status \
  -b 'ag_session=<session-token>'
```

Do not enable vector search merely because the container starts. Verify a real
embedding request returns exactly the configured finite-vector dimensions,
then reconcile and confirm non-zero `chunks_embedded`. A production smoke test
must use the deployment's actual private model; mocked unit tests validate the
protocol and policy contract but do not prove that model availability, quality,
or network routing.

The bundled PostgreSQL image installs pgvector. An external PostgreSQL 16
service must install pgvector before the API starts, because startup executes:

```sql
CREATE EXTENSION IF NOT EXISTS vector;
```

The database role therefore needs permission to create that already-installed
extension during initial deployment, or an administrator must create it first.

## Build and maintain the corpus

Index reconciliation runs in Celery. It does not embed the whole corpus during
API startup.

An account with `manage_feeds` can queue the first build:

- In **ATT&CK Navigator → AI RAG assistant** (dialog title: **Intelligence RAG
  assistant**), select **Build / refresh
  RAG index** when the readiness card reports an empty corpus; or
- call the API directly:

```bash
curl -sS -X POST http://localhost:3000/api/rag/reindex \
  -H 'Content-Type: application/json' \
  -b 'ag_session=<session-token>' \
  --data '{"source_types":[],"include_embeddings":true}'
```

An empty `source_types` array means every supported source. Poll:

```bash
curl -sS http://localhost:3000/api/rag/status \
  -b 'ag_session=<session-token>'

curl -sS 'http://localhost:3000/api/rag/index-runs?limit=10' \
  -b 'ag_session=<session-token>'
```

The worker writes source documents before calling an embedding endpoint, and
does not keep an open database transaction during provider egress. If the
embedding service is down, the run becomes partial/degraded while lexical
retrieval remains usable. A later reconciliation retries pending chunks.

The persisted run normally moves from `queued` to `running`, then to one of
these terminal states:

- `completed`: selected sources reconciled and every requested embedding was
  created;
- `degraded`: the lexical corpus is usable, but one or more requested
  embeddings failed or were policy-blocked; or
- `failed`: reconciliation itself failed; inspect the bounded worker error and
  requeue after correcting the dependency or data problem.

Run history exposes source selection, document/chunk counters, embedding
counters, `attempt_count`, `heartbeat_at`, bounded failure summary, and start
and completion timestamps. Enqueue calls are idempotent: a queued run is
redispatched, a fresh running run is reused, and a running run with no heartbeat
for two hours can be redispatched. The worker's corpus advisory lock remains the
authoritative single-writer guard; lock contention retries after 15 seconds
rather than creating a second writer. A broker publication failure leaves the
persisted run recoverable for the next UI, API, or scheduled enqueue.

Celery Beat queues a daily reconciliation at `RAG_RECONCILE_HOUR` and
`RAG_RECONCILE_MINUTE` in UTC. UI and scheduled requests reuse an active run,
and workers also hold a corpus-wide PostgreSQL advisory lock so different run
IDs cannot replace the shared chunks concurrently.

The reconciliation worker holds a PostgreSQL **session** advisory lock on one
dedicated physical connection across commits and binds all corpus reads/writes
to that connection. Connect the RAG worker directly to PostgreSQL or through
PgBouncer with `pool_mode=session`. PgBouncer transaction or statement pooling
is not supported for this worker: it can move later transactions to another
server session, separating the corpus work from the lock that guards it. If the
API uses a transaction-pooled DSN, give the worker process its own direct or
session-pooled database configuration. AdversaryGraph does not auto-detect or
correct an incompatible PgBouncer mode.

### Derived-data retention

Celery Beat starts `rag.retention_purge` daily at
`RAG_RETENTION_HOUR:RAG_RETENTION_MINUTE` UTC (default `04:45`). The task uses
the corpus advisory lock, so it defers instead of deleting while reconciliation
owns the corpus. Each transaction deletes at most
`RAG_RETENTION_BATCH_SIZE` rows from each eligible record family, and a run
performs at most `RAG_RETENTION_MAX_BATCHES` transactions.

- Inactive RAG documents whose tombstone time is older than
  `RAG_TOMBSTONE_RETENTION_DAYS` are deleted. Their chunks, full-text rows, and
  vectors are removed by the database foreign-key cascade. Active documents are
  never eligible.
- Assistance records older than `RAG_ASSISTANCE_RETENTION_DAYS` are deleted.
  Associated Navigator proposals are removed by cascade. The platform audit
  event retains counts and policy cutoffs, not the deleted answer or excerpts.
- Index-run history and platform audit events are not deleted by this RAG
  retention task. Apply a separate, approved database/audit retention policy to
  them; do not assume the assistance window covers those records.
- The defaults are 30 days for tombstones and 90 days for assistance. Set a day
  value to `0` to disable automatic deletion for that family. Setting both to
  `0` is the platform's operator-controlled legal-hold mode and produces a
  `rag.retention.legal_hold` audit event.

Retention is based on the derived record's tombstone/index time or assistance
creation time, not the source intelligence's observation time. Legal-hold mode
does not make records immutable and does not govern manual SQL, exports,
replicas, snapshots, or backups. Apply the same hold and deletion policy to
those systems. To enqueue an out-of-schedule run after changing policy:

```bash
docker compose exec worker \
  celery -A app.tasks.celery_app call rag.retention_purge
```

## Business-context IOC workflow

Open **ATT&CK Navigator**, then open **AI RAG assistant**. The assistant supports
source filters and an optional saved client profile.

An analyst with `manage_intel` can select **Create business profile** in the
assistant and save a name, sector, region, technologies, and crown jewels. The
profile stays outside the globally retrievable corpus; its terms expand the
current lexical/private-vector query and deterministically rerank results.

To investigate “find IOCs relevant for my business: Israel tech company”:

1. Confirm the index readiness card is ready. If it is empty, a user with
   `manage_feeds` selects **Build / refresh RAG index** and waits for the run to
   finish. A search during a partial embedding outage can still use exact and
   full-text retrieval.
2. Create or select a business profile such as **Israel technology company**.
   Set `sector=technology`, `region=Israel`, list the technologies actually in
   use, and identify crown jewels at a useful but non-secret level. Selecting a
   saved profile makes those server-loaded fields authoritative reranking
   context; typing the same words only in the question does not.
3. Keep **IOCs** and **Actors** selected. Add **Reports** when report, Knowledge,
   Threat Radar, hunt, and Evidence Graph context should contribute; add
   **Assets** only when its local-only handling is intended. The six UI groups
   expand to the twelve API source types in the coverage table.
4. Enter the question below. Use **Search evidence** first when you want only
   deterministic retrieval. Use **Generate grounded answer** when you also want
   a cited synthesis from a configured provider.

   ```text
   Find recent IOCs relevant to this saved business profile. Separate direct
   facts from relationship-based relevance. For each IOC show the actor or
   campaign link, source, first/last seen, confidence, freshness limitation,
   and why the profile affected ranking. Do not claim targeting or compromise.
   ```

5. Review the top-level retrieval mode. It contains `fts` plus `exact` when an
   exact identifier matched, `vector` when query embedding and vector search
   were available, and `relationship` when expansion returned rows. Valid
   examples include `fts`, `exact+fts`, `fts+vector`, and
   `exact+fts+vector+relationship`. Use each result's `retrieval_signals` to
   see which paths contributed to that item; the top-level mode alone does not
   prove that every path produced a surviving candidate. A vector or fused
   score is not confidence.
6. Open every material citation route and compare the excerpt with the
   authoritative record. Verify TLP, legal-sensitive warnings, dates, source,
   actor-link evidence, and whether the IOC is still useful in the local
   environment before creating a block, hunt, detection, or incident action.

When a remote chat provider is selected, the analyst must acknowledge that
policy-eligible request context and excerpts may leave the deployment. A
selected business profile, asset, threat hunt, Evidence Graph node,
`TLP:AMBER+STRICT`, `TLP:RED`, or any other legally sensitive result makes the
request local-only even if remote AI is enabled. **Search evidence** does not
call a chat model, although vector search can call the configured private
embedding endpoint when embeddings are enabled.

Other example questions:

```text
Find recent IOCs relevant to an Israel-based technology company. Separate
direct source evidence from inferred relevance and show freshness/confidence.
```

```text
Which KEV CVEs affect internet-facing identity or collaboration products in our
profile, and which ATT&CK techniques have stored source-backed links?
```

```text
Using these sources, propose the relevant Enterprise ATT&CK techniques and let
me preview them on Navigator. Do not replace my current selection.
```

When a client profile is selected, region, sector, technologies, and crown
jewels are deterministic relevance features. They do not prove targeting or
compromise. Without a saved profile, text such as “Israel tech company” is only
search context, and the response carries a non-authoritative-scope warning.

For example, the relationship-aware path for “find IOCs relevant to an Israel
technology company” can retrieve an actor observation that mentions Israel or
technology and then retrieve IOC documents sharing that actor's stored
identifier. The citations support the observation and stored actor/IOC link;
they do not support the stronger claim that the IOC targets that company.

The result separates:

- the generated explanation;
- exact retrieved source excerpts and routes;
- normalized IOC/CVE/TTP/actor/report entities;
- retrieval mode and index age;
- the `relationship` retrieval signal and its evidence/targeting warning when
  bounded relationship expansion contributed a result;
- TLP and legal-processing warnings;
- cautions and evidence gaps;
- a Navigator proposal, when explicitly requested.

## Navigator TTP proposal workflow

A proposal never modifies the matrix automatically.

To answer “paste all relevant TTPs on Navigator” safely:

1. Open the intended Navigator domain and its latest locally available ATT&CK or
   ATLAS version. The assistant rejects a request pinned to a stale version.
2. Select the business profile and source groups that define “relevant.” Avoid
   selecting every source merely to increase the result count.
3. Select **Generate grounded answer** with an explicit request such as:

   ```text
   Propose only Enterprise ATT&CK techniques directly supported by the cited
   reports, campaigns, actor observations, IOCs, CVEs, hunts, and asset context
   relevant to this profile. Explain each inclusion. Create a Navigator proposal
   for review; do not claim it has been applied or saved.
   ```

4. Review the answer, cautions, effective TLP, every citation, and each proposed
   ID. The server removes malformed, invented, deprecated, wrong-domain, and
   non-current IDs before a proposal is returned.
5. Choose **Preview _N_ on Navigator**. This displays a temporary overlay; it
   does not alter the active selected-technique set.
6. Choose **Review Add / Replace diff**. Select **Add** to preserve the current
   selection or **Replace** to make the proposal the complete selection. Review
   added, already-selected, and removed IDs, then affirm that the cited evidence
   was reviewed.
7. Confirm. The server locks the proposal row and rechecks checksum, owner (or
   `manage_intel` override), expiry, cited chunk hashes, domain, current catalog
   version, and all technique IDs. A changed source, catalog, request context,
   or Navigator selection stops local application.
8. Only after the exact server receipt is validated does the browser apply the
   confirmed IDs to the in-memory Navigator workspace. Use **Save layer** as a
   separate action if persistence is intended; no saved layer is created by the
   assistant or confirmation endpoint.

Proposals expire after 30 minutes and cannot be confirmed twice.

## REST API

| Method | Endpoint | Permission | Purpose |
|---|---|---|---|
| `GET` | `/api/rag/status` | `read` | Corpus, embedding, coverage, and freshness status |
| `GET` | `/api/rag/profiles` | `run_analysis` | Bounded client-profile selector data |
| `POST` | `/api/rag/profiles` | `manage_intel` | Create a saved business profile |
| `PUT` | `/api/rag/profiles/{id}` | `manage_intel` | Replace a saved business profile |
| `DELETE` | `/api/rag/profiles/{id}` | `manage_intel` | Delete a saved business profile |
| `POST` | `/api/rag/search` | `run_analysis` | Exact + lexical + vector hybrid retrieval |
| `GET` | `/api/rag/entity/{type}/{id}` | `run_analysis` | One sanitized indexed entity with bounded chunks |
| `GET` | `/api/rag/providers` | `run_analysis` | Governed generation provider readiness |
| `POST` | `/api/rag/assist` | `run_analysis` | Citation-bound RAG answer and optional proposal |
| `POST` | `/api/rag/proposals/{id}/confirm` | `run_analysis` | Confirm an expiring proposal; no layer save |
| `POST` | `/api/rag/reindex` | `manage_feeds` | Queue idempotent reconciliation |
| `GET` | `/api/rag/index-runs` | `manage_feeds` | Review background-run outcomes |

Example search:

```json
{
  "query": "Israel technology sector phishing infrastructure",
  "source_types": ["actor_intel", "ioc", "attack_group", "attack_campaign", "analysis_report", "attack_technique"],
  "domain": "enterprise-attack",
  "limit": 12
}
```

An empty `source_types` list means every supported collector at the REST layer.
Use an explicit allowlist in repeatable analyst automation so later collector
additions do not silently broaden the evidence boundary. `attack_version` is an
optional optimistic guard: when supplied, it must equal the current local
catalog for the selected domain.

Example grounded request using a pre-existing profile:

```bash
curl -sS -X POST http://127.0.0.1:3000/api/rag/assist \
  -H 'Content-Type: application/json' \
  -b 'ag_session=<session-token>' \
  --data '{
    "query": "Propose only cited Enterprise ATT&CK techniques relevant to this profile and create a Navigator proposal for review.",
    "source_types": ["attack_technique", "attack_group", "attack_campaign", "actor_intel", "ioc", "cve", "analysis_report"],
    "domain": "enterprise-attack",
    "attack_version": "<current-version>",
    "client_profile_id": 4,
    "limit": 20,
    "provider": "local",
    "cloud_processing_acknowledged": false
  }'
```

The response contains `assistance_id`, provider/model, actual retrieval mode,
effective TLP, answer, verified citations, normalized entities, cautions,
warnings, and an optional `navigator_proposal`. Absence of a proposal is a
valid outcome when the question did not request one or no cited, locally valid
technique survived validation.

Server confirmation requires the exact proposal ID and checksum returned to the
same owner (or a user with `manage_intel`):

```bash
curl -sS -X POST \
  http://127.0.0.1:3000/api/rag/proposals/<proposal-id>/confirm \
  -H 'Content-Type: application/json' \
  -b 'ag_session=<session-token>' \
  --data '{"proposal_checksum":"<64-character-sha256>","mode":"add"}'
```

The receipt deliberately returns `persisted=false`. A non-browser API client
may record that receipt but must not describe it as a changed Navigator
workspace or saved layer; the web client performs its own exact receipt and
request-context checks before applying IDs in memory.

## MCP server

The MCP surface reuses these authenticated REST contracts instead of opening a
second database authorization path. The first release is read-only/advisory:

- search intelligence;
- ask the grounded assistant;
- get a sanitized indexed entity;
- propose a Navigator technique list as unconfirmed MCP-client advisory output.

It does not expose arbitrary SQL, URL fetching, feed configuration, secrets,
raw source JSON, simulation, SIEM forwarding, proposal confirmation, or layer
mutation.

For the standard Compose deployment, a host-side MCP process must use
`MCP_API_BASE_URL=http://127.0.0.1:3000`; port `3000` is the published
frontend/API proxy. Port `8000` is an internal API-container origin and is not
published to the host.

See [`mcp-server.md`](mcp-server.md) for setup, authentication, transport, tool,
resource, and client configuration details.

## Operations

Monitor at least:

- active/tombstoned document and chunk counts;
- ready/pending/failed embedding counts;
- last successful reconciliation and index age;
- partial/failed run reason;
- lexical-only fallbacks;
- provider timeout/failure rate;
- stale-answer rejection count;
- persisted proposal state and expiry, plus `rag.navigator.confirm` audit
  events. There is no separate reject endpoint or automatic expiry audit event;
- `rag.assist.remote_attempt`, `rag.assist.suggest`, `rag.index.queue`, and
  `rag.index.redispatch` audit events as applicable;
- `rag.retention.purge` or `rag.retention.legal_hold` audit events, deleted
  counts, cutoffs, and whether a run reached its configured batch ceiling;
- RAG worker database routing, including confirmation that any PgBouncer path
  uses session pooling rather than transaction or statement pooling.

The corpus is derived data, but it may contain sensitive curated excerpts.
Include it in PostgreSQL backup access controls and retention decisions. A full
reindex can recreate it from authoritative records; an old backup must still be
protected as customer/investigation data. Database retention does not purge an
existing backup, snapshot, replica, or export.

## Troubleshooting

### The corpus is empty or a run remains queued

Confirm PostgreSQL, Redis, `worker`, and `beat` are healthy and that the worker
loads `app.tasks.rag`. Review `/api/rag/index-runs` for status,
`attempt_count`, `heartbeat_at`, and the bounded failure summary. Repeating the
UI/API reindex request is safe: it redispatches a queued or two-hour-stale run
instead of creating concurrent corpus writers. Do not edit the run row or
delete the advisory lock manually. If publication returns 503, restore the
broker and repeat the enqueue; the persisted run is intentionally recoverable.

### The latest run is degraded or failed

`degraded` means source documents and exact/full-text chunks were reconciled but
at least one requested embedding was not usable. Inspect embedding counts and
the private model route, correct the dependency, and requeue. `failed` means the
corpus reconciliation itself did not complete; inspect bounded worker logs,
database/extension availability, collector data errors, and worker database
routing before retrying. Do not report vector coverage from a degraded run
without checking `chunks_embedded` and the request's retrieval mode.

### Status says lexical only

Check that `RAG_EMBEDDING_ENABLED=true`, the configured model exists, the API
and worker can reach `LOCAL_LLM_BASE_URL`, and returned vectors have exactly
`RAG_EMBEDDING_DIMENSIONS` values. Review the latest index run rather than
assuming a generated answer used vector retrieval.

### PostgreSQL reports that type `vector` does not exist

The running database image/host does not have pgvector installed. Rebuild the
bundled PostgreSQL image or install the extension package on the external
database, then create the extension before restarting the API.

### RAG reconciliation runs behind PgBouncer

Confirm the worker's database route uses `pool_mode=session`, or bypass
PgBouncer and connect the worker directly to PostgreSQL. Do not use transaction
or statement pooling for reconciliation. Restart the worker after changing its
database route, then review or requeue the persisted index run; do not assume a
client-side pool setting can restore a PostgreSQL session advisory lock that was
acquired through an incompatible proxy mode.

### The assistant returns no evidence

Confirm the corpus was indexed, broaden the selected source filters, check the
selected ATT&CK domain, and review tombstoned/failed counts. The assistant
intentionally refuses to generate an ungrounded answer when retrieval is empty.

For a business-context IOC query, also confirm the saved profile exists and
that **IOCs** and **Actors** are selected. Relationship expansion can return an
IOC only when an initial result and the IOC share an allowlisted stored actor,
campaign, technique, CVE, or IOC-record identifier; it does not invent a link
from matching prose.

### A remote provider is configured but the request is rejected

Confirm cloud AI is operator-enabled and the analyst acknowledged the request.
Then review effective TLP and every selected source. A business profile, asset,
threat hunt, Evidence Graph node, legal-sensitive signal, actor-intelligence
observation, `TLP:AMBER+STRICT`, or `TLP:RED` source forces local generation.
Removing a source merely to bypass handling policy is not a valid workaround;
use the approved private provider or narrow the question for a legitimate
analytical reason.

### A proposal became stale

The ATT&CK version, source chunks, proposal checksum, ownership, or expiry
changed. Run the search again and review a fresh proposal.

## Known boundaries

- Retrieval coverage is limited to currently implemented allowlisted
  collectors and indexed records; it is not proof that no relevant intelligence
  exists elsewhere.
- The configured vector-distance threshold rejects weak neighbours, but a
  semantically related record can still be operationally irrelevant. Review
  structured relationships and source evidence.
- Reconciliation currently materializes each selected collector and its
  existing corpus rows in the worker. For unusually large deployments, split
  source types across separately monitored runs and review worker memory until streaming
  reconciliation is introduced.
- IOC freshness, feed confidence, actor attribution, CVE-to-TTP links, and
  sector labels inherit the limitations of their source records.
- Relationship expansion is one bounded, non-recursive retrieval pass over
  allowlisted stored identifiers. It is not a complete knowledge-graph traversal
  and does not establish unrecorded transitive relationships.
- A selected business profile improves ranking but is not a targeting claim.
- Cloud-provider controls reduce data-egress risk but do not replace provider
  due diligence, contracts, region/retention review, and network egress policy.
- The current single-workspace data model is not a tenant-isolation boundary.
- MCP is an integration surface, not permission to automate blocking,
  exploitation, hunt execution, response, or Navigator mutation.
