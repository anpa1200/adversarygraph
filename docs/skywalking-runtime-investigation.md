# Apache SkyWalking runtime dependency investigation

AdversaryGraph can run its pinned optional SkyWalking runtime profile or use an
existing Apache SkyWalking OAP deployment as a read-only runtime evidence
source. The integration turns observed
service calls into a bounded graph that analysts can search by service or
technology in **Observability → Runtime dependency investigation**.

This is complementary to AdversaryGraph's CTI and Evidence Graph:

- SkyWalking answers which instrumented services communicated in a selected
  observation window.
- AdversaryGraph preserves the source and classifies every imported node and
  edge as a `runtime_observation`.
- An analyst may compare those observations with assets, IOCs, CVEs, ATT&CK
  techniques, reports, and hypotheses. A runtime edge alone is never treated
  as compromise, attribution, or proof of malicious activity.

## Start the integrated runtime profile

The optional `runtime-observability` Compose profile runs OAP 10.4.0 with the
exact BanyanDB revision selected by the upstream SkyWalking 10.4.0 Compose
example. It is opt-in because telemetry storage and OAP require substantial
memory and because workload instrumentation is an operator decision.

Set `SKYWALKING_ENABLED=true` in `.env`, then run:

```bash
make runtime-observability-up
make runtime-observability-logs
```

OAP's agent and HTTP ports bind to host loopback only. Containers on the
Compose network use `skywalking-oap:11800` for supported agent telemetry and
`skywalking-oap:12800/graphql` for AdversaryGraph queries. Remote workloads
need a separately authenticated private ingress or collector; do not change
the binding to `0.0.0.0` as a shortcut.

The profile owns only OAP and BanyanDB. It does not install an agent into
AdversaryGraph or any monitored workload. Configure a supported SkyWalking
agent or OpenTelemetry Collector, give every service a stable environment-aware
name, and verify telemetry coverage before drawing dependency conclusions.

## Configure an existing OAP endpoint

Set the following in the deployment `.env`:

```dotenv
SKYWALKING_ENABLED=true
SKYWALKING_GRAPHQL_URL=http://skywalking-oap:12800/graphql
SKYWALKING_AUTH_TOKEN=
SKYWALKING_TIMEOUT_SECONDS=8
SKYWALKING_VERIFY_TLS=true
SKYWALKING_MAX_TOPOLOGY_NODES=500
SKYWALKING_RUNTIME_RETENTION_DAYS=30
SKYWALKING_SYNC_INTERVAL_MINUTES=5
```

Use HTTPS and a scoped bearer token when the OAP endpoint crosses a trust
boundary. Keep OAP private; do not publish its GraphQL port directly to the
Internet. AdversaryGraph does not accept an OAP URL from browser requests, does
not follow redirects, and does not return the configured token.

For an existing deployment, replace the internal URL with its private HTTPS
GraphQL endpoint and configure its scoped token. The same no-silent-agent
boundary applies.

## API

Runtime status, live topology, investigation, and stored-graph reads require
the baseline `read` permission. Platform request traces, log tails, and metrics
on the same page remain restricted to `view_audit`.

```text
GET /api/observability/architecture?minutes=60
GET /api/observability/skywalking/status
GET /api/observability/skywalking/topology?minutes=60
GET /api/observability/skywalking/topology?minutes=60&service=checkout
GET /api/observability/skywalking/investigate?minutes=60&query=postgres
POST /api/observability/skywalking/sync
GET /api/observability/runtime-graph?query=checkout
POST /api/observability/runtime-graph/promote
```

The investigation route keeps matching nodes and their one-hop neighbors. This
supports Maltego-like pivoting without presenting the complete production
topology when the analyst only needs a focused dependency view.

## Analyst workflow

Open **Platform → Data Logic** (route `/observability/data-logic`) for the
companion data-provenance dashboard. It explains the live path from IOC and CVE
feeds through parsing, normalization, deduplication, tagging, correlations,
PostgreSQL persistence, RAG indexing, the read-only MCP boundary, and
human-reviewed AI assistance. Its counts and readiness states come from the
running database and provider configuration; the page does not manufacture
feed, model, or correlation activity.

1. Open **Operations → Observability** and review the live architecture graph.
   It combines current database counts, API traffic and latency, redacted log
   activity, configured data flows, and live SkyWalking calls. Solid animated
   edges are measured or observed; dashed edges are configured architecture.
2. Verify IOC/CVE feed health, RAG volume, cross-linked knowledge counts, API
   error activity, and OAP health before interpreting a missing relationship.
3. Start from an incident term, affected service, asset, or technology.
4. Query a short, relevant observation window.
5. Review the matching service and its one-hop callers and dependencies.
6. Treat the relationship as runtime evidence and verify timestamps,
   instrumentation coverage, environment, and service ownership.
7. Pivot separately into IOC, CVE, ATT&CK, report, or Evidence Graph records.
8. Record the analyst's conclusion and distinguish observed facts from inferred
   attack paths.

The architecture endpoint applies the same evidence labels to machine-readable
output. Database counts and API middleware counters are measured; OAP
relationships are observed; deployment dependencies are configured. None of
these classifications assert compromise, exploitation, or attribution.

## Native AdversaryGraph integration

Selecting **Sync into AdversaryGraph** or allowing the scheduled synchronization
creates governed runtime records:

- `runtime_topology_snapshots` records the requested scope, observation window,
  counts, truncation, actor, and provenance.
- `runtime_services` deduplicates service identities from the configured OAP
  source and maintains first/last observation timestamps and counts.
- `runtime_calls` deduplicates directed calls and maintains the observed
  components, detect points, timestamps, and counts.
- `runtime_asset_links` stores candidate matches between runtime services and
  Asset Inventory records. These are candidates until an analyst reviews them.

Every successful synchronization immediately reconciles exact and full-text
`runtime_service` records into the unified RAG corpus under the corpus advisory
lock. If vector retrieval is enabled, the scheduled full-corpus reconciliation
adds embeddings; the request path does not wait on an embedding model. The RAG
record contains only allowlisted
service metadata, relationships, timestamps, tags, and the evidence boundary.
It never copies spans, logs, SQL statements, HTTP bodies, credentials, or
arbitrary provider metadata.

The local MCP server exposes `search_runtime_dependencies`. General
`search_intelligence` and `ask_intelligence` calls may also include
`runtime_service` in their source filters. This allows the AI assistant to
connect runtime services with assets, reports, IOCs, CVEs, actors, and ATT&CK
knowledge while retaining citations and the original TLP policy.

Select synchronized services and choose **Promote to Evidence Graph** to create
reviewable evidence nodes and observed-call relationships. Promotion is
idempotent for previously imported services and relations. New nodes start as
`needs_evidence`; promotion does not confirm compromise or attribution.

## Permissions and audit

- Live and persisted runtime graph reads require `read`.
- Synchronization and Evidence Graph promotion require `manage_intel`.
- API request traces, platform logs, and metrics require `view_audit`.
- Synchronization and promotion write platform audit events.
- The self-test reports disabled SkyWalking as an optional healthy state,
  connected OAP as healthy, and configured-but-unavailable OAP as degraded.

## Retention and synchronization

Celery Beat invokes `runtime_intelligence.sync_skywalking` at the configured
interval. The task is a no-op while `SKYWALKING_ENABLED=false`, uses a database
advisory lock to prevent overlapping runs, applies runtime retention, and
refreshes only the exact/full-text `runtime_service` RAG source under the
corpus lock. The scheduled full RAG reconciliation handles vectors.

`SKYWALKING_RUNTIME_RETENTION_DAYS` removes expired calls, services, candidate
asset links through referential cascades, and snapshots. RAG reconciliation
tombstones corresponding derived documents. Database backups have a separate
retention lifecycle.

## Security and evidence boundary

- OAP URL and credentials are operator configuration, never request input.
- Redirects and environment proxy inheritance are disabled.
- Responses and GraphQL errors are bounded.
- The authenticated UI never receives the OAP bearer token.
- Imported runtime evidence defaults to `TLP:AMBER+STRICT`.
- Cloud AI still requires the platform's separate provider policy and explicit
  acknowledgement. MCP remains local, stdio-only, and pinned to local AI.
- Runtime communication may be normal application behavior. An analyst must
  validate identity, environment, instrumentation coverage, timestamps, and
  ownership before using it in a conclusion.
