# Deployment Sizing Guide

This guide gives starting points for controlled self-hosted deployments. Actual
requirements depend on feed volume, number of analysts, LLM provider latency,
uploaded report size, RAG document/chunk count, embedding dimensions,
malware-analysis workload, and Attack Simulation usage. The profiles below do
not include CPU/GPU/RAM for a separately deployed local chat or embedding model.

## Profiles

| Profile | Analysts | CPU | RAM | Disk | Recommended Use |
|---|---:|---:|---:|---:|---|
| Small | 1-3 | 4 vCPU | 8-12 GiB | 80-150 GiB SSD | Lab, evaluation, private analyst workstation |
| Medium | 3-10 | 8 vCPU | 24-32 GiB | 250-500 GiB SSD | Internal CTI/detection team with scheduled feeds |
| Large | 10-30 | 16 vCPU | 48-64 GiB | 1 TiB+ SSD | Shared team deployment, broad IOC/CVE/feed sync, heavier malware triage |

## Per-Service Starting Points

| Service | Small | Medium | Large |
|---|---:|---:|---:|
| PostgreSQL | 1 vCPU / 2 GiB | 2 vCPU / 4-8 GiB | 4 vCPU / 16 GiB |
| API | 1-2 vCPU / 2 GiB | 2 vCPU / 4 GiB | 4 vCPU / 8 GiB |
| Worker | 1-2 vCPU / 2-3 GiB | 2-4 vCPU / 6-8 GiB | 6-8 vCPU / 16 GiB |
| Redis | 0.5 vCPU / 512 MiB | 1 vCPU / 1 GiB | 2 vCPU / 2 GiB |
| MalwareGraph | 1-2 vCPU / 2 GiB | 2-4 vCPU / 4-8 GiB | 4-8 vCPU / 16 GiB |
| Frontend | 0.5 vCPU / 256 MiB | 0.5 vCPU / 512 MiB | 1 vCPU / 1 GiB |

## Unified RAG Capacity

RAG reconciliation materializes the selected normalized sources, creates
bounded chunks, writes PostgreSQL full-text vectors, and optionally calls the
private embedding endpoint in batches. Only one corpus reconciliation is active
at a time, but ordinary Celery jobs still share the worker pool.

Use `/api/rag/status` and `/api/rag/index-runs` to record:

- active/tombstoned document count;
- chunk count and per-source coverage;
- complete, pending, and failed embedding counts;
- latest indexed time, run duration, heartbeat, attempts, and failure summary;
- exact/full-text/vector retrieval mode observed in a representative query.

For pgvector's default 32-bit elements, the raw vector payload is approximately:

```text
chunk_count × embedding_dimensions × 4 bytes
```

This excludes PostgreSQL tuple/WAL overhead, document and text content, GIN and
HNSW indexes, dead tuples, backups, and free-space headroom. As a starting
budget, reserve at least two to four times the raw vector payload in addition to
the lexical/source text footprint, then measure the real database after the
first full reconciliation. HNSW index construction and query performance need
memory headroom; avoid sizing PostgreSQL so tightly that the OS begins swapping.

At the default 768 dimensions, one raw vector is roughly 3 KiB before database
and index overhead. Changing dimensions changes both model compatibility and
storage; it is a schema migration plus full-reindex decision, not an online
tuning knob.

The embedding service should accept `RAG_EMBEDDING_BATCH_SIZE` texts within the
worker timeout and return exactly the configured dimensions. Reduce the batch
size if the service rejects payloads or exhausts accelerator memory. Keep
`RAG_EMBEDDING_ENABLED=false` until the endpoint is measured; exact and
PostgreSQL full-text search provide a supported lower-resource mode.

## Disk Planning

Plan storage for:

- PostgreSQL database: ATT&CK/ATLAS, APTs, IOCs, CVEs, reports, cases, users.
- PostgreSQL RAG data: normalized document copies, chunk text, generated
  full-text vectors, optional embeddings/HNSW index, assistance provenance, and
  expiring proposals.
- `adversarygraph_logs`: API logs, Attack Simulation logs, observability log tail.
- `malwaregraph_storage`: uploaded samples, extracted artifacts, static-analysis output.
- `attck_data`: cached ATT&CK/ATLAS bundles.
- Backups: at least 7-30 logical dumps, depending on retention.

Suggested baseline:

- Small: 80 GiB SSD plus 80 GiB backup target.
- Medium: 250 GiB SSD plus 500 GiB backup target.
- Large: 1 TiB SSD plus 2 TiB backup target.

## Operational Notes

- Keep PostgreSQL data on persistent SSD-backed storage.
- Keep backups outside the primary data directory.
- Disable `AUTO_IOC_FULL_SYNC_ON_STARTUP` in production and run feed sync on a
  planned schedule.
- Enable auth before exposing the UI beyond localhost.
- Use an external reverse proxy or ingress for TLS.
- Monitor `/api/health` for process liveness, `/api/ready` for database-backed
  traffic readiness, `/api/observability/summary`, and service logs.
- Monitor `/api/rag/status` and recent index runs. Alert on an empty enabled
  corpus, stale reconciliation, failed embeddings, repeated redispatch, or
  unexpected growth in tombstoned documents and retained assistance.
- Schedule the initial/full reconciliation outside peak analyst and feed-sync
  windows for large databases. The worker must connect directly to PostgreSQL or
  through PgBouncer session pooling because its advisory lock spans commits on
  one database session.
- Size and monitor the private model gateway independently. GPU memory, model
  context limits, concurrency, latency, and provider logs are outside the table
  above.
