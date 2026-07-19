# Observability, Security Scanning, And Validation Evidence

AdversaryGraph now exposes an operator-facing observability layer for controlled self-hosted deployments. The goal is to make production readiness measurable: health checks, request traces, API metrics, safe log review, and repeatable security scans.

## Runtime Observability

| Surface | Path | Purpose |
|---|---|---|
| Liveness | `/api/health` | Lightweight process/version check; does not prove database readiness |
| Readiness | `/api/ready` | Deployment acceptance check; returns `503` when the database is unavailable |
| Self-test | `/api/system/selftest` | Database, Redis, ATT&CK/ATLAS, IOC/CVE feeds, pgvector/RAG corpus, CPU, memory, storage, dependent-service, and provider-key readiness |
| RAG status | `/api/rag/status` | Corpus/source counts, indexed freshness, embedding state, active run, retrieval mode, and warnings |
| RAG run history | `/api/rag/index-runs` | Feed-manager view of reconciliation outcomes, counts, attempts, heartbeat, timing, and bounded failure summary |
| Dashboard | `/observability` | UI view for API uptime, request counts, latency, recent traces, top routes, log tail, and metrics preview |
| Summary API | `/api/observability/summary` | JSON snapshot for dashboards and automation |
| Recent traces | `/api/observability/traces` | Recent request trace ring buffer with request ID, method, path, status, latency, and timestamp |
| Log tail | `/api/observability/logs` | Redacted tail of `adversarygraph-api.log` |
| Prometheus text | `/api/observability/metrics` | Prometheus-compatible counters and gauges |

The request middleware assigns or preserves `X-Request-ID`, records latency and status family, and writes structured log lines to both stdout and the rotating API log file.

## What Is Logged

The API log records:

- request ID
- method
- path
- HTTP status code
- request duration
- exception class for failed requests

Console and rotating-file handlers redact common credential markers such as
`token=`, `api_key=`, `password=`, `secret=`, URL userinfo, and
`Authorization:` before persistence. The observability log-tail endpoint
reapplies the same filter as defense in depth. Redaction is best effort; do not
log request bodies or credentials.

Do not treat this as a full SIEM audit replacement. It is an operator dashboard and troubleshooting layer. Security-relevant user actions are still stored through the platform audit-event model where implemented.

RAG generation and maintenance also write bounded governance evidence. Review
persisted assistance/proposal records and actual audit events such as
`rag.assist.remote_attempt`, `rag.assist.suggest`, `rag.navigator.confirm`,
`rag.index.queue`, `rag.index.redispatch`, `rag.retention.purge`, and
`rag.retention.legal_hold`. Proposal rejection and automatic expiry do not emit
separate audit events in the current implementation. These records intentionally omit credentials, raw provider
responses, unrestricted prompts, and deleted source/answer content. Send audit
metadata to the organization's monitoring system under the same access and
retention policy as the underlying intelligence.

## Prometheus Integration

The metrics endpoint returns text in Prometheus exposition format:

```text
adversarygraph_uptime_seconds
adversarygraph_requests_total
adversarygraph_request_latency_average_ms
adversarygraph_request_latency_max_ms
adversarygraph_requests_by_status_total{status_family="2xx"}
```

For cloud deployments, scrape the endpoint through the authenticated frontend/API boundary or use a trusted reverse proxy that injects a service identity.

## Security Scanning

Run the local security validation wrapper:

```bash
make security-scan
```

That target is a best-effort developer check and reports optional host tools as
skipped. A release requires the fail-closed variant:

```bash
make security-scan-strict
# or, as part of the complete gate:
./scripts/release-readiness.sh --full
```

The wrapper runs:

| Check | Tool |
|---|---|
| Backend lint/SAST baseline | `ruff` |
| Backend SAST | `bandit` at medium/high severity |
| Backend dependency audit | `pip-audit` |
| Frontend dependency audit | `npm audit --audit-level=high` |
| Anomaly docs dependency audit | `npm audit --audit-level=high` |
| Anomaly docs production validation | `npm run build` with broken-link and anchor failures enabled |
| Secret scan | `gitleaks` |
| Deployment validation | default/development/production Docker Compose render and Helm lint/render |
| Container scan | `trivy` across seven custom images (PostgreSQL, backend, frontend, MalwareGraph, both attack-lab images, and anomaly docs) plus pinned Redis, BusyBox, and docs Nginx |

Strict mode requires Bandit, pip-audit, Gitleaks, Trivy, and Helm to be present.
Missing tools or failed checks stop the command. CI installs and runs the
required hosted tools for dependency audit, SAST, secret scanning, container
scanning, Docker builds, frontend and anomaly-docs builds, backend tests, and
version consistency.

## Release Evidence Record

Store the dated output or CI URL for each release. At minimum it must show:

- version consistency and patch hygiene passed;
- backend lint/tests, Bandit, and pip-audit passed;
- frontend lint/build/browser tests and npm audit passed;
- Gitleaks passed with reviewed configuration;
- all three Compose configurations and the Helm chart rendered successfully;
- all seven release images and all three pinned stack images passed the
  configured Trivy gate.

Do not present best-effort output containing `SKIP` as release evidence.

## Validation Examples

Recommended evidence to capture for release validation:

1. `/observability` dashboard showing request volume, status counters, traces, and log tail.
2. Authenticated `/troubleshooting` self-test popup or report showing
   `status=ok` rather than `degraded`; a readiness-only fallback is not full
   self-test evidence.
3. RAG status and recent index-run history showing a non-empty corpus, expected
   source coverage, current indexed time, and zero unexplained failed
   embeddings.
4. One exact IOC/CVE/ATT&CK search, one approved semantic search, and one
   grounded answer whose citations open the expected canonical source records.
5. A Navigator proposal preview and confirmation receipt showing domain,
   ATT&CK version, expiry, Add/Replace mode, and `persisted=false`.
6. An optional MCP stdio smoke with a dedicated analyst session showing all
   four bounded tools and no proposal confirmation or state mutation.
7. Attack Simulation real-time telemetry page after a lab scenario.
8. SIEM forwarding result after sending lab telemetry.
9. CVE Library feed status and correlation detail.
10. Admin Panel showing role-based access management.
11. CI run with backend tests, SAST, dependency audit, secret scan, pgvector
    extension/index smoke, and container scan.

These screenshots should be used as validation examples, not as proof of production compromise or real-world attack execution.
