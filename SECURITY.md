# Security Policy

## Supported Versions

AdversaryGraph **v6.5.0** is the current source release for controlled
self-hosted deployments.
The project is a self-hosted/internal analyst workbench, not a hardened multi-tenant SaaS.
Security fixes are applied to the latest `main` branch and the latest tagged release.

| Version | Supported |
|---|---|
| latest `main` (`v6.5.0`) | Yes |
| latest tagged release (`v6.0.0`) | Yes |
| older tags (`v4.x` and below) | Best effort |

## Reporting a Vulnerability

Do not open a public issue for vulnerabilities involving data exposure, authentication bypass, secret handling, arbitrary file access, or unsafe report parsing.

Report privately by email:

```text
1200km@gmail.com
```

Include:

- Affected component: frontend, API, parser, export, RAG index, model gateway,
  MCP process/client boundary, Docker deployment, or docs.
- Impact and attack preconditions.
- Reproduction steps.
- Whether the issue affects self-hosted deployments, the public web workspace, or both.
- Suggested mitigation if known.

## Data Handling Model

- AdversaryGraph Docker stores report analysis data in the operator-controlled PostgreSQL database.
- Uploaded report text is sent only to the LLM provider configured by the operator.
- Unified RAG copies only allowlisted, normalized source fields into PostgreSQL
  documents and chunks. Raw feed/provider JSON and configuration credential
  fields are not indexed. Stored report/article/evidence text is not a DLP or
  secret-redaction boundary; remove unnecessary secrets and set the correct TLP
  and legal marking before ingestion.
- Embedding text is sent only to the configured private OpenAI-compatible
  endpoint. Embeddings are disabled by default; exact-ID and PostgreSQL
  full-text retrieval continue without model egress.
- Saved business profiles are private request context and are not global corpus
  documents. Asset/profile context and actor-intelligence observations without
  reviewed per-record markings are handled as local-only
  `TLP:AMBER+STRICT` data.
- Cloud chat generation is separately operator-controlled and requires
  per-request analyst acknowledgment. `TLP:AMBER+STRICT`, `TLP:RED`, and
  legally sensitive results cannot cross that boundary.
- Assistance records and temporary Navigator proposals are stored derived data.
  Their default automatic retention is 90 days; inactive corpus tombstones
  default to 30 days. Setting either retention window to zero disables that
  purge for operator-controlled legal hold; backups need a separate policy.
- MCP tool results are returned to the local MCP client and any model attached
  to it. Treat that client/model as part of the same authorized data-processing
  boundary.
- AI requests initiated through MCP are pinned to the configured local provider;
  the process cannot acknowledge cloud processing on an analyst's behalf.
- The public web workspace is for exploration and should not receive confidential, customer-sensitive, classified, or internal reports.
- Operators who need private processing should use a local or private LLM gateway and isolate the deployment behind an authenticated reverse proxy.

## Deployment Boundary

The default Docker Compose profile is for local or controlled self-hosted use. Internet-facing deployments require:

- TLS termination.
- Native authentication enabled or identity-aware reverse-proxy authentication.
- Named administrator recovery accounts and least-privilege SOC group
  assignments verified through both the UI and direct API authorization.
- Network restrictions for PostgreSQL, Redis, API, and worker services.
- Secret rotation and non-default database credentials.
- Backups, retention policy, and restore testing.
- Review of LLM provider data-retention terms.
- Review of the embedding endpoint, model provenance, vector dimensions, RAG
  retention settings, corpus rebuild procedure, and derived-data backups.
- Direct PostgreSQL connectivity for the RAG reconciliation worker, or PgBouncer
  in session-pooling mode. Transaction/statement pooling cannot protect the
  corpus with the required session advisory lock.
- A dedicated least-privilege analyst account/session for MCP. The process is
  stdio-only; do not expose it through an ad-hoc network wrapper.

## Known Security Limitations

- The default deployment is not a hardened multi-tenant SaaS.
- LLM outputs are untrusted and require analyst review.
- RAG ranking, vector similarity, and relationship expansion are retrieval
  signals, not confidence, attribution, targeting, exploitation, or compromise
  evidence.
- The application is a single workspace. Not every authoritative source table
  has tenant ownership, so one instance must not be used as a hard isolation
  boundary between mutually untrusted customers.
- MCP bearer configuration uses an ordinary AdversaryGraph session and inherits
  all permissions and expiry/revocation behavior of that account; it is not an
  independently scoped API credential. Only stdio transport is supported.
- Vectors and indexed excerpts are sensitive derived data. Database access,
  backups, deletion, and incident response must cover the RAG tables as well as
  their authoritative sources.
- File parsing is bounded but should still be run in a controlled environment for untrusted documents.
- Generated detection logic is a draft and must not be deployed without local review and testing.
- Starlette/FastAPI transitive dependencies are audited in CI with `pip-audit`. Operators who route public traffic through AdversaryGraph should still ensure a trusted reverse proxy normalizes the `Host` header before it reaches the backend.
- The client-only frontend remains on React Router `6.30.3`. The current npm
  advisory database reports two moderate findings: an SSR-hydration
  deserialization issue (AdversaryGraph does not use React Router SSR) and a
  backslash-based navigation redirect issue. API-controlled external links
  pass through the centralized safe-URL policy, and browser tests reject unsafe
  schemes; developers must still never pass untrusted values directly to
  `Link` or `useNavigate`. React Router `7.18.1` is not adopted for this release
  because its current dependency range introduces a high-severity React Server
  Components action advisory and a breaking router migration. Re-evaluate both
  advisory sets before every release tag.
