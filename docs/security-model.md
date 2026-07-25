# Security Model

AdversaryGraph is a self-hosted analyst workbench, not a managed SaaS.

## Trust Boundaries

| Boundary | Trust Assumption |
|---|---|
| Browser to frontend | User has access to the workspace |
| Frontend to API | API is reachable from the operator-controlled network |
| API to PostgreSQL | Database is private to the deployment |
| API/worker to LLM provider | Operator controls provider choice and accepts provider data terms; governed Threat Hunting cloud AI is disabled by default and requires explicit analyst acknowledgment when enabled |
| API/worker to embedding endpoint | RAG embeddings use the configured `local` provider only; the endpoint host must be loopback, a private/link-local IP, or recognized private service DNS, and the operator must still secure routing, authentication, TLS, logs, and retention |
| Local MCP client to MCP subprocess | MCP uses stdio only; the subprocess calls fixed authenticated RAG API routes with a dedicated least-privilege AdversaryGraph session and exposes no remote MCP listener |
| API to MITRE/GitHub | Public ATT&CK STIX bundles are downloaded for sync |
| API to IOC feeds | Operator controls ThreatFox, OTX, and custom feed credentials/URLs |
| AdversaryGraph to malware-analysis service | Malware samples remain outside the main application containers; only validated result artifacts are imported |
| Malware-analysis service to sandbox | Dynamic execution is allowed only in disposable isolated sandbox profiles, not in normal application containers |

## Sensitive Data

Potentially sensitive data includes:

- Uploaded reports.
- Uploaded malware archives and extracted samples, if the optional malware-analysis service is enabled.
- Extracted text from reports.
- Malware-analysis artifacts such as strings, PCAPs, memory metadata, debugger notes, and unpacked payloads.
- LLM raw responses.
- Analyst notes.
- Threat Hunting AI suggestions, analyst focus text, source citations, and
  assistant provenance metadata.
- Normalized RAG documents, excerpts, embeddings, source relationship metadata,
  business profiles, assistant answers, citations, and expiring Navigator
  proposals.
- MCP tool results and any copies retained by the connected MCP client or its
  model.
- Campaign or customer names.
- IOC feed contents and actor-linked indicators.
- Custom feed URLs.
- Exported PDF/JSON reports.
- API keys.

## Public Workspace

The public web workspace is for exploration. It should not receive:

- Customer reports.
- Internal incident data.
- Classified or restricted data.
- Credentials.
- Private victim details.

## Self-Hosted Workspace

For private analysis:

- Deploy locally or inside a trusted network.
- Use non-default database credentials.
- Use private LLM infrastructure if provider transmission is not acceptable.
- Restrict access through a reverse proxy.
- Keep the API behind an edge that rejects oversized decoded request bodies.
  The bundled Nginx configurations enforce a 10 MiB default and narrowly
  scoped larger upload limits. Application upload handlers also enforce their
  documented decoded-file limits, but the generic `Content-Length` pre-check
  is not an ASGI streaming limiter and cannot protect a directly exposed API
  from an oversized chunked JSON or form body.
- Configure `AUTH_ENABLED=true` for native username/password access control.
  The local setup guide is available at <http://localhost:3000/auth-guide>.
- Create at least two tested named Platform Administrator accounts before
  clearing the bootstrap password. Assign workforce accounts through reviewed
  least-privilege SOC groups; module hiding is not the security boundary, so
  verify direct API denial as well as sidebar visibility.
- For trusted-header authentication, configure `PROXY_SECRET`. The proxy must
  strip client-supplied `X-Auth-User`, `X-Auth-Roles`, and
  `X-Internal-Proxy-Secret` headers before setting trusted identity headers.
- Set explicit `CORS_ALLOWED_ORIGINS`; wildcard origins are rejected when
  credentialed API access is enabled.
- Back up and purge data according to local policy.
- Keep governed Threat Hunting AI on the operator-configured local endpoint
  unless cloud processing is explicitly enabled and approved. Treat
  `TLP:AMBER+STRICT` and `TLP:RED` hunt context as local-only.
- Keep RAG embeddings local-only and review every field allowlist before adding
  a new indexed source type. Do not index raw provider payloads or secrets.
- Include the RAG tables, vector indexes, assistance records, business profiles,
  and MCP-client copies in classification, retention, deletion, backup, and
  incident-response policy.

## LLM Output

LLM output is treated as untrusted:

- Mappings require analyst review.
- Similarity scores are investigation leads.
- Generated detection logic is draft material.
- Threat Hunting hypotheses, plans, queries, finding drafts, and outcome
  summaries are suggestions, not evidence or decisions.
- Threat Hunting AI does not execute telemetry queries, save findings, change
  lifecycle state, choose a disposition, or initiate response actions.
- Applying a safe suggestion only copies permitted content into an unsaved
  editable form; the analyst must review and use the normal save workflow.
- Exports should include limitations when used in a report.

Threat Hunting AI starts from a stored report/research session or the bounded
current-hunt context. Stored reports carry a server-side TLP marking and default
to `TLP:AMBER+STRICT`; only the `manage_intel` report-edit path may change it.
The request may raise but cannot lower that marking. Cloud processing is
disabled by default; when an operator enables it, a remote request still
requires explicit analyst acknowledgment. `TLP:AMBER+STRICT` and `TLP:RED`
requests are rejected for remote providers.
Enterprise ATT&CK is the only supported report-to-hunt framework in the v6.5
implementation.

The assistant request treats report text as untrusted model input. Fixed task
prompts, structured validation, source-span checks, provider/TLP gates, and
human review reduce prompt-injection and hallucination risk but cannot eliminate
it. The API rechecks stored source or saved-hunt context after a provider call
and rejects the result if that context changed during generation; later edits
still require manual comparison or regeneration. The platform may retain
bounded, server-validated citation excerpts of at most 300 characters with
their source references and offsets, but it does not
persist the raw assistant prompt, full raw report, or raw provider response in
an AI-assistance record. The stored report remains the controlled source of
record; assistant provenance does not create another full-text copy.

## Unified RAG And MCP

RAG retrieval separates authoritative records from a rebuildable derived
corpus. Reconciliation copies only allowlisted normalized fields into
`rag_documents` and bounded `rag_chunks`. Each record carries its source
identity, canonical route, content hash, timestamps, TLP, sanitization state,
and legal-sensitive flag. Raw feed/provider JSON, configuration credential
fields, and unrestricted asset metadata are excluded from the corpus. Included
narrative fields are not passed through a general DLP/secret redactor; the
operator must remove unnecessary secrets and apply correct TLP/legal markings.

The search service uses exact identifiers and PostgreSQL full text, with
optional private vector similarity. One-hop relationship expansion is bounded,
non-recursive, and limited to stored allowlisted relationship identifiers.
Those relationships may originate from upstream or automated ingestion and do
not have a universal analyst-review state. Neither a
business-profile match nor a retrieved relationship proves targeting,
exploitation, attribution, active infrastructure, or compromise.

Generation adds these controls:

- a fixed structured-output schema and server-side validation;
- citations constrained to the retrieved source set and rechecked locally;
- source and business-context freshness checks after provider egress;
- effective-TLP calculation and local-only handling for legal-sensitive,
  `TLP:AMBER+STRICT`, and `TLP:RED` context;
- explicit per-request acknowledgment before eligible content reaches a remote
  provider;
- bounded stored provenance instead of raw prompts, raw provider responses, or
  provider exceptions;
- locally validated ATT&CK IDs and expiring checksum-bound proposals;
- explicit browser confirmation before Add/Replace. Proposal and confirmation
  state is persisted for audit, but no named layer is saved and no operational
  action is executed.

The MCP process deliberately has a narrower boundary. It supports stdio only,
rejects public cleartext API origins, validates inputs and output sizes, and
offers search, grounded questions, sanitized indexed-entity reads, and
unconfirmed Navigator proposals. It cannot reindex the corpus, confirm a
proposal, save a layer, change intelligence, execute a hunt, run Attack
Simulation, forward detections, or acknowledge cloud processing for a user.
Because `MCP_API_TOKEN` is an ordinary application session rather than an
independently scoped MCP credential, use a dedicated analyst/service account,
rotate and revoke the session, protect process configuration, and treat the
connected client/model as another sensitive-data processor.

See [Unified Intelligence RAG and MCP](unified-rag-and-mcp.md),
[MCP Server](mcp-server.md), and the more detailed
[Security Threat Model](security-threat-model.md).

## File Parsing

AdversaryGraph supports text, PDF, and DOCX extraction. Operators should treat uploaded documents as untrusted and run the platform in a controlled environment.

## Malware Analysis

The integrated MalwareGraph malware-analysis capability has a separate architecture because
malware samples are more dangerous than ordinary report uploads. The main
AdversaryGraph containers should not receive, extract, execute, or debug malware
directly.

Required security posture:

- keep malware archives, extracted payloads, memory dumps, and packet captures in
  a dedicated malware-analysis service and artifact store;
- default to static-only analysis with no sample execution;
- use non-root, read-only, capability-dropped containers for intake and static
  workers;
- deny outbound network access from analysis workers unless a specific
  enrichment worker is allowlisted;
- run dynamic execution, debugging, or memory-unpacking only in disposable VM,
  microVM, or dedicated sandbox profiles;
- route dynamic network behavior to fake internet or sinkhole services by
  default, not to production networks;
- do not submit binaries to third-party services unless an operator policy and
  analyst approval explicitly allow it;
- import only validated `analysis.json` results and derived artifacts into the
  AdversaryGraph investigation graph.

See [Malware Analysis Architecture](malware-analysis-architecture.md) for the
full scenario, container model, pipeline stages, and safety controls.

## IOC Feeds

IOC feeds are operational data, not stable reference data. Operators should:

- keep ThreatFox/OTX keys out of commits and screenshots;
- review custom feed provenance before import;
- expect server-side feed fetches to reject localhost, private, link-local,
  multicast, reserved, and cloud-metadata destinations as SSRF protection;
- treat URL validation as one layer of defense: environment proxies are
  disabled, each connection is pinned to a validated public address, and each
  redirect target is independently resolved and validated while HTTPS keeps
  the original hostname for certificate verification; production deployments
  should still enforce DNS policy and outbound network allowlists;
- avoid importing customer-private feeds into public demos;
- define retention and export rules for actor IOC CSVs;
- treat extracted IOCs from uploaded reports as untrusted until reviewed.
