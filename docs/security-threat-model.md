# Security Threat Model

AdversaryGraph is a self-hosted analyst workbench for controlled environments. This document describes expected trust boundaries and the security assumptions reviewers should use when evaluating the project.

## Assets

| Asset | Why it matters |
|---|---|
| Uploaded reports and extracted text | May contain customer, incident, or victim-sensitive details |
| Stored investigations and analyst notes | May contain private conclusions and operational context |
| Threat Hunting AI context and suggestions | May contain report-derived hypotheses, source citations, hunt scope, query drafts, and analyst focus text |
| Unified RAG corpus, embeddings, and assistance | May contain curated IOC/CVE/TTP/report, actor sector/region/technology observations, relationship evidence, hunt, evidence, and sanitized asset excerpts plus derived vectors and citations; saved business profiles remain private per-request context |
| IOC feeds and enrichment results | May include restricted source data or private indicators |
| Malware-analysis artifacts | Potentially hostile files, strings, unpacked outputs, and debugger notes |
| Attack Simulation SIEM targets | May identify internal collectors or validation systems |
| Evidence Graph exports | May include sensitive report excerpts, analyst decisions, and validation results |
| API keys and provider tokens | Enable external LLM, CTI, IOC, and enrichment calls |

## Trust Boundaries

| Boundary | Expected control |
|---|---|
| Browser to frontend | Operator-controlled network or authenticated reverse proxy |
| Frontend to API | Same deployment boundary; no direct public API exposure by default |
| API to PostgreSQL/Redis | Internal Compose network only |
| API to LLM providers | Operator-selected provider; governed Threat Hunting cloud use is disabled by default, requires explicit acknowledgment when enabled, and rejects `TLP:AMBER+STRICT`/`TLP:RED` remote processing |
| RAG to embedding/generation providers | Embeddings are local-only and the endpoint host must pass the loopback/private-IP/private-service-DNS check; only field-allowlisted normalized data is embedded, but included narrative text is not general-DLP redacted; legal-sensitive and `TLP:AMBER+STRICT`/`TLP:RED` generation context remains local, and eligible remote generation requires explicit acknowledgment |
| API to feed URLs | SSRF-hardened fetch logic blocks localhost, private, link-local, reserved, and metadata ranges; each connection is pinned to a validated public address and each redirect target is independently resolved and validated; deployment egress and DNS controls remain defense in depth |
| API to SIEM collector | Explicit operator-provided HTTP(S) destination for telemetry forwarding |
| AdversaryGraph to MalwareGraph | Isolated service boundary; analysis artifacts are imported back, not raw runtime control |
| Attack Simulation to lab fixtures | Approved local lab targets only; no arbitrary internet target execution |

## Main Threats

| Threat | Mitigation |
|---|---|
| Public demo data leakage | Public demo warning in docs and UI guidance; private work should use self-hosted deployment |
| Secret leakage in repository | `.env.example` contains placeholders only; CI includes gitleaks secret scan |
| Request-body resource exhaustion | Bundled Nginx edges enforce decoded-body limits (10 MiB by default, with narrow upload exceptions); structured request models and upload handlers add application limits. A directly exposed API must not rely on the `Content-Length` pre-check for chunked bodies. |
| SSRF through feed import or SIEM forwarding | URL validation rejects unsafe schemes and metadata/link-local/private ranges, environment proxies are disabled, connections use a validated pinned address while preserving the HTTPS hostname, and redirect targets are revalidated before connecting; operators still enforce outbound network and DNS policy as defense in depth; SIEM forwarding is explicit and logs destination use |
| LLM hallucination or overconfident mapping | Review states, validation docs, limitation notices, and evidence-based mapping workflow |
| Prompt injection in a stored report | Fixed assistant tasks, bounded context, structured output validation, citation verification, safe-field application, and mandatory analyst review; model output remains untrusted |
| Prompt injection through indexed intelligence | Raw provider JSON is excluded, chunks are explicitly untrusted, provider output has a strict schema, citations must bind to known retrieval references, model tool calls are unsupported, and proposals cannot self-confirm |
| Relationship match mistaken for targeting or compromise | Expansion is one bounded, non-recursive pass over allowlisted stored identifiers, results carry a relationship signal and warning, and analysts must review each cited observation/link instead of treating a shared actor/TTP as proof |
| Cross-customer retrieval leakage | AdversaryGraph documents that it is single-workspace and must not be used as a tenant-isolation boundary; separate deployments are required for mutually untrusted customers |
| Stale or invented Navigator techniques | Proposal source/checksum/expiry/version revalidation and local current-catalog validation occur before browser application; saving a layer independently repeats catalog validation |
| Sensitive hunt data sent to a cloud model | Cloud disabled by default, operator enablement, per-request analyst acknowledgment, conservative stored-source default `TLP:AMBER+STRICT`, authoritative server-side marking that requests cannot lower, and local-only enforcement for `TLP:AMBER+STRICT`/`TLP:RED` |
| AI suggestion mistaken for evidence or an action | Suggested-only lifecycle, no query execution or automatic save, normal hunt/finding save controls, and explicit UI execution-boundary warnings |
| Stale or truncated assistant context | Post-provider source/hunt recheck rejects concurrent changes; truncation and citation warnings disclose bounded coverage; later edits require analyst regeneration or manual comparison |
| Untrusted file parsing | Controlled deployment guidance and bounded parser usage; malware workflows stay behind MalwareGraph boundary |
| Malware execution in app containers | Not allowed by default; runtime debugging requires isolated disposable MalwareGraph profiles |
| Internet-exposed default stack | Default Compose binds UI/docs/PostgreSQL to localhost and leaves API/Redis/internal services unexposed |
| Overclaiming synthetic telemetry | Docs separate real lab telemetry from synthetic AI-generated telemetry |
| Overclaiming Evidence Graph paths | Node/edge review states, AI draft markers, readiness-score limitations, and analyst-decision requirements |
| Sensitive graph export leakage | Secret-like metadata keys are redacted; malware binaries and SIEM destination secrets are not included in Evidence Pack exports |

## Required Operator Hardening

Before exposing AdversaryGraph beyond a trusted local network:

- Put the frontend/API behind TLS.
- Enforce decoded request-body limits at the reverse proxy or ingress. Preserve
  the bundled route-specific upload allowances instead of applying an
  unlimited global body size, and do not expose the API container directly.
- Enable native authentication with `AUTH_ENABLED=true`; use trusted-header authentication with a strong `PROXY_SECRET` only behind an identity-aware reverse proxy.
- Create named accounts through the policy-aware Admin Panel workflow, retain
  two tested administrator recovery paths, and assign least-privilege SOC
  groups. Verify backend denial for modules outside each group; hidden
  navigation alone is not an authorization control.
- Set `CORS_ALLOWED_ORIGINS` to the exact production origin.
- Rotate `DB_PASS`, `REDIS_PASSWORD`, LLM keys, and CTI provider tokens.
- Restrict PostgreSQL, Redis, MalwareGraph, and lab fixtures to internal networks.
- Connect RAG reconciliation workers directly to PostgreSQL or through
  PgBouncer `pool_mode=session`; transaction/statement pooling cannot preserve
  the worker's session advisory lock across commits.
- Configure backups, retention policy, monitoring, and audit log retention.
- Decide which data may be sent to cloud LLM and enrichment providers.
- Keep Threat Hunting cloud AI disabled unless approved provider data terms,
  region, retention, and organizational handling rules have been documented.
  Verify that the configured `local` endpoint is actually deployed within the
  intended private boundary.
- Train analysts to classify stored report sources before assistance, review
  remote-processing acknowledgment, and treat citations as report context—not
  proof of local activity.
- Treat Evidence Graph exports as sensitive investigation artifacts and store them under the same controls as incident reports.

## Residual Risk

AdversaryGraph remains an analyst-assistance tool. AI-generated mappings, Threat
Hunting suggestions, Evidence Graph suggestions, generated detections,
malware-analysis summaries, synthetic attack telemetry, and similarity scores
can be wrong. Treat them as review material, not authoritative output. The
Threat Hunting assistant may retain bounded, server-validated citation excerpts
of at most 300 characters with source references and offsets. It does not
persist the raw prompt, full raw report, or raw provider response in its
assistance record, but the original stored report, structured suggestion,
citations, and any analyst-saved hunt content remain sensitive investigation
data.

The API's generic request-size dependency checks a declared `Content-Length`.
It is defense in depth, not a streaming limit: a client can omit that header or
use chunked transfer encoding. The deployment edge therefore remains part of
the security boundary for decoded-body resource controls.
