# Limitations

AdversaryGraph is designed to assist CTI analysts. It does not replace analyst judgment.

## ATT&CK Mapping

- The model can produce false positives and false negatives.
- A tool mention does not always justify a technique mapping.
- A broad technique may need a more specific sub-technique.
- Some reports do not provide enough detail for precise mapping.
- ATT&CK version changes can alter names, tactics, or relationships.

## Attribution

AdversaryGraph does not prove attribution.

Group and campaign comparison uses TTP overlap. TTP overlap can result from:

- Shared tools.
- Common tradecraft.
- Reporting bias.
- Incomplete source coverage.
- Reused infrastructure.
- Coincidental overlap.

Use similarity as a lead, not a conclusion.

## Detection Engineering

Generated detection content is draft material.

Before production use:

- Confirm telemetry exists.
- Check false-positive conditions.
- Validate in a lab or historical dataset.
- Add triage guidance.
- Review with detection engineering owners.

## Threat Hunting AI Assistance

- Generated hypotheses, plans, queries, finding summaries, and outcome summaries
  are suggestions. They are not evidence, reviewed findings, query-run results,
  dispositions, or authorization to act.
- A source-report citation shows where supporting language appears in the
  report; it does not establish that the behavior occurred in the local
  environment.
- Report instructions can influence a model. Structured output validation and
  fixed task prompts reduce prompt-injection risk but do not eliminate
  hallucination, omission, or misleading synthesis.
- The current governed assistant supports Enterprise ATT&CK report-to-hunt
  generation only. Mobile ATT&CK, ICS ATT&CK, and MITRE ATLAS report domains are
  rejected for this workflow.
- Long reports may be processed only in part. The interface warns when the
  bounded source limit truncates input; conclusions cannot be extended to
  omitted text.
- Saved-hunt assistance also uses bounded context: the canonical query is
  limited to 12,000 characters; only the newest five query versions and newest
  50 active findings are included; and their query, backend-assumption, summary,
  and note fields have documented per-field caps. The response warns whenever
  these limits omit or truncate current data.
- Suggestions are generated from a source and hunt snapshot. The API rejects a
  result if that stored context changes during the provider call. A report or
  hunt changed later still makes the earlier suggestion stale and requires
  regeneration or explicit manual comparison.
- Query drafts remain implementation-dependent. Analysts must validate fields,
  syntax, time bounds, performance, and read-only behavior in the destination
  before execution.
- The AI-assistance record stores the validated suggestion, governance and
  provenance metadata, and bounded server-validated citation excerpts of at
  most 300 characters each. It does not store the full raw report, raw prompt,
  or raw provider response. The original report remains subject to the report
  store's access and retention controls.

## Evidence-to-Detection Graph

- Graph nodes and edges preserve analyst reasoning, but they do not prove that a
  detection is complete or production-ready.
- AI-generated graph items are drafts until analyst-reviewed.
- Detection Readiness Score is an operational completeness score, not scientific
  coverage proof.
- A static malware finding, IOC, or actor name does not prove behavior unless the
  supporting evidence is reviewed.
- Evidence Pack exports may contain sensitive report excerpts and analyst
  conclusions; handle them as investigation artifacts.

## Unified RAG and Navigator AI

- Hybrid retrieval improves discovery; it does not prove relevance,
  attribution, targeting, exploitation, or compromise. Vector similarity is a
  ranking signal, not evidence confidence.
- The assistant refuses ungrounded generation when no safe indexed source
  matches. A refusal is not evidence that no relevant intelligence exists.
- Source markers bind the answer to retrieved excerpts but do not guarantee the
  model interpreted them correctly. Review the source route and full record.
- IOC freshness/confidence, CVE relationships, actor links, sector labels, and
  ATT&CK mappings inherit source limitations and can be incomplete or stale.
- Actor sector/region/technology observations are indexed from the normalized
  observation table with evidence and sanitized references, not raw provider
  JSON. They have no per-observation distribution marking and are therefore
  treated as `TLP:AMBER+STRICT`; their presence still does not prove current
  victim selection or campaign scope.
- Relationship expansion is one non-recursive search over allowlisted IDs from
  the initial result set, and only runs for an explicitly requested target class
  that is present in the source filter. It is not a complete graph traversal or
  evidence that an absent relationship does not exist.
- IOC/CVE relationship evidence and current ATT&CK usage/attribution text are
  preserved for review, but indexing does not independently validate, approve,
  or strengthen the underlying relationship. A business-context match followed
  by an actor-to-IOC link is not proof that the IOC targets that business.
- A business profile supplies deterministic relevance context. It does not show
  that an actor or IOC targets that organization.
- Navigator output is an expiring proposal. Preview does not change selected
  techniques, confirmation does not save a named layer, and every ID still
  requires analyst review.
- The corpus contains curated derived excerpts and remains sensitive data. It
  is covered by database backup, access, retention, and deletion controls.
- AdversaryGraph is single-workspace. The RAG corpus is not a tenant-isolation
  mechanism for mutually untrusted customers.

## Privacy

Other Docker-mode AI workflows send their selected input to the configured LLM
provider. Threat Hunting AI defaults to the operator-configured local endpoint;
cloud use is disabled by default and requires operator enablement plus explicit
analyst acknowledgment. `TLP:AMBER+STRICT` and `TLP:RED` assistant inputs are
local-only. A stored source report defaults conservatively to
`TLP:AMBER+STRICT`; only the `manage_intel` report-edit path may change its
server-side marking, and a request may raise but cannot lower it. The governed
local adapters reject public hostnames, but an accepted loopback/private-IP or
private-service-DNS endpoint is private only when the operator has also deployed
and governed its routing, access control, TLS, logging, and retention that way.

## Sector Intelligence

- Sector relevance is a prioritization aid, not proof that an actor is currently
  targeting a specific client.
- Source coverage depends on MISP Galaxy metadata and local synced references.
- Broad labels such as private sector are weak evidence and require analyst
  review.
- Activity windows depend on available campaign/report dates and may miss
  unreported activity.

## IOC Intelligence

- ATT&CK does not provide live IOCs; IOCs come from separate feeds or analyst
  imports.
- Many actors will have zero linked IOCs if sources do not name the actor or an
  alias directly.
- Public IOCs may be stale, sinkholed, re-used, or weakly attributed.
- Actor-linked IOCs should be presented with source, freshness, and confidence.
- Uploaded report IOC extraction is best-effort and requires analyst review.

## Deployment

The default Compose profile is intended for local and controlled self-hosted use. It is not a hardened public SaaS configuration.

The API's generic size pre-check relies on a client-declared `Content-Length`;
it is not a decoded-body streaming limiter. The bundled Nginx configurations
enforce decoded request limits and route-specific upload allowances. A custom
deployment must reproduce those ingress limits and must not expose the API
container directly to untrusted clients.
