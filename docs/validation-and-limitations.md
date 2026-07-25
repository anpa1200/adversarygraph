# Validation and Limitations

This document records what AdversaryGraph can validate today and where analyst review is still required.

## Validation Rules

| Output | Validation requirement |
|---|---|
| ATT&CK mapping | Confirm the evidence describes behavior, not just a tool name or actor label |
| Group/campaign similarity | Treat TTP overlap as an investigation lead, not attribution |
| Generated detection logic | Test in the target SIEM/EDR/query engine before operational deployment |
| IOC enrichment | Check source, timestamp, confidence, and relationship context |
| RAG search result | Confirm the source route, content hash/index time, active retrieval signals, TLP/legal labels, and the authoritative record; ranking is not evidence confidence |
| Grounded AI answer | Verify every material statement against its cited full record; citation validity proves excerpt provenance, not model correctness |
| Navigator proposal | Verify domain, ATT&CK version, technique IDs, rationale, citations, expiry, and Add/Replace diff; confirmation is not a saved layer |
| Malware-analysis summary | Confirm static and runtime evidence separately; do not merge AI interpretation into ground truth |
| Asset Surface matrix | Validate exposure, ownership, criticality, and reachable services against authoritative inventory |
| Attack Simulation real telemetry | Confirm the lab target emitted the event and that the SIEM parsed it as expected |
| Attack Simulation synthetic telemetry | Use for parser/rule/correlation drills only; it is not proof of real exploit detection |
| Evidence-to-Detection Graph path | Confirm each node and edge review state; AI-generated graph items are hypotheses until analyst-reviewed |
| Detection Readiness Score | Treat as operational completeness scoring, not scientific proof of coverage |

## Implemented Validation Aids

- Review states for extracted mappings.
- Evidence snippets and source references where available.
- Saved investigations, asset-surface cases, and attack simulation runs.
- Real-time attacked-server log view for lab simulations.
- SIEM forwarding status, event counts, and recent destination history.
- Evidence Graph gaps, review queue, reasoning paths, readiness score, and Evidence Pack export.
- RAG source routes, exact/full-text/vector signal labels, content hashes,
  indexed timestamps, TLP/legal flags, business-context warnings, verified
  citations, and refusal when no safe source set is available.
- Expiring checksum-bound Navigator proposals with local ATT&CK validation,
  temporary preview, explicit Add/Replace review, and a non-mutating server
  confirmation receipt. The advisory record and confirmation state are kept
  for audit; `persisted=false` means no named Navigator layer was saved.
- Demo dataset with expected mappings and expected outputs.
- CI checks for tests, lint, dependency audit, Docker build, container scan, secret scan, and version consistency.

## Current Limitations

- The default deployment is not a hardened multi-tenant SaaS.
- Native username/password authentication provides project-level access control, but the default deployment is still not a hardened internet-facing SaaS.
- AI provider behavior can vary between model versions.
- Generated detections are drafts.
- Evidence Graph nodes and edges preserve reasoning state but do not prove attribution, coverage, or exploitability by themselves.
- Synthetic telemetry may match a vendor structure but is still generated data.
- SQL, FTP, identity, and egress simulation target classes require dedicated lab fixtures before they can be treated as real lab telemetry.
- Malware dynamic analysis requires isolated MalwareGraph runtime profiles and remains disabled by default.
- Business profiles improve deterministic ranking but do not prove that an
  actor, campaign, IOC, CVE, or technique targets the organization.
- Vector similarity and bounded one-hop relationship expansion can surface
  useful leads but do not prove attribution, targeting, exploitation, active
  infrastructure, or compromise. Absence from the derived corpus is not proof
  that intelligence does not exist.
- Semantic retrieval requires an approved private embedding service. When it is
  disabled or unavailable, supported exact/full-text fallback remains visible
  in the result mode.
- The MCP surface is local stdio advisory access, not a remote automation or
  response interface. It cannot confirm/apply Navigator proposals or mutate
  operational state.
- The client-only frontend uses React Router `6.30.3`. Two moderate npm
  advisories remain: one is limited to SSR hydration, which this frontend does
  not use, and one concerns untrusted backslash navigation values. External
  API-controlled URLs use the centralized safe-URL guard and browser tests
  cover unsafe schemes, but route values must still be treated as untrusted
  input. A Router 7 upgrade is deferred because the currently available
  release introduces a high-severity React Server Components advisory and
  requires a deliberate breaking migration.

## Reviewer Checklist

Before accepting a result as validated:

- Confirm the source record exists.
- Confirm the timestamp, run ID, case ID, or analysis ID matches the reviewed output.
- Confirm the ATT&CK technique is behaviorally justified.
- Confirm no private data was uploaded to public demos.
- Confirm generated detections were tested against representative telemetry.
- Confirm RAG source coverage and index freshness before treating search as a
  meaningful review aid.
- Follow every consequential assistant citation to its complete canonical
  record and document any stale, conflicting, or weak relationship evidence.
- Confirm a Navigator proposal did not silently persist, execute, or imply
  coverage; save and validate a named layer through the normal workflow only
  after review.
- Confirm the current frontend dependency audit and Router advisory review
  remain valid for the exact lockfile shipped with the release.
- Confirm Evidence Graph AI drafts, ATT&CK mappings, and readiness score inputs were analyst-reviewed.
- Document unresolved assumptions and validation gaps in the investigation.
