# Report Review Gate

The Report Review Gate is the authority boundary between report analysis and
trusted intelligence in AdversaryGraph. Parsing, deterministic extraction, and
AI assistance create candidates. They do not create authoritative ATT&CK
mappings, actor attribution, IOCs, RAG documents, hunt inputs, or STIX objects.

Only an immutable promotion manifest from a current, approved review revision
can cross that boundary.

## Security and governance invariants

- The stored source text and review-relevant analysis are SHA-256 fingerprinted.
- File uploads retain a point-in-time receipt with original-byte and extracted-
  text digests, size, filename, and acquisition time. URL reports retain the
  requested/final URL and retrieval receipt. A later source edit supersedes the
  receipt instead of recomputing it from the replacement text.
- Every source or analysis mutation makes the current review stale and starts a
  new revision.
- Machine preflight, AI suggestions, and analyst decisions are stored in
  separate fields.
- Provider output always enters as a suggestion. It cannot set a gate verdict,
  accept a claim, approve a review, or promote a report.
- Accepted claims must be locally bound to the stored source or stored retrieval
  metadata.
- ATT&CK overlap, malware similarity, and shared tooling are investigation leads,
  not actor attribution.
- Optimistic version checks reject stale browser writes instead of replaying
  them against a newer review.
- Approval requires a different authenticated human from the submitter.
- Promotion and revocation records are append-only. A revoked promotion remains
  in review history but is excluded from every active downstream projection.
- Service accounts may run ingestion and deterministic checks, but cannot write
  analyst decisions.

## Review lifecycle

```text
report stored or parsed
        |
        v
draft -> in_review -> approved -> promoted
  |          |            |          |
  |          v            v          v
  +----> changes_requested          revoked
  |
  +----> rejected

Any source or analysis change -> stale -> new draft revision
```

Each mutation increments the review `version`. The client must submit
`expected_version`; a mismatch returns HTTP 409 and no decision is applied.

## The five gates

| Gate | Deterministic evidence | Analyst decision requirement |
| --- | --- | --- |
| Source provenance | Stored source; upload byte/text digests and acquisition time; or public URL syntax, final URL, HTTP receipt, retrieval timestamp, and content hashes | Confirm that the stored source is genuine and correctly bound, or record a specific failure |
| Publication date | Parsed publication fields, report text dates, conflict and acquisition-timeline checks | Select and accept the supported date, or use the internal-IR exception where applicable |
| Procedure relevance | Exact source-bound behavior evidence and complete-coverage facts | Confirm that the report describes adversary or incident behavior rather than a name-only mention |
| Procedure-level claim | Specific source-bound action/object claims with locally valid ATT&CK or ATLAS IDs | Accept at least one concrete procedure claim; a generic tool label is insufficient |
| Actor identification | Explicit/source-reported actor evidence; similarity inputs are excluded | Accept explicit attribution, record no actor claim, or fail/request evidence; overlap alone cannot pass |

Machine verdicts are `not_run`, `pass`, `warning`, or `fail`. Analyst verdicts
are `pending`, `pass`, `fail`, `needs_information`, or a policy-limited
`not_applicable`. Machine output never copies into analyst columns.

## Claims and evidence

Claims are independently adjudicated as `suggested`, `accepted`, `rejected`, or
`needs_evidence`. Supported claim types are procedure, actor, publication date,
indicator, and vulnerability.

Text evidence is accepted only when the exact excerpt and offsets match the
stored report. Metadata evidence is accepted only when its value exists in the
stored acquisition record. Evidence copied only from model prose is discarded.

Analysts can add a manual claim using exact source offsets. This supports
reports where a date, procedure, actor, IOC, or CVE was not produced by the
initial parser. A manual claim remains suggested until a human accepts it.

## Coverage

The initial report-analysis adapter processes a bounded source window. The
review records both stored and analyzed character counts. Promotion is blocked
when coverage is incomplete unless one of these occurs:

- optional AI review assistance processes all bounded chunks and every retained
  suggestion is locally validated; or
- an analyst records an explicit coverage exception with a durable reason.

AI coverage does not change any gate or claim decision.

## Optional AI assistance

AI review assistance is advisory and defaults to the local provider. Remote
providers require the normal TLP policy checks and an explicit cloud-processing
acknowledgment. The report is divided into bounded overlapping chunks. Returned
JSON is schema checked, and every retained quotation is rebound to the exact
stored source.

Before remote egress, the request records a durable redacted attempt containing
provider, model, TLP, acknowledgment, coverage, and checksums. A second durable
event records success, failure, cancellation, invalid output, or a concurrent
review conflict. Raw report text and raw provider prose are never copied into
those audit events or a promotion manifest.

## Promotion manifest

A promotion snapshots only accepted claims and analyst gate decisions. Its
checksum binds the manifest and selected targets. The manifest includes:

- schema and policy versions;
- session, review, revision, and approval identities;
- source and analysis checksums;
- source coverage;
- accepted source-bound claims;
- the five analyst gate decisions; and
- generation time and downstream targets.

The manifest deliberately excludes raw model output, unresolved claims,
rejected claims, and TTP-similarity actor leads.

`canonical_intelligence` is mandatory. The analyst may additionally authorize
any combination of `rag`, `hunting`, and `exports`; target authorization is
immutable for that promotion and changing it requires revocation and a new
review revision.

## Downstream enforcement

| Consumer | Before promotion | After active promotion | After revocation or staleness |
| --- | --- | --- | --- |
| Reports / Research | Candidate tags and review badge | Promoted badge and immutable manifest reference | Stale/revoked badge; no active authority |
| Intelligence graph | No report-derived canonical edges | Accepted tags and claim-backed edges only | Promotion-provenance edges withdrawn |
| IOC library | Report-local IOC candidates only | Accepted IOCs under a reserved promotion-specific source, revalidated against the live manifest on reads | Promotion-specific IOC source withdrawn; stale rows fail closed if cleanup is delayed |
| RAG | Report excluded | When the `rag` target is selected, source plus accepted claims are indexed under the manifest checksum | Document removed during reconciliation |
| Threat Hunting AI | HTTP 409 for report-to-hypothesis | When the `hunting` target is selected, advisory hypotheses include promotion provenance | HTTP 409; in-flight requests fail revalidation |
| Asset retrohunt | Report excluded | Accepted intake projection matched | Matches removed on refresh |
| PDF | Clearly marked non-authoritative assessment | With the `exports` target, promoted assessment and accepted claims; otherwise still non-authoritative | Clearly marked revoked/stale assessment |
| STIX/OpenCTI | HTTP 409 | With the `exports` target, accepted procedures and explicit actor claims only | HTTP 409 |

## Permissions

- `review_reports` starts reviews, runs preflight, adjudicates gates and claims,
  adds manual claims, and records coverage exceptions.
- `promote_reports` requests changes, rejects, approves, promotes, and revokes.
- `read` can view assessments and append-only history.

Threat-intelligence and security-administration roles receive both permissions.
Analyst and incident-response roles receive review permission. Service accounts
receive neither decision permission.

## API surface

All paths are under `/api/analyze/sessions/{session_id}/review`.

- `GET /` - current assessment
- `POST /start` - start or reopen a fingerprinted revision
- `POST /preflight` - run the deterministic five-gate evaluator
- `PATCH /gates/{gate_key}` - record an analyst gate decision
- `POST /claims` - add a source-bound manual claim
- `PATCH /claims/{claim_id}` - adjudicate a claim
- `POST /coverage-exception` - record a bounded analyst exception
- `POST /submit` - submit the completed assessment
- `POST /approve` - approve a promotion-ready review
- `POST /request-changes` - return a review for correction
- `POST /reject` - reject the revision
- `POST /promote` - create and materialize the immutable manifest
- `POST /revoke` - append a revocation and withdraw projections
- `POST /ai-assist` - request source-bound advisory suggestions
- `GET /history` - append-only review history
- `GET /promotion` - current version-matched promotion

## Operator validation

Before release, verify:

1. A newly analyzed report receives a draft review and deterministic preflight.
2. An unpromoted URL report does not create global IOCs, graph edges, RAG
   documents, retrohunt matches, hunt hypotheses, or STIX objects.
3. A model-supplied `accepted` value is stored as `suggested`.
4. Unbound evidence and overlap-only actor claims cannot be accepted.
5. A concurrent stale `expected_version` write returns HTTP 409.
6. A source edit, reparse, or legacy technique-review mutation withdraws any
   active projection and creates a new draft revision.
7. Promotion materializes only accepted manifest claims.
8. Revocation removes active graph, IOC, RAG, hunt, retrohunt, and export
   eligibility while retaining history.
9. Replacing uploaded-file text cannot pass by hashing the replacement; the
   immutable acquisition digest mismatches or the receipt is marked superseded.
10. Generic IOC imports, enrichment, and taxonomy jobs cannot create or mutate
    the reserved `report-promotion-` projection namespace.
11. OpenCTI pull and taxonomy maintenance skip review-owned analyses; new or
    legacy-unreviewed OpenCTI reports enter deterministic preflight before
    their transaction commits.
12. `POST /api/ioc/report` returns only a local candidate preview and creates no
    global IOC or actor link.
13. Indicators embedded in OpenCTI reports remain attached to their reviewable
    report intake; only first-class indicator and observable feed objects retain
    their independent feed-import semantics.
14. RSS, STIX/TAXII, and MISP report intake retains extracted observables on the
    pending report and creates neither a global `Observable` nor a retrohunt
    match before promotion.
15. Generic IOC STIX/TAXII imports reject bundles containing STIX `report`
    objects; report-bearing collections must enter the candidate-only report
    pipeline instead of losing their report context in a global IOC import.
16. `POST /api/evidence-graph/from-report/{report_id}` accepts only a report
    session UUID or its unambiguous linked intake UUID, requires the exact
    current `canonical_intelligence` promotion, and materializes only accepted
    manifest claims with immutable promotion provenance. Generic graph writes
    cannot claim the reserved report namespace, and stale, replaced, revoked,
    or legacy-unprovenanced report rows disappear from graph views, readiness,
    exports, and RAG; RAG additionally requires the active `rag` target.
