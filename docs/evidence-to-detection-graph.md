# Evidence-to-Detection Graph

The Evidence-to-Detection Graph is the AdversaryGraph reasoning layer that
preserves how an analyst moves from raw evidence to a validated detection
outcome.

```text
Evidence
  -> Claim
  -> Behavior
  -> ATT&CK Technique
  -> Required Telemetry
  -> Detection Candidate
  -> Detection Rule
  -> Validation Scenario
  -> SIEM Result
  -> Analyst Decision
```

It is not a decorative graph. It stores typed nodes and reviewed/draft edges in
PostgreSQL so CTI, IOCs, malware findings, assets, Attack Simulation runs, SIEM
results, detection logic, reports, and analyst decisions can be connected with
evidence and review state.

## Why It Exists

CTI-to-detection work often loses context:

- a report says something happened;
- an AI assistant maps it to ATT&CK;
- a detection engineer guesses which telemetry is required;
- a Sigma/KQL/SPL rule is drafted;
- a lab or SIEM validation is performed;
- an analyst eventually accepts or rejects the result.

Without a reasoning graph, those steps become disconnected notes. The graph
keeps each step explicit, reviewable, exportable, and auditable.

## Data Model

The implementation uses relational tables:

- `evidence_graph_nodes`
- `evidence_graph_edges`

Nodes have a `node_type` discriminator. Edges include source, target, edge type,
rationale, confidence, creator, review status, AI marker, and metadata.

This preserves graph behavior without introducing Neo4j or another datastore.

## Node Types

| Node type | Purpose |
|---|---|
| Evidence | Raw source artifact or finding: report text, IOC, malware finding, asset observation, log event, simulation event, SIEM event, or analyst note |
| Claim | A statement extracted from evidence; may be observed, inferred, vendor-supplied, analyst-authored, or AI-suggested |
| Behavior | Normalized adversary or system behavior |
| ATT&CK Technique | ATT&CK, ATLAS, or custom technique mapping with rationale |
| Required Telemetry | Data source/component and required fields needed to validate or detect behavior |
| Detection Candidate | Detection hypothesis or engineering opportunity |
| Detection Rule | Concrete rule logic such as Sigma, SPL, KQL, EQL, YARA, or custom |
| Validation Scenario | Lab, replay, synthetic, manual, or external scenario used to test detection |
| SIEM Result | Collector/SIEM validation result and match state |
| Analyst Decision | Final review decision and next action |

## Edge Types

Important operational edges include:

- `SUPPORTS`: evidence supports a claim.
- `DESCRIBES`: claim describes behavior.
- `MAPS_TO`: behavior maps to ATT&CK/ATLAS/custom technique.
- `REQUIRES_TELEMETRY`: technique requires specific telemetry.
- `ENABLES_DETECTION`: telemetry enables a detection candidate.
- `IMPLEMENTED_AS`: candidate becomes rule logic.
- `VALIDATED_BY`: rule is tested by a validation scenario.
- `PRODUCED_RESULT`: scenario creates SIEM/collector result.
- `REVIEWED_AS`: SIEM result receives analyst decision.
- `RELATED_IOC`, `RELATED_ASSET`, `RELATED_REPORT`, `RELATED_MALWARE_FINDING`: connect graph reasoning to existing platform entities.
- `CONTRADICTS`, `WEAKENS`, `GAP_BLOCKS`: represent uncertainty, weak evidence, and detection blockers.

## Analyst Workflow

The UI exposes a top-level **Evidence Graph** page.

Primary views:

- Graph Overview: node/edge counts, readiness score, gaps, AI drafts, validation coverage.
- Interactive Graph View: typed nodes and labeled edges.
- Reasoning Path View: readable linear chain from evidence to analyst decision.
- Gap View: missing telemetry, missing rules, missing validation, missing SIEM results, and missing decisions.
- Node Detail Panel: approve, reject, request more evidence, and create next-step nodes.
- Analyst Review Queue: unreviewed AI suggestions, unresolved validation results, and evidence blockers.

## AI Review Model

AI may generate draft claims, behavior normalization, ATT&CK mappings, telemetry
requirements, detection candidates, validation ideas, and report text.

AI must not auto-approve:

- claims;
- ATT&CK mappings;
- attribution;
- detection readiness;
- validation results;
- analyst decisions.

Every AI-generated node or edge must carry:

- `ai_generated: true`
- provider/model metadata when available
- rationale
- confidence
- `review_status: draft`

## Detection Readiness Score

The graph computes a deterministic operational readiness score from 0 to 100.
It is not scientific truth and must not be used as proof of coverage.

Current scoring:

| Condition | Points |
|---|---:|
| Evidence exists | 15 |
| Analyst-reviewed claim exists | 15 |
| Analyst-reviewed ATT&CK mapping exists | 15 |
| Required telemetry is available or validated | 20 |
| Detection rule exists | 15 |
| Validation scenario exists | 10 |
| SIEM result succeeded and matched | 5 |
| Analyst accepted or marked production-ready | 5 |

Rejected nodes and edges do not improve readiness.

## Gap Analysis

A gap is created when:

- a technique has evidence but no required telemetry;
- a technique has no detection candidate;
- required telemetry is unavailable, partial, or unknown;
- a detection candidate is blocked by missing telemetry or parser work;
- a detection rule has no validation scenario;
- a validation scenario has no SIEM result;
- a SIEM result did not match;
- a SIEM result has no analyst decision;
- an AI-generated claim or mapping is still unreviewed.

## Exports

Supported API exports:

- JSON graph export.
- Markdown report export.
- CSV nodes export.
- Evidence Pack ZIP containing `graph.json`, `nodes.csv`, `edges.csv`,
  `gaps.csv`, `report.md`, and `metadata.json`.

Export safety:

- secrets are redacted by key name;
- malware binaries are not exported;
- SIEM credentials are not exported;
- evidence excerpts may still be sensitive, so exports include a warning.

## API

Primary endpoints:

- `GET /api/evidence-graph/summary`
- `GET /api/evidence-graph`
- `POST /api/evidence-graph/nodes`
- `PATCH /api/evidence-graph/nodes/{node_id}`
- `DELETE /api/evidence-graph/nodes/{node_id}`
- `POST /api/evidence-graph/edges`
- `PATCH /api/evidence-graph/edges/{edge_id}`
- `DELETE /api/evidence-graph/edges/{edge_id}`
- `GET /api/evidence-graph/paths`
- `GET /api/evidence-graph/gaps`
- `POST /api/evidence-graph/from-report/{report_id}`
- `POST /api/evidence-graph/from-simulation/{simulation_run_id}`
- `POST /api/evidence-graph/from-ioc/{ioc_id}`
- `POST /api/evidence-graph/from-asset/{asset_id}`
- `POST /api/evidence-graph/from-malware/{case_id}`
- `GET /api/evidence-graph/export?fmt=json|markdown|csv|evidence-pack`

## Security Boundaries

- Viewer can read graph data.
- Analyst can create/update draft nodes, edges, and decisions.
- Admin is required for delete operations.
- Mutations are audit logged.
- Graph query depth and result size are bounded.
- Export redacts secret-like metadata keys.
- Attack Simulation remains defensive validation only.
- Malware Analysis remains static-first and safe by default.
- TTP overlap is not attribution proof.

## Demo Data

Safe synthetic demo files are in [`demo/evidence-graph/`](../demo/evidence-graph/).
They use fictional activity, `example.com`, and RFC5737 documentation IP ranges.

## Limitations

- The first implementation stores graph nodes and edges as relational tables and
  renders the graph in the frontend; it is not a graph database.
- Typed foreign-key tables for every external entity are planned, while the
  current implementation preserves external references in `source_ref` and
  metadata.
- Required telemetry import from ATT&CK data components is best-effort and
  should be analyst-reviewed.
- SIEM match status must be attached from validation results; the graph does not
  prove production detection by itself.
