# AdversaryGraph v6 Case Studies

These are reproducible local acceptance case studies built from fictional
repository data. They demonstrate implemented workflows and review criteria;
they are not customer testimonials, external benchmark results, or proof of
real-world detection efficacy.

> **Release boundary:** Case Studies 1–3 apply to the tagged `v6.0.0`
> platform. Case Studies 4–6 document Unified RAG/MCP capabilities included in
> the v6.5.0 source release; they were not shipped in the immutable `v6.0.0`
> tag, and become immutable v6.5 evidence only after its tag workflow succeeds.

## Case Study 1: Report Evidence to Detection Review

### Objective

Turn a public-style report excerpt into reviewable ATT&CK candidates while
preserving the difference between source evidence, analyst decisions, and
generated detection ideas.

### Inputs

- [`demo/sample-report.md`](../demo/sample-report.md)
- [`demo/expected-techniques.json`](../demo/expected-techniques.json)
- [`demo/expected-iocs.json`](../demo/expected-iocs.json)
- [`demo/expected-report.md`](../demo/expected-report.md)

### Workflow

1. Upload or paste the sample report in AI Analysis.
2. Review extracted evidence snippets before accepting mappings.
3. Compare candidate techniques and IOCs with the expected baseline.
4. Open the Evidence-to-Detection Graph and record gaps, telemetry needs,
   detection candidates, and analyst decisions.
5. Export the reviewed result for handoff.

### Acceptance Evidence

- Every accepted ATT&CK mapping has a behaviorally relevant source reference.
- Actor or campaign overlap is labeled as a lead, not attribution.
- Generated rules remain drafts until tested against representative telemetry.
- Unexpected and missing mappings are recorded as review findings rather than
  silently normalized to the expected file.

### Outcome

The workflow provides a defensible chain from report text to analyst-reviewed
work items without presenting the LLM output as ground truth.

## Case Study 2: Asset Exposure Prioritization

### Objective

Convert a small fictional inventory into prioritized exposure questions and
ATT&CK candidates for security-owner review.

### Inputs

- [`demo/asset-inventory.csv`](../demo/asset-inventory.csv)
- [`demo/evidence-graph/sample-assets.csv`](../demo/evidence-graph/sample-assets.csv)
- Threat Radar templates under [`templates/threat-radar/`](../templates/threat-radar/)

### Workflow

1. Import the demo inventory into Asset Surface.
2. Review normalized products, technologies, reachability, criticality, and
   internet exposure.
3. Open inventory-derived ATT&CK candidates as a separate Navigator layer.
4. Use Threat Radar to relate product/component/dependency signals to exposure.
5. Assign high-priority findings to PSIRT, Hunt, IR, or Detection workflows.

### Acceptance Evidence

- Inventory-derived techniques remain candidates until validated by asset
  owners and authoritative configuration data.
- Risk scoring preserves the inputs that drove exposure and priority.
- Product, component, dependency, and asset relationships retain stable IDs or
  normalized labels.
- Legal-sensitive signal handling stores sanitized metadata only.

### Outcome

The workflow creates a review queue that connects product-security signals to
actual inventory context without claiming exploitability solely from a CVE,
technology name, or generated score.

## Case Study 3: Controlled Attack Simulation and SIEM Validation

### Objective

Validate that a safe ATT&CK-shaped lab scenario produces source-labeled
telemetry and can be delivered to a test SIEM without turning the platform into
an arbitrary attack runner.

### Inputs

- Built-in `attack-lab-web` approved target
- T1595 HTTP/TLS fingerprint scenario
- A test HTTP(S) collector with non-production credentials
- [`demo/firewall.log`](../demo/firewall.log) and
  [`demo/edr.jsonl`](../demo/edr.jsonl) for parser comparison

### Workflow

1. Select T1595 in Attack Simulation.
2. Confirm the approved target, authorization, expected telemetry, and
   detection focus.
3. Run the fixed benign lab request set.
4. Confirm the target-side access/security log includes the run identifier.
5. Forward only the selected run to the test collector.
6. Record delivery status, parsing result, detection result, and gaps.

### Acceptance Evidence

- The executed target is present in the approved lab registry.
- The platform sends fixed benign requests and no arbitrary command or exploit
  payload.
- Real lab telemetry and synthetic AI telemetry are labeled separately.
- SIEM credentials are not retained in saved destination history or logs.
- A successful HTTP delivery is not treated as a successful detection; parser
  and rule results are recorded independently.

### Outcome

The workflow supports repeatable parser, field-mapping, and detection-rule
validation while preserving authorization and telemetry-fidelity boundaries.

## Case Study 4: Business-Context IOC Research With Relationship Evidence

### Objective

Find IOCs that may be relevant to a fictional Israel-based technology company
without converting business similarity, vector proximity, or a shared actor ID
into a targeting or compromise claim.

### Inputs

- Saved profile: sector `technology`, region `Israel`, representative cloud and
  identity technologies, and non-secret crown-jewel categories
- A stored actor-intelligence observation that associates a fictional actor ID
  with source-provided regional/sector context
- An IOC record with a separately stored source-backed link to the same actor ID
- A reconciled unified RAG corpus; embeddings are optional

The deterministic unit fixture is in
[`backend/tests/unit/test_rag_service.py`](../backend/tests/unit/test_rag_service.py).
It uses fictional identifiers and does not assert that any real actor targets
an Israeli organization.

### Workflow

1. In Navigator, open **AI RAG assistant** and select the saved business
   profile. Confirm that region, sector, technologies, and crown jewels are the
   intended server-side context.
2. Select **IOCs** and **Actors**. Add report sources only when their handling
   and provenance have been reviewed.
3. Enter: “Find IOCs relevant to this saved business profile. Separate direct
   facts from relationship-based relevance and show freshness limitations.”
4. Select **Search evidence** before generation. Record whether retrieval is
   exact/full-text only or whether vector and relationship signals also
   contributed.
5. Review the actor-observation source card. Confirm observation type/value,
   actor ID, confidence, source reference, TLP, and dates.
6. Review the IOC card independently. Confirm observable type/value, source,
   first/last seen, confidence, relationship type, and the evidence stored on
   its actor link.
7. If a synthesis is useful, select **Generate grounded answer** with the local
   provider. Require distinct citations for the business-context observation
   and IOC relationship.
8. Record unsupported, stale, or weak links as limitations. Perform blocking,
   hunt creation, incident escalation, or response only in the corresponding
   governed workflow after separate validation.

### Acceptance Evidence

- A selected profile affects query expansion and deterministic reranking but is
  not exposed as a globally retrievable source document.
- The bounded relationship pass searches only allowlisted shared identifiers
  from initial results and does not recursively traverse the graph.
- A relationship-expanded IOC includes the `relationship` signal and the
  targeting/compromise warning.
- Prompt-only wording such as “my company” produces a non-authoritative-scope
  warning when no saved profile is selected.
- Actor-intelligence context fails closed to `TLP:AMBER+STRICT`; selected
  business context and legally sensitive records cannot be sent to a remote
  provider.
- Every operationally material fact remains traceable to a source ID, excerpt,
  route, content hash, handling label, and index timestamp.

### Outcome

The result is a review queue of potentially relevant observables with explicit
fact/inference separation. It is not an automated block list, actor attribution,
or finding of compromise.

## Case Study 5: Cited TTP Proposal to an In-Memory Navigator Selection

### Objective

Turn reviewed cross-source intelligence into a bounded ATT&CK proposal, preview
the exact technique set, and apply it to Navigator only after freshness,
catalog, ownership, checksum, and human-review checks.

### Inputs

- Current local Enterprise ATT&CK catalog and an open Navigator workspace
- Reconciled reports, campaigns, actors, IOC/CVE relationships, hunts, or asset
  records that contain supported ATT&CK IDs
- A configured governed chat provider; local is required whenever effective
  handling is `TLP:AMBER+STRICT`, `TLP:RED`, or legal-sensitive

### Workflow

1. Select the intended business profile and source groups in **AI RAG
   assistant**.
2. Ask: “Propose only Enterprise ATT&CK techniques directly supported by the
   cited sources. Explain every inclusion and create a Navigator proposal; do
   not claim it was applied or saved.”
3. Review the generated explanation, cautions, effective TLP, citation cards,
   canonical routes, and every technique rationale.
4. Confirm that malformed, invented, deprecated, wrong-domain, non-current, or
   uncited technique IDs are absent.
5. Select **Preview _N_ on Navigator**. Confirm that the temporary overlay is
   visible while the active selection remains unchanged.
6. Select **Review Add / Replace diff**. Compare added, already-selected, and
   removed techniques; select the intended mode and affirm evidence review.
7. Confirm the proposal. The server rechecks the proposal owner (or
   `manage_intel` override), 30-minute expiry, checksum, cited chunk hashes,
   domain, current ATT&CK version, and every technique ID.
8. Confirm that only the validated receipt is applied to the browser's
   in-memory selection. Save a named layer separately if persistence is needed.
9. Change a cited chunk, expire the proposal, change the catalog, or submit the
   same proposal again in negative-path validation; each case must prevent a
   second or stale application.

### Acceptance Evidence

- The provider must return schema-valid JSON and use known `[S#]` markers in
  the answer; unknown or missing citation markers reject the response.
- A proposed technique must be present in cited evidence and pass the current
  local ATT&CK/ATLAS catalog check.
- Preview does not mutate the active selected-technique set.
- Confirmation returns `persisted=false`; it does not create a saved layer.
- Confirmation is single-use and fails on expiry, checksum mismatch, withdrawn
  evidence, catalog-version mismatch, or technique revalidation failure.
- Changing request context or Navigator selection clears or invalidates pending
  local review state before client-side application.

### Outcome

The workflow accelerates intelligence-to-Navigator mapping while preserving a
human-controlled, evidence-bound change boundary. The selected techniques are
investigative hypotheses, not proof that behavior occurred locally.

## Case Study 6: Local MCP Research Without a Remote Control Plane

### Objective

Let a desktop MCP client search and summarize the governed intelligence corpus
without opening a remote MCP listener or exposing mutation, confirmation,
reindex, feed, simulation, SIEM, or response tools.

### Inputs

- The stdio MCP process launched from the backend environment
- `MCP_API_BASE_URL` set to an approved API origin
- When authentication is enabled, a dedicated non-administrator session whose
  effective permissions include `run_analysis`
- A ready RAG corpus and configured local chat model for AI tools

### Workflow

1. Configure the client to launch `python -m app.mcp_server` over stdio. Store
   the bearer session token in the client's secret facility, not the repository.
2. Call `search_intelligence` with the fictional business query, explicit
   source filters, domain, saved profile ID, and a bounded result limit.
3. Verify returned excerpts, routes, TLP/legal flags, scores, retrieval signals,
   hashes, index time, and warnings.
4. Call `get_indexed_entity` only for a returned source type and source ID; it
   must return sanitized bounded chunks, not the raw database row.
5. Call `ask_intelligence`; confirm that it is pinned to `provider=local`, uses
   verified citations, and cannot acknowledge cloud processing.
6. Call `propose_navigator_layer`; confirm that it reports
   `confirmation_performed=false`, `navigator_state_changed=false`, and
   `saved_layer_created=false`.
7. Attempt a non-stdio transport, public plain-HTTP origin, invalid source type,
   traversal-shaped source ID, oversized input, redirect, revoked token, and
   missing permission. Each must fail safely without returning raw API bodies or
   secrets.

### Acceptance Evidence

- The process exposes exactly four tools and supports stdio only.
- API operations are fixed to RAG search, assistance, and indexed-entity reads;
  dynamic entity segments are allowlisted, bounded, and percent-encoded.
- Environment proxies and redirect following are disabled, responses are size
  bounded, and errors are sanitized.
- Read tools require `run_analysis`; AI tools additionally create governed
  assistance/audit artifacts but do not mutate operational platform state.
- The MCP toolset cannot list or modify profiles, reindex, confirm a proposal,
  save a layer, execute a hunt, forward telemetry, or perform response.

### Outcome

MCP provides a local integration surface for evidence retrieval and advisory
synthesis. It is not a remote autonomous agent endpoint and cannot bypass the
browser's explicit Navigator confirmation workflow.

## Reviewer Evidence Map

| Evidence | Location |
|---|---|
| Sanitized inputs and expected outputs | [`demo/`](../demo/) |
| Tagged v6.0.0 visual evidence | [v6 screenshot manifest](assets/adversarygraph-v6/manifest.md) |
| Automated browser smoke coverage | [`frontend/tests/e2e/`](../frontend/tests/e2e/) |
| RAG retrieval, collectors, relationship expansion, and business reranking | [`backend/tests/unit/test_rag_service.py`](../backend/tests/unit/test_rag_service.py) |
| Citation validation and supported-TTP proposal filtering | [`backend/tests/unit/test_rag_ai.py`](../backend/tests/unit/test_rag_ai.py) |
| RAG authorization, profile, assistance, proposal, and indexing contracts | [`backend/tests/integration/test_rag_routes.py`](../backend/tests/integration/test_rag_routes.py) |
| MCP transport, endpoint, bounds, output, and no-mutation contracts | [`backend/tests/unit/test_mcp_server.py`](../backend/tests/unit/test_mcp_server.py) |
| Citation-route browser behavior | [`frontend/tests/e2e/intelligence-deep-links.spec.ts`](../frontend/tests/e2e/intelligence-deep-links.spec.ts) |
| Validation rules and limitations | [Validation and Limitations](validation-and-limitations.md) |
| Production acceptance gates | [v6 Release Readiness](release-readiness-v6.md) |
| Attack Simulation safety model | [Attack Simulation](attack-simulation.md) |

The tagged v6.0.0 screenshot manifest predates the unified RAG/MCP changes and
must not be presented as visual proof of these three later case studies. Their
current evidence is the linked deterministic unit, integration, and browser
tests plus deployment-specific review of the running UI. Capture new sanitized,
revision-bound screenshots before publishing visual claims for this feature.
