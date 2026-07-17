# AdversaryGraph v6 Case Studies

These are reproducible local acceptance case studies built from fictional
repository data. They demonstrate implemented workflows and review criteria;
they are not customer testimonials, external benchmark results, or proof of
real-world detection efficacy.

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

## Reviewer Evidence Map

| Evidence | Location |
|---|---|
| Sanitized inputs and expected outputs | [`demo/`](../demo/) |
| Current visual evidence | [v6 screenshot manifest](assets/adversarygraph-v6/manifest.md) |
| Automated browser smoke coverage | [`frontend/tests/e2e/`](../frontend/tests/e2e/) |
| Validation rules and limitations | [Validation and Limitations](validation-and-limitations.md) |
| Production acceptance gates | [v6 Release Readiness](release-readiness-v6.md) |
| Attack Simulation safety model | [Attack Simulation](attack-simulation.md) |
