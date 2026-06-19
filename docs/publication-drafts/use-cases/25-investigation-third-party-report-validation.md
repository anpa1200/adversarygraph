# AdversaryGraph Usecases.

## Usecase number "25"

### Investigation: Validate A Third-Party CTI Report: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.6.0
**Level:** Complex investigation workflow
**Workflow group:** Complex Investigation Usecases

## Table Of Contents

- [Why This Use Case Matters](#why-this-use-case-matters)
- [Real-Life Scenario](#real-life-scenario)
- [Workflow](#workflow)
- [Expected Output](#expected-output)
- [Analyst Review Standard](#analyst-review-standard)
- [Where This Fits](#where-this-fits)

## Why This Use Case Matters

AdversaryGraph is useful when an analyst needs to move from raw intelligence to reviewed action: ATT&CK mapping, IOC enrichment, actor context, feed synchronization, matrix visualization, detection generation, and exportable evidence. This use case shows one practical way to use the platform without separating the work across spreadsheets, browser tabs, and disconnected notes.

## Real-Life Scenario

**Situation:** A customer sends an external CTI report and asks whether it is actionable for their sector.

**Analyst objective:** Validate report claims, map evidence, and identify what is usable for defense.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Upload the report.**
2. **Extract TTPs, IOCs, sectors, actors, and malware names.**
3. **Enrich all IOCs and check source recency.**
4. **Compare TTPs with actor profiles and sector filters.**
5. **Reject unsupported or vague mappings.**
6. **Mark uncertain mappings as needs-evidence.**
7. **Create a customer-ready validation summary.**

## Expected Output

A validated CTI report summary with accepted findings, rejected claims, evidence gaps, and recommended actions.

## Analyst Review Standard

- Preserve source labels and timestamps for every finding.
- Mark weak or incomplete evidence as `needs-evidence` instead of forcing a conclusion.
- Treat actor similarity as a hypothesis, not attribution.
- Prefer source-backed report evidence first, enrichment-platform evidence second, and AI enrichment only as reviewed support.
- Export only findings that have been reviewed by an analyst.

## Where This Fits

This use case supports CTI production, SOC triage, threat hunting, detection engineering, customer reporting, or platform validation depending on the workflow level.

**Project:** https://github.com/anpa1200/adversarygraph
**Docs:** https://1200km.com/adversarygraph-docs/
**Use cases:** https://1200km.com/adversarygraph/use-cases.html
