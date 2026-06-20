# AdversaryGraph Usecases.

## Usecase number "19"

### Review One Coverage Gap: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.7.0
**Level:** Intermediate, 3-5 steps
**Workflow group:** Intermediate Usecases

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

**Situation:** A SOC manager asks whether a specific ATT&CK technique is covered by current detections.

**Analyst objective:** Inspect a single missing or weakly covered technique and create next steps.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Open Navigator or coverage view.**
2. **Select the technique.**
3. **Review actor/report usage evidence.**
4. **Generate or draft detection logic for the target SIEM/rule format.**

## Expected Output

A coverage-gap note with evidence, affected actors, rule draft, and review status.

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
