# AdversaryGraph Usecases.

## Usecase number "18"

### Compare Two Reports: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.6.0
**Level:** Intermediate, 3-5 steps
**Workflow group:** Intermediate Usecases

## Table Of Contents

- [Why This Use Case Matters](#why-this-use-case-matters)
- [Real-Life Scenario](#real-life-scenario)
- [Workflow](#workflow)
- [Expected Output](#expected-output)
- [Analyst Review Standard](#analyst-review-standard)
- [Where This Fits](#where-this-fits)

## Walkthrough GIF

![Usecase 18 - Compare Two Reports walkthrough](../assets/use-cases/usecase-18-compare-two-reports.gif)

## Why This Use Case Matters

AdversaryGraph is useful when an analyst needs to move from raw intelligence to reviewed action: ATT&CK mapping, IOC enrichment, actor context, feed synchronization, matrix visualization, detection generation, and exportable evidence. This use case shows one practical way to use the platform without separating the work across spreadsheets, browser tabs, and disconnected notes.

## Real-Life Scenario

**Situation:** Two reports may describe related campaigns but use different names, IOCs, and writing styles.

**Analyst objective:** Compare extracted TTPs, actors, IOCs, malware families, and evidence overlap.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Analyze both reports.**
2. **Accept or reject extracted TTPs.**
3. **Open Compare.**
4. **Review shared and unique techniques, IOCs, and actor hints.**

## Expected Output

A comparison record showing overlap, divergence, and next investigation pivots.

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
