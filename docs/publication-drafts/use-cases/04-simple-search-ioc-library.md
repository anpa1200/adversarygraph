# AdversaryGraph Usecases.

## Usecase number "4"

### Search The IOC Library: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.6.0
**Level:** Simple, 1-2 steps
**Workflow group:** Simple Usecases

## Table Of Contents

- [Why This Use Case Matters](#why-this-use-case-matters)
- [Real-Life Scenario](#real-life-scenario)
- [Workflow](#workflow)
- [Expected Output](#expected-output)
- [Analyst Review Standard](#analyst-review-standard)
- [Where This Fits](#where-this-fits)

## Walkthrough GIF

![Usecase 4 - Search The IOC Library walkthrough](../assets/use-cases/usecase-04-search-ioc-library.gif)

## Why This Use Case Matters

AdversaryGraph is useful when an analyst needs to move from raw intelligence to reviewed action: ATT&CK mapping, IOC enrichment, actor context, feed synchronization, matrix visualization, detection generation, and exportable evidence. This use case shows one practical way to use the platform without separating the work across spreadsheets, browser tabs, and disconnected notes.

## Real-Life Scenario

**Situation:** A SOC analyst wants to know whether an indicator has already appeared in local or synchronized intelligence.

**Analyst objective:** Search the local IOC database and see whether the value is mapped to actors, malware, reports, feeds, or TTPs.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Open IOC Library.**
2. **Search by indicator value, malware family, campaign, source, type, or actor.**

## Expected Output

A filtered IOC result with source, first seen, last seen, type, mapped actor, mapped TTPs, and enrichment button.

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
