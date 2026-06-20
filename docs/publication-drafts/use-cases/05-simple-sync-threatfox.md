# AdversaryGraph Usecases.

## Usecase number "5"

### Sync ThreatFox IOCs: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.7.0
**Level:** Simple, 1-2 steps
**Workflow group:** Simple Usecases

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

**Situation:** The local IOC library needs current malware infrastructure before the team starts daily triage.

**Analyst objective:** Run a source sync and refresh recent ThreatFox-backed indicators.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Open Feeds Management.**
2. **Run ThreatFox sync and review imported or updated IOC counts.**

## Expected Output

Updated IOC records with source attribution, malware context, timestamps, and actor links where available.

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
