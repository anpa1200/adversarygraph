# AdversaryGraph Usecases.

## Usecase number "26"

### Defense: Build MITRE Coverage Baseline: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.6.0
**Level:** Complex defense workflow
**Workflow group:** Complex Defense Usecases

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

**Situation:** A detection team needs to know which ATT&CK techniques are covered before planning new engineering work.

**Analyst objective:** Create a baseline that shows current coverage, missing techniques, and priority actor-driven gaps.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Sync ATT&CK Enterprise, Mobile, ICS, and ATLAS where relevant.**
2. **Import current detection coverage layer.**
3. **Select relevant sectors, actors, and technologies.**
4. **Overlay actor TTPs on Navigator.**
5. **Identify uncovered high-priority techniques.**
6. **Generate a coverage report and backlog.**

## Expected Output

A baseline coverage map with prioritized missing techniques and supporting actor evidence.

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
