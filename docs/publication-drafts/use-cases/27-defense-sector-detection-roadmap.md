# AdversaryGraph Usecases.

## Draft

## Usecase number "27"

### Defense: Create Sector-Based Detection Roadmap: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.5.9  
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

**Situation:** A customer in telecom, finance, cloud, healthcare, or critical infrastructure needs a practical roadmap, not a generic ATT&CK list.

**Analyst objective:** Build a sector-driven detection plan from current actor relevance and technology exposure.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Open Sector Intel.**
2. **Select sectors, regions, technologies, and activity window.**
3. **Review ranked actors and relevant TTPs.**
4. **Open top actor profiles and IOC tabs.**
5. **Show relevant TTPs on matrix.**
6. **Group gaps by telemetry source and detection format.**
7. **Generate roadmap phases for quick wins, medium effort, and advanced coverage.**

## Expected Output

A customer-specific detection roadmap tied to actors, sector evidence, and ATT&CK coverage.

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
