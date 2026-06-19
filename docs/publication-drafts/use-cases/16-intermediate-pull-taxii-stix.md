# AdversaryGraph Usecases.

## Draft

## Usecase number "16"

### Pull TAXII Or Import STIX: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.5.9  
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

**Situation:** A team receives STIX/TAXII intelligence from a sharing community or internal platform.

**Analyst objective:** Import structured STIX objects into local IOC and CTI context.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Open Feeds Management.**
2. **Add TAXII collection URL, token, or basic auth as needed.**
3. **Pull STIX objects.**
4. **Review imported indicators and observed-data mappings.**

## Expected Output

A synchronized TAXII/STIX feed represented in the IOC Library and CTI workflow.

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
