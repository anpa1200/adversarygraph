# AdversaryGraph Usecases.

## Draft

## Usecase number "22"

### Investigation: Cloud And Kubernetes Incident: AdversaryGraph Use Case

**Version focus:** AdversaryGraph v2.5.9  
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

**Situation:** A cloud customer reports suspicious service account activity, container execution, and unusual outbound connections.

**Analyst objective:** Map cloud and Kubernetes behavior to ATT&CK and produce practical detection tasks.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Collect cloud logs, Kubernetes audit snippets, and incident notes.**
2. **Analyze the report text with AI Analysis.**
3. **Filter Sector Intel by cloud and Kubernetes technology.**
4. **Map extracted TTPs to Enterprise and relevant cloud behavior.**
5. **Enrich domains and IPs.**
6. **Compare against actor profiles with cloud tradecraft.**
7. **Generate KQL/Sigma drafts for identity, container, and network telemetry.**
8. **Export coverage gaps and customer-facing summary.**

## Expected Output

A cloud incident workup with TTP mapping, IOC enrichment, actor relevance, and cloud-focused detection backlog.

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
