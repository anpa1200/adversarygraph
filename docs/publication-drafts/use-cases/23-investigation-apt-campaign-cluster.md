# AdversaryGraph Usecases.

## Usecase number "23"

### Investigation: Cluster Multiple APT Reports: AdversaryGraph Use Case

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

**Situation:** Several vendor reports mention similar actors, aliases, malware, and infrastructure but use inconsistent names.

**Analyst objective:** Normalize the reporting and decide whether the cluster is one campaign, overlapping tradecraft, or separate activity.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Import all reports.**
2. **Extract TTPs and IOCs per report.**
3. **Normalize actor aliases through Group Library.**
4. **Compare reports pairwise and by campaign.**
5. **Review shared techniques and unique evidence.**
6. **Open related actor pages and IOC tabs.**
7. **Build a cluster summary with confidence levels.**
8. **Export the final matrix layer and evidence table.**

## Expected Output

A campaign-clustering package that separates strong evidence from weak similarity.

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
