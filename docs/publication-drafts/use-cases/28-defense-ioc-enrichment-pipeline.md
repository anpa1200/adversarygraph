# AdversaryGraph Usecases.

## Draft

## Usecase number "28"

### Defense: Build IOC Enrichment Pipeline: AdversaryGraph Use Case

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

**Situation:** A SOC wants daily enrichment of IOCs from public, partner, and private sources.

**Analyst objective:** Connect feeds, enrich new values, map IOCs to TTPs, and keep external/custom data outside the container image.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Configure external database storage.**
2. **Open Feeds Management.**
3. **Connect ThreatFox, OTX, MalwareBazaar/Malpedia, MISP, TAXII/STIX, sandbox, and custom feeds.**
4. **Run sync and review source counts.**
5. **Enrich new indicators by source priority: strict report evidence, enrichment platform, then AI if approved.**
6. **Map IOCs to actors and TTPs.**
7. **Export CSV/STIX where needed.**

## Expected Output

A repeatable IOC enrichment pipeline with source attribution, mapped TTPs, actors, and update history.

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
