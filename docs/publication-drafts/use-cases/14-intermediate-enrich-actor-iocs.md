# AdversaryGraph Usecases.

## Usecase number "14"

### Enrich Actor IOCs: AdversaryGraph Use Case

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

![Usecase 14 - Enrich Actor IOCs walkthrough](../assets/use-cases/usecase-14-enrich-actor-iocs.gif)

## Why This Use Case Matters

AdversaryGraph is useful when an analyst needs to move from raw intelligence to reviewed action: ATT&CK mapping, IOC enrichment, actor context, feed synchronization, matrix visualization, detection generation, and exportable evidence. This use case shows one practical way to use the platform without separating the work across spreadsheets, browser tabs, and disconnected notes.

## Real-Life Scenario

**Situation:** An actor profile has only partial IOC coverage and the analyst needs current infrastructure context.

**Analyst objective:** Use source-backed enrichment before adding AI-derived context.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Open the actor IOC tab.**
2. **Sync ThreatFox, OTX, MalwareBazaar/Malpedia, or custom feeds.**
3. **Open IOC Enrichment for high-value values.**
4. **Add accepted mapped TTPs to My TTPs where evidence supports it.**

## Expected Output

An enriched actor IOC view with source labels, malware family context, TTP hints, and review state.

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
