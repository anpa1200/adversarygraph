# AdversaryGraph Usecases.

## Usecase number "21"

### Investigation: Ransomware Intrusion Triage: AdversaryGraph Use Case

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

**Situation:** A company discovers encrypted servers, PowerShell activity, lateral movement, suspicious domains, and possible data theft.

**Analyst objective:** Create an investigation package from raw incident material to actor hypotheses and detection handoff.

**Operational pressure:** The analyst needs an answer that is fast enough for daily work but still traceable enough for customer reporting, detection engineering, or later peer review.

## Workflow

1. **Run selftest and confirm enrichment keys.**
2. **Create an investigation workspace.**
3. **Upload or paste the incident report.**
4. **Extract TTPs and IOCs.**
5. **Review TTP status values.**
6. **Enrich IOCs with VT, OTX, ThreatFox, MalwareBazaar, sandbox, and custom feeds.**
7. **Compare accepted TTPs against actors and campaigns.**
8. **Show accepted TTPs on Navigator.**
9. **Generate Sigma/YARA/YARA-L/KQL/SPL/EQL drafts for priority gaps.**
10. **Export a PDF report and Navigator layer.**

## Expected Output

A full ransomware triage package with evidence-backed TTPs, enriched IOCs, actor hypotheses, matrix layer, and detection backlog.

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
