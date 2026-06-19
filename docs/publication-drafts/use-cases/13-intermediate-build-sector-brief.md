# Build A Sector Threat Brief: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Create a practical threat brief for one sector/customer.

## Why This Use Case Matters

Create a practical threat brief for one sector/customer. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A telecom, finance, or cloud customer asks which actors matter most to them this quarter. A generic threat landscape report is too broad.

**Trigger:** The customer needs a sector-specific briefing connected to technologies they actually use.

**Analyst objective:** The analyst needs to filter actors by sector, region, technology, and recency, then convert the result into a focused threat brief.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open Sector Intel.**
2. **Select sector, region, technologies, and activity window.**
3. **Review actor ranking and evidence reasons.**
4. **Show relevant TTPs on matrix.**
5. **Summarize top actors, TTPs, and detection priorities.**


## Expected Output

Sector-specific actor and ATT&CK priority brief.

## Analyst Review Standard

- Keep source evidence and source labels attached.
- Mark uncertain findings as `needs-evidence` instead of forcing a conclusion.
- Do not treat TTP similarity as attribution by itself.
- Use enrichment as context, not as an automatic decision.
- Export only reviewed findings.

## Where This Fits

This use case can support CTI production, SOC triage, threat hunting, detection engineering, customer reporting, or platform validation depending on the workflow level.

**Project:** https://github.com/anpa1200/adversarygraph  
**Docs:** https://1200km.com/adversarygraph-docs/  
**Use cases:** https://1200km.com/adversarygraph/use-cases.html
