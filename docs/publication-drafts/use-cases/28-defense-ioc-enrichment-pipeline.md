# Defense: Build IOC Enrichment Pipeline: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Create a repeatable SOC enrichment pipeline for incoming IOCs.

## Why This Use Case Matters

Create a repeatable SOC enrichment pipeline for incoming IOCs. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A SOC receives IOCs from feeds, partners, MISP, incident reports, and internal cases every day. Analysts waste time checking them manually.

**Trigger:** The organization needs a repeatable enrichment pipeline with source labels, recency, and exportable reviewed results.

**Analyst objective:** The platform owner needs to connect feeds, normalize records, enrich selected IOCs, and define how each IOC should be used.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Configure ThreatFox, OTX, VT, Malpedia, MISP, TAXII/STIX, and custom feeds as allowed.**
2. **Run Reference Sync and confirm IOC counts.**
3. **Define source labels and retention rules.**
4. **Import private/customer feeds into the external DB.**
5. **Use IOC Library filters for type, source, actor, and recency.**
6. **Enrich selected IOCs with VT and related sources.**
7. **Map IOCs to malware, actors, and TTPs when evidence supports it.**
8. **Export reviewed IOC sets as CSV/STIX.**
9. **Document which IOCs are block, hunt, monitor, or context-only.**
10. **Schedule daily sync and periodic quality review.**


## Expected Output

Central IOC enrichment workflow with source labels, pivots, and export paths.

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
