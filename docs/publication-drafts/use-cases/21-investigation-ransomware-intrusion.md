# Investigation: Ransomware Intrusion Triage: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Investigate a ransomware report from intake to actor hypothesis and detection handoff.

## Why This Use Case Matters

Investigate a ransomware report from intake to actor hypothesis and detection handoff. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A company discovers encrypted servers, suspicious PowerShell, lateral movement indicators, and possible data theft. The incident response team needs CTI support immediately.

**Trigger:** The first report contains scattered details: commands, hashes, domains, affected systems, and a ransom note. The team needs structure fast.

**Analyst objective:** The analyst needs to create a full investigation package: reviewed TTPs, enriched IOCs, actor hypotheses, matrix layer, and detection backlog.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Run selftest and confirm enrichment keys are available.**
2. **Create an investigation workspace in Operations/Pipeline.**
3. **Upload the ransom incident report and extract TTPs.**
4. **Review every TTP and mark weak mappings as needs-evidence.**
5. **Extract IOCs from the report and store them in IOC Library.**
6. **Enrich hashes/domains/IPs with VT, OTX, ThreatFox, and sandbox feeds.**
7. **Compare accepted TTPs against actors and campaigns.**
8. **Open top actor profiles and review IOCs, reports, aliases, and sector relevance.**
9. **Show accepted TTPs on Navigator and export a layer.**
10. **Create detection backlog items for initial access, execution, lateral movement, and impact.**
11. **Export a PDF investigation summary with evidence, hypotheses, and next actions.**


## Expected Output

Investigation package with TTPs, IOCs, actor hypotheses, Navigator layer, and detection backlog.

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
