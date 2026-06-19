# AdvarsaryGraph Usecases.

## Draft

## Usecase number "5"

### Sync ThreatFox IOCs: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Refresh open-source IOC data for actor and malware context.

## Why This Use Case Matters

Refresh open-source IOC data for actor and malware context. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A SOC shift begins after a night of malware alerts. Analysts want fresh open-source malware IOC context before reviewing suspicious domains and hashes.

**Trigger:** ThreatFox data may have changed since the last sync, and stale IOC context can waste investigation time.

**Analyst objective:** The analyst needs to update the local IOC library and confirm whether new observables link to malware or actor context.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open Reference Sync and run ThreatFox IOC sync.**
2. **Review sync counts and check actor IOC tabs for updated observables.**


## Expected Output

Updated IOC Library records from ThreatFox.

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
