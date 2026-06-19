# AdvarsaryGraph Usecases.

## Draft

## Usecase number "1"

### Check One IOC: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Check whether one IP, domain, URL, or hash has useful enrichment context.

## Why This Use Case Matters

Check whether one IP, domain, URL, or hash has useful enrichment context. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** Morning SOC triage starts with an EDR alert that contains a suspicious domain contacted by one endpoint. The analyst does not yet know if it is active malware infrastructure, a parked domain, an internal false positive, or an old indicator copied from another alert.

**Trigger:** The queue is growing and the analyst has only a few minutes before deciding whether to escalate, enrich, hunt, or close the alert.

**Analyst objective:** The analyst needs to decide whether the IOC is malicious enough to pivot on, whether it has actor or malware context, and whether it should become a hunting seed rather than an immediate block.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open VirusTotal Lookup or IOC Library Enrichment.**
2. **Submit the indicator and review reputation, tags, relationships, and possible actor/TTP links.**


## Expected Output

Quick IOC context for triage or hunting seed.

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
