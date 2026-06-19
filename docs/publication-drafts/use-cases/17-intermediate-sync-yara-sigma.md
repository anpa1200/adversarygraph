# Sync YARA And Sigma Feeds: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Connect detection-rule context to IOCs and malware.

## Why This Use Case Matters

Connect detection-rule context to IOCs and malware. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A suspicious malware family appears in an incident. Detection engineers ask whether any existing YARA or Sigma content can help.

**Trigger:** The team wants to avoid writing detection content from scratch if reusable rules already exist.

**Analyst objective:** The analyst needs to connect malware, IOC, and rule-feed context, then pass useful rule references to engineering.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Add YARA/Sigma feed sources.**
2. **Run rule-feed sync.**
3. **Open IOC or malware enrichment.**
4. **Review matching rule names, tags, and references.**
5. **Use rule context as detection research input.**


## Expected Output

Detection content leads tied to IOC/malware context.

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
