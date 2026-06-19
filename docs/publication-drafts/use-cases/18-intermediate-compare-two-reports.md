# AdvarsaryGraph Usecases.

## Draft

## Usecase number "18"

### Compare Two Reports: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Assess whether two reports describe related activity.

## Why This Use Case Matters

Assess whether two reports describe related activity. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** Two reports from different vendors describe similar tools and infrastructure. The CTI team needs to know whether they represent one campaign or unrelated activity.

**Trigger:** The overlap is not obvious because the reports use different names and levels of detail.

**Analyst objective:** The analyst needs to compare TTPs, IOCs, actor hints, and timing before clustering the reports.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Analyze and store both reports.**
2. **Open report comparison.**
3. **Compare shared and unique TTPs, IOCs, and actor hints.**
4. **Separate generic overlap from distinctive behavior.**
5. **Export the comparison summary.**


## Expected Output

Relationship assessment between reports.

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
