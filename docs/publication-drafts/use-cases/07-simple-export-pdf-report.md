# AdvarsaryGraph Usecases.

## Usecase number "7"

### Export A PDF Report: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Create a shareable analyst report from reviewed findings.

## Why This Use Case Matters

Create a shareable analyst report from reviewed findings. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** An analyst has reviewed a set of extracted TTPs and needs to brief a SOC lead before the end of the day. Screenshots and raw JSON are not enough.

**Trigger:** The team needs a portable artifact that includes reviewed findings and can be shared internally.

**Analyst objective:** The analyst needs to export only reviewed content and make sure the PDF reflects evidence, not raw model output.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open a reviewed analysis or report view.**
2. **Click PDF export and verify the included TTPs, evidence, and notes.**


## Expected Output

PDF report for handoff or briefing.

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
