# AdvarsaryGraph Usecases.

## Draft

## Usecase number "6"

### Import A Navigator Layer: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Load an existing ATT&CK layer for review or comparison.

## Why This Use Case Matters

Load an existing ATT&CK layer for review or comparison. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A partner team sends an ATT&CK Navigator layer from a previous assessment. The local team wants to compare it against current actor behavior and internal coverage.

**Trigger:** The layer arrives as JSON and needs to become part of the local workspace without manual recreation.

**Analyst objective:** The analyst needs to import the layer, verify the selected TTPs, and decide whether to merge it into My TTPs or keep it separate.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open Navigator and click Import layer.**
2. **Review the imported TTPs and save or merge them into My TTPs.**


## Expected Output

Imported matrix layer available for analysis.

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
