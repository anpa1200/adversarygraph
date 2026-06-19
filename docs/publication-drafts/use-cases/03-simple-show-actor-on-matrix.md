# AdvarsaryGraph Usecases.

## Usecase number "3"

### Show Actor TTPs On The Matrix: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Visualize one actor's known ATT&CK behavior.

## Why This Use Case Matters

Visualize one actor's known ATT&CK behavior. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A detection lead wants to explain actor behavior visually before assigning engineering work. A text list of techniques is hard for management and SOC analysts to understand.

**Trigger:** The team is about to start a coverage review or tabletop exercise for a specific actor.

**Analyst objective:** The analyst needs to show the actor behavior across tactics and decide which areas deserve deeper review.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open the actor profile and click the matrix or Navigator action.**
2. **Review selected TTPs by tactic and export the layer if needed.**


## Expected Output

Actor behavior map in Navigator.

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
