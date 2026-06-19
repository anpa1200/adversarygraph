# AdvarsaryGraph Usecases.

## Draft

## Usecase number "19"

### Review One Coverage Gap: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Compare a threat layer to existing coverage.

## Why This Use Case Matters

Compare a threat layer to existing coverage. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A SOC lead has a current coverage layer and a new threat layer. The question is not whether coverage exists, but where the important gaps are.

**Trigger:** Detection engineering capacity is limited, so prioritization matters.

**Analyst objective:** The analyst needs to compare relevant TTPs to coverage and decide which missing techniques deserve backlog work.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Load threat TTPs into Navigator.**
2. **Import or load current coverage layer.**
3. **Identify uncovered high-priority tactics/techniques.**
4. **Open TTP detail panels for detection guidance.**
5. **Create backlog items for feasible detections.**


## Expected Output

Focused coverage-gap list for engineering.

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
