# AdvarsaryGraph Usecases.

## Draft

## Usecase number "26"

### Defense: Build MITRE Coverage Baseline: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Create a baseline of current coverage across MITRE ATT&CK.

## Why This Use Case Matters

Create a baseline of current coverage across MITRE ATT&CK. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A security program review asks for a current MITRE ATT&CK coverage baseline. Leadership wants to know which tactics are covered, weak, or missing.

**Trigger:** The organization has many detections, but no clean view of how they map to ATT&CK or actor relevance.

**Analyst objective:** The analyst needs to import coverage, compare it to relevant threats, identify gaps, and create a prioritized roadmap.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Import current detection coverage as Navigator layer or manual TTP set.**
2. **Normalize coverage by domain and tactic.**
3. **Mark detections by maturity where available.**
4. **Compare coverage against top sector actors.**
5. **Identify uncovered high-risk techniques.**
6. **Open TTP detail panels for detection guidance.**
7. **Map gaps to telemetry availability.**
8. **Prioritize backlog by risk, feasibility, and actor relevance.**
9. **Export coverage layer and gap report.**
10. **Schedule periodic review after ATT&CK sync.**


## Expected Output

MITRE coverage baseline with prioritized gaps and detection roadmap.

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
