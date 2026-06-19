# AdvarsaryGraph Usecases.

## Usecase number "27"

### Defense: Create Sector-Based Detection Roadmap: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Create a detection roadmap for a sector/customer environment.

## Why This Use Case Matters

Create a detection roadmap for a sector/customer environment. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A financial services customer wants a 90-day detection roadmap based on actors and techniques that actually matter to their sector and technology stack.

**Trigger:** The customer cannot implement every possible detection, so the roadmap must be selective and evidence-based.

**Analyst objective:** The analyst needs to combine sector intelligence, actor TTPs, current coverage, and telemetry feasibility into a practical plan.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Select customer sector, region, and technologies in Sector Intel.**
2. **Choose activity window and review ranked actors.**
3. **Show relevant actor TTPs on matrix.**
4. **Merge top relevant TTPs into a planning layer.**
5. **Compare planning layer to existing coverage.**
6. **Prioritize gaps based on sector relevance and telemetry.**
7. **Check Sigma/YARA/rule feed context for available detection ideas.**
8. **Create backlog items grouped by tactic.**
9. **Export roadmap PDF and Navigator layer.**
10. **Review roadmap after source sync or customer environment changes.**


## Expected Output

Sector-driven detection roadmap tied to actor relevance and MITRE coverage.

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
