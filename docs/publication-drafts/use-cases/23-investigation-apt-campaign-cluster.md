# AdvarsaryGraph Usecases.

## Usecase number "23"

### Investigation: Cluster Multiple APT Reports: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Assess whether several reports belong to one campaign cluster.

## Why This Use Case Matters

Assess whether several reports belong to one campaign cluster. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** Three public reports describe similar targeting, malware names, and infrastructure but use different campaign labels. The CTI team needs to decide whether to cluster them.

**Trigger:** A customer asks whether the reports indicate one sustained campaign against their sector.

**Analyst objective:** The analyst needs to analyze each report, compare TTPs and IOCs, review actor fit, and write a defensible relationship assessment.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Create a campaign workspace.**
2. **Analyze each report separately and store results.**
3. **Normalize report metadata, dates, sectors, and source labels.**
4. **Compare reports for shared and unique TTPs.**
5. **Compare IOCs across reports and enrich shared observables.**
6. **Compare combined TTPs against known actors and campaigns.**
7. **Separate generic TTP overlap from distinctive procedures.**
8. **Open actor profiles for likely matches and review timeline/sector fit.**
9. **Create one combined Navigator layer and one layer per report.**
10. **Write a cluster assessment: related, possibly related, or unrelated.**
11. **Export campaign evidence and matrix layers.**


## Expected Output

Campaign clustering assessment with report-to-report and actor comparison evidence.

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
