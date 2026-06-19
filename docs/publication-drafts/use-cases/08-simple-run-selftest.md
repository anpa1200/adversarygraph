# Run Deployment Selftest: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Check whether the deployment is healthy before analysis.

## Why This Use Case Matters

Check whether the deployment is healthy before analysis. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** After a Docker pull or configuration change, analysts report that the matrix or enrichment looks empty. The platform owner needs to know whether the problem is API, DB, ATT&CK sync, or missing keys.

**Trigger:** The team is about to start analysis work, so silent failures are unacceptable.

**Analyst objective:** The operator needs a clear health result and a fix path before users trust the platform output.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open the app and run Self-test or call the selftest endpoint.**
2. **Fix any popup errors, then click Recheck until all checks are green.**


## Expected Output

Clear readiness status for API, DB, ATT&CK data, and keys.

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
