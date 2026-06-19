# AdvarsaryGraph Usecases.

## Draft

## Usecase number "12"

### Compare Incident TTPs To Actors: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Use TTP overlap to generate actor hypotheses.

## Why This Use Case Matters

Use TTP overlap to generate actor hypotheses. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** An IR team observes credential theft, remote execution, discovery, and exfiltration behavior. Leadership asks whether this resembles a known actor.

**Trigger:** The team has incident TTPs but not enough evidence for attribution.

**Analyst objective:** The analyst needs to generate actor hypotheses from TTP overlap while clearly separating similarity from attribution.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Load accepted incident TTPs into My TTPs.**
2. **Open Compare against groups.**
3. **Review shared techniques and Jaccard overlap.**
4. **Open top actor pages and check sector, timeline, aliases, reports, and IOCs.**
5. **Document hypotheses and caveats.**


## Expected Output

Ranked actor hypotheses without overclaiming attribution.

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
