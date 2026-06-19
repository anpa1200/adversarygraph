# AdvarsaryGraph Usecases.

## Draft

## Usecase number "25"

### Investigation: Validate A Third-Party CTI Report: AdversaryGraph Use Case

**Level:** Complex Platform Workflows  
**Goal:** Validate a vendor or public CTI report before using it operationally.

## Why This Use Case Matters

Validate a vendor or public CTI report before using it operationally. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A vendor report claims a specific actor, several techniques, and a list of IOCs. Before operationalizing it, the internal CTI team must validate the claims.

**Trigger:** The SOC is ready to import IOCs and build detections, but unsupported claims could create noise or wrong priorities.

**Analyst objective:** The analyst needs to separate evidence-backed findings from unsupported assumptions and export only reviewed operational content.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Import the report and extract TTPs.**
2. **Review each TTP against actual procedure evidence.**
3. **Extract all IOCs and remove examples/placeholders.**
4. **Enrich high-priority observables.**
5. **Compare report claims against actor profiles and ATT&CK data.**
6. **Check whether sector/geography claims align with available evidence.**
7. **Mark unsupported claims as needs-evidence.**
8. **Create a reviewed Navigator layer.**
9. **Export a validation note showing accepted, rejected, and uncertain findings.**
10. **Send only reviewed detections/IOCs to SOC workflows.**


## Expected Output

Validated CTI report with reviewed mappings and operationally safe outputs.

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
