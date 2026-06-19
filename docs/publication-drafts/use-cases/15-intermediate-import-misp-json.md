# AdvarsaryGraph Usecases.

## Usecase number "15"

### Import MISP JSON: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Bring MISP event or attribute exports into IOC Library.

## Why This Use Case Matters

Bring MISP event or attribute exports into IOC Library. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** The organization already curates events in MISP, but analysts still copy indicators manually into separate tools for enrichment.

**Trigger:** A MISP event is relevant to an active investigation and needs to be searchable in AdversaryGraph.

**Analyst objective:** The analyst needs to import the MISP JSON, preserve source labels, and enrich only approved indicators.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Create or expose a MISP JSON export URL.**
2. **Open IOC Library source panel and connect the MISP source.**
3. **Sync and filter by the MISP source label.**
4. **Review imported observables and tags.**
5. **Enrich or export only approved data.**


## Expected Output

MISP-backed IOC records searchable in AdversaryGraph.

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
