# AdvarsaryGraph Usecases.

## Usecase number "11"

### Map A Report To ATT&CK: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Turn one report into reviewed ATT&CK techniques.

## Why This Use Case Matters

Turn one report into reviewed ATT&CK techniques. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A vendor publishes a detailed intrusion report with long narrative text, screenshots, and behavior descriptions. The SOC wants detections, but the report is not yet mapped into reviewed ATT&CK techniques.

**Trigger:** The report is relevant to the organization sector and cannot wait for a long manual mapping cycle.

**Analyst objective:** The analyst needs to extract candidate TTPs, validate evidence, reject weak mappings, and create a matrix layer for detection review.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Load PDF/DOCX/TXT or paste text into AI Analysis.**
2. **Choose provider/domain and run extraction.**
3. **Review evidence for every TTP and set review status.**
4. **Inject accepted TTPs into Navigator.**
5. **Export JSON, layer, or PDF.**


## Expected Output

Reviewed TTP set with evidence and exportable layer/report.

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
