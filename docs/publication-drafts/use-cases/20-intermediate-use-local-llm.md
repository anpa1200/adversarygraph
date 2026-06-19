# AdvarsaryGraph Usecases.

## Draft

## Usecase number "20"

### Use A Local LLM For Private Reports: AdversaryGraph Use Case

**Level:** Intermediate  
**Goal:** Analyze sensitive content without public LLM routing.

## Why This Use Case Matters

Analyze sensitive content without public LLM routing. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** A customer incident report contains internal hostnames, usernames, and operational details. The analyst cannot send it to a public LLM provider.

**Trigger:** The team still wants AI-assisted extraction but must keep processing inside controlled infrastructure.

**Analyst objective:** The analyst needs to route analysis through a local/private model and validate output the same way as any other extraction.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Configure local/private LLM gateway in deployment env.**
2. **Run selftest and confirm provider is reachable.**
3. **Choose local provider in AI Analysis.**
4. **Analyze the report and review mappings.**
5. **Export only reviewed findings.**


## Expected Output

Private report extraction with controlled model routing.

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
