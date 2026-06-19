# Open One Actor Profile: AdversaryGraph Use Case

**Level:** Simple  
**Goal:** Review the core context for one ATT&CK group or actor.

## Why This Use Case Matters

Review the core context for one ATT&CK group or actor. In real CTI and SOC work, the value is not only the result. The value is the repeatable path from input to reviewed output. AdversaryGraph keeps report analysis, ATT&CK mapping, actor context, IOC enrichment, and exportable evidence in one workflow.

## Real-Life Scenario

**Situation:** During a threat briefing, someone asks for immediate context about a named actor mentioned in a customer report. The team needs more than a search-engine summary: aliases, ATT&CK techniques, related reports, IOCs, and operational themes.

**Trigger:** The request happens live in a meeting or shift handoff, where speed and accuracy both matter.

**Analyst objective:** The analyst needs to answer what the actor is known for, which techniques matter, and whether the actor is relevant to the current environment.

**How AdversaryGraph helps:** The platform keeps the workflow connected: source context, ATT&CK mapping, IOC enrichment, actor or sector context, matrix view, and exportable evidence stay in one place instead of being split across notes, browser tabs, and spreadsheets.

## Workflow

1. **Open ATT&CK Group Library and search the actor name, ID, or alias.**
2. **Review description, aliases, techniques, reports, IOCs, and tactic coverage.**


## Expected Output

Actor context ready for a note, briefing, or investigation pivot.

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
