# Compare Two Or More Threat Reports: A Practical AdversaryGraph Workflow

**Subtitle:** Are multiple reports describing related activity, or do they only share common tradecraft?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Compare Two Or More Threat Reports**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

Several reports mention similar malware, infrastructure, or behaviors. The analyst needs to determine whether they should be grouped together as a campaign or handled separately.

The operational question is: **Are multiple reports describing related activity, or do they only share common tradecraft?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, campaign tracker, IR lead, or research analyst.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Two or more analyzed reports
- Reviewed TTP mappings
- Report-derived IOCs
- Actor or malware names if available

## Before You Start

- Previous analyses are stored
- Report metadata is clear
- Each report has reviewed mappings
- The analyst can distinguish generic overlap from campaign-specific evidence

## Step-By-Step Workflow

### Step 1: Analyze each report separately and store results.

This step should produce or protect one concrete part of the analysis: report overlap summary. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are shared techniques distinctive enough?

### Step 2: Open stored report comparison.

This step should produce or protect one concrete part of the analysis: shared/unique ttp lists. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Do reports share infrastructure, malware, target sector, or timing?

### Step 3: Compare shared TTPs, unique TTPs, tactics, IOCs, and actor references.

This step should produce or protect one concrete part of the analysis: ioc comparison. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are differences caused by incomplete reporting or truly different behavior?

### Step 4: Review whether overlap occurs at early, middle, or late intrusion phases.

This step should produce or protect one concrete part of the analysis: campaign relationship assessment. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should reports be merged into one campaign workspace?

### Step 5: Check if shared observables are current, reused, or generic.

This step should produce or protect one concrete part of the analysis: report overlap summary. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are shared techniques distinctive enough?

### Step 6: Write a conclusion: related, possibly related, or unrelated/common tradecraft.

This step should produce or protect one concrete part of the analysis: shared/unique ttp lists. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Do reports share infrastructure, malware, target sector, or timing?

### Step 7: Export the comparison for case notes or briefing.

This step should produce or protect one concrete part of the analysis: ioc comparison. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are differences caused by incomplete reporting or truly different behavior?

## Key Analyst Decisions

- Are shared techniques distinctive enough?
- Do reports share infrastructure, malware, target sector, or timing?
- Are differences caused by incomplete reporting or truly different behavior?
- Should reports be merged into one campaign workspace?

## What The Analyst Gets

- Report overlap summary
- Shared/unique TTP lists
- IOC comparison
- Campaign relationship assessment

## Common Mistakes To Avoid

- Merging unrelated reports based on common techniques
- Ignoring reporting bias
- Comparing raw unreviewed mappings
- Overlooking time-window differences


## Handoff Guidance

Use the comparison to decide campaign grouping, detection reuse, and whether one report should update findings from another.

A good handoff should make the reasoning visible. It should separate observed behavior, model-assisted extraction, enrichment from external sources, and analyst hypotheses. This is especially important when the output will be used by a SOC team, a customer, or a detection engineering backlog.

## Review Discipline

AdversaryGraph should accelerate analysis, not bypass it. TTP overlap, actor matches, IOC enrichment, rule matches, and sandbox behavior are signals. They become useful only after source review, confidence calibration, and analyst judgment.

Before publishing or handing off the result:

- Confirm that every accepted finding has evidence.
- Keep weak or partial findings as `needs-evidence`.
- Do not turn similarity into attribution without corroboration.
- Keep source labels attached to IOCs and enrichment.
- Export reviewed results, not raw model output.

## Practical Output

A finished workflow can produce Navigator layers, PDF reports, JSON exports, CSV IOC lists, STIX bundles, actor notes, detection backlog items, and investigation evidence. The exact output depends on the use case, but the principle stays the same: every result should be traceable to evidence.

## Closing

The value of this workflow is repeatability. Instead of treating every report, alert, actor, or IOC as a one-off task, AdversaryGraph gives the analyst a consistent path from raw input to reviewed operational intelligence.

**Project:** https://github.com/anpa1200/adversarygraph  
**Docs:** https://1200km.com/adversarygraph-docs/  
**Use cases:** https://1200km.com/adversarygraph/use-cases.html
