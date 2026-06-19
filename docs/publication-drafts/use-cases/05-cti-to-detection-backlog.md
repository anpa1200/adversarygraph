# Turn CTI Into A Detection Backlog: A Practical AdversaryGraph Workflow

**Subtitle:** Which intelligence findings should become detection engineering work?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Turn CTI Into A Detection Backlog**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A report contains many behaviors, but only some are useful and feasible for detection. The team needs to turn CTI into prioritized backlog items.

The operational question is: **Which intelligence findings should become detection engineering work?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: Detection engineer, CTI analyst, SOC lead, or purple team operator.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Reviewed TTP list
- Evidence snippets
- Customer or organization telemetry inventory
- Existing detection coverage if known

## Before You Start

- TTPs have review status
- Detection engineers know available log sources
- Navigator layer is prepared
- False-positive constraints are understood

## Step-By-Step Workflow

### Step 1: Start with accepted TTPs and exclude rejected mappings.

This step should produce or protect one concrete part of the analysis: detection backlog. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the technique observable in available telemetry?

### Step 2: Group techniques by tactic and operational phase.

This step should produce or protect one concrete part of the analysis: prioritized ttp list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is detection better as a rule, hunt, dashboard, or enrichment?

### Step 3: Open TTP detail panels and review detection guidance.

This step should produce or protect one concrete part of the analysis: telemetry requirements. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does the report provide enough procedure detail?

### Step 4: Mark which techniques have available telemetry.

This step should produce or protect one concrete part of the analysis: evidence-backed ticket content. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: What is the expected false-positive rate?

### Step 5: Prioritize high-impact, high-confidence, low-coverage techniques.

This step should produce or protect one concrete part of the analysis: detection backlog. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the technique observable in available telemetry?

### Step 6: Export a detection backlog with evidence and source report references.

This step should produce or protect one concrete part of the analysis: prioritized ttp list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is detection better as a rule, hunt, dashboard, or enrichment?

### Step 7: Create tickets or tasks for Sigma, SIEM, EDR, or hunting content.

This step should produce or protect one concrete part of the analysis: telemetry requirements. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does the report provide enough procedure detail?

## Key Analyst Decisions

- Is the technique observable in available telemetry?
- Is detection better as a rule, hunt, dashboard, or enrichment?
- Does the report provide enough procedure detail?
- What is the expected false-positive rate?

## What The Analyst Gets

- Detection backlog
- Prioritized TTP list
- Telemetry requirements
- Evidence-backed ticket content

## Common Mistakes To Avoid

- Creating detections for techniques without telemetry
- Prioritizing noisy generic techniques over distinctive behavior
- Losing source evidence during handoff
- Treating all TTPs as equal priority


## Handoff Guidance

Give engineering a concise backlog item per technique: behavior, evidence, log source, proposed logic, expected signal, and validation plan.

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
