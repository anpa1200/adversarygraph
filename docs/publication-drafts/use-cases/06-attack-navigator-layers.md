# Create ATT&CK Navigator Layers: A Practical AdversaryGraph Workflow

**Subtitle:** How can selected techniques be visualized, shared, and reused?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Create ATT&CK Navigator Layers**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

An analyst needs to communicate coverage, actor behavior, campaign behavior, or report findings visually using an ATT&CK matrix.

The operational question is: **How can selected techniques be visualized, shared, and reused?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, SOC lead, detection engineer, or security architect.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Selected TTPs from AI analysis, actor profiles, manual selection, or imports
- Domain choice: Enterprise, Mobile, ICS, or ATLAS where available
- Layer naming convention
- Optional scoring or comments

## Before You Start

- ATT&CK data is loaded
- Selected techniques are reviewed
- Export path is available
- Layer purpose is clear

## Step-By-Step Workflow

### Step 1: Open Navigator and select the correct domain.

This step should produce or protect one concrete part of the analysis: navigator-compatible json. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the layer representing observed behavior, expected actor behavior, or detection coverage?

### Step 2: Add techniques manually, import coverage, inject accepted AI results, or load actor TTPs.

This step should produce or protect one concrete part of the analysis: interactive matrix layer. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should low-confidence techniques be excluded or colored differently?

### Step 3: Use My TTPs only to show selected behavior, not every possible related technique.

This step should produce or protect one concrete part of the analysis: named layer in workspace. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which domain should be used?

### Step 4: Review tactic distribution and technique labels.

This step should produce or protect one concrete part of the analysis: visual evidence for reports or briefings. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should this become a reusable named layer?

### Step 5: Export Navigator JSON or keep the layer in the layer library.

This step should produce or protect one concrete part of the analysis: navigator-compatible json. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the layer representing observed behavior, expected actor behavior, or detection coverage?

### Step 6: Share the layer with a short explanation of scope and confidence.

This step should produce or protect one concrete part of the analysis: interactive matrix layer. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should low-confidence techniques be excluded or colored differently?

## Key Analyst Decisions

- Is the layer representing observed behavior, expected actor behavior, or detection coverage?
- Should low-confidence techniques be excluded or colored differently?
- Which domain should be used?
- Should this become a reusable named layer?

## What The Analyst Gets

- Navigator-compatible JSON
- Interactive matrix layer
- Named layer in workspace
- Visual evidence for reports or briefings

## Common Mistakes To Avoid

- Mixing observed and hypothetical TTPs without labeling
- Using one layer for too many purposes
- Exporting unreviewed model output
- Forgetting domain differences


## Handoff Guidance

Attach the Navigator layer to reports, backlog tickets, and briefings with a short note explaining what the layer represents.

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
