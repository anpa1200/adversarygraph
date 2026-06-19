# Connect MISP JSON Exports: A Practical AdversaryGraph Workflow

**Subtitle:** How can MISP event or attribute exports become searchable IOC records?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Connect MISP JSON Exports**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A team already uses MISP and wants selected events or attributes to become searchable and enrichable inside AdversaryGraph.

The operational question is: **How can MISP event or attribute exports become searchable IOC records?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: MISP operator, CTI analyst, SOC platform engineer, or threat hunter.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- MISP event or attribute JSON export URL
- Local gateway URL if MISP is not directly reachable
- Source label
- Optional event tags and galaxy context

## Before You Start

- MISP export is accessible to the API container
- Authentication is handled by gateway or export URL
- Source labeling is clear
- Private data sharing rules are understood

## Step-By-Step Workflow

### Step 1: Open IOC Library source connection panel.

This step should produce or protect one concrete part of the analysis: misp-backed ioc records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is this an event-level export or attribute-level export?

### Step 2: Paste the MISP JSON export URL or gateway URL.

This step should produce or protect one concrete part of the analysis: searchable source filter. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which MISP tags should influence actor or malware mapping?

### Step 3: Connect the source and review imported counts.

This step should produce or protect one concrete part of the analysis: optional enrichment and actor links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Can indicators be enriched externally?

### Step 4: Filter IOC Library by the MISP source.

This step should produce or protect one concrete part of the analysis: csv/stix export path. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should MISP remain source-of-truth or be copied for local analysis?

### Step 5: Review event/attribute fields and descriptions.

This step should produce or protect one concrete part of the analysis: misp-backed ioc records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is this an event-level export or attribute-level export?

### Step 6: Enrich selected indicators only when permitted.

This step should produce or protect one concrete part of the analysis: searchable source filter. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which MISP tags should influence actor or malware mapping?

### Step 7: Export or use MISP-backed indicators for hunting.

This step should produce or protect one concrete part of the analysis: optional enrichment and actor links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Can indicators be enriched externally?

## Key Analyst Decisions

- Is this an event-level export or attribute-level export?
- Which MISP tags should influence actor or malware mapping?
- Can indicators be enriched externally?
- Should MISP remain source-of-truth or be copied for local analysis?

## What The Analyst Gets

- MISP-backed IOC records
- Searchable source filter
- Optional enrichment and actor links
- CSV/STIX export path

## Common Mistakes To Avoid

- Leaking sensitive MISP data to external enrichment
- Using stale event exports
- Losing MISP tags during normalization
- Assuming every MISP attribute is high-confidence


## Handoff Guidance

Use the MISP import to connect existing CTI operations with AdversaryGraph analysis and enrichment workflows.

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
