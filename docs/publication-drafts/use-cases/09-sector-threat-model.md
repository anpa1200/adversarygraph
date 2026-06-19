# Build A Sector-Specific Threat Model: A Practical AdversaryGraph Workflow

**Subtitle:** Which actors, TTPs, campaigns, and technologies matter most for this customer?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Build A Sector-Specific Threat Model**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

Before a customer engagement or internal planning cycle, the team needs a threat model grounded in sector relevance and actual ATT&CK behavior.

The operational question is: **Which actors, TTPs, campaigns, and technologies matter most for this customer?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: Security architect, CTI analyst, vCISO, or detection lead.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Sector and business context
- Geography
- Technology stack
- Recent incident concerns
- Relevant actors and TTPs from Sector Intel

## Before You Start

- Sector and technology filters are prepared
- Actor library is synchronized
- Detection or telemetry constraints are known
- The model scope is clear

## Step-By-Step Workflow

### Step 1: Select sector, region, technology, and activity window.

This step should produce or protect one concrete part of the analysis: sector threat model. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which actors are relevant because of sector targeting versus capability?

### Step 2: Review the top actors and their evidence reasons.

This step should produce or protect one concrete part of the analysis: actor priority list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which technologies create exposure?

### Step 3: Open actor pages for descriptions, aliases, campaigns, reports, IOCs, and TTP coverage.

This step should produce or protect one concrete part of the analysis: att&ck matrix overlay. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which threats are strategic versus immediate?

### Step 4: Show relevant TTPs on matrix.

This step should produce or protect one concrete part of the analysis: detection and monitoring priorities. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which assumptions require future validation?

### Step 5: Group TTPs by tactic and detection feasibility.

This step should produce or protect one concrete part of the analysis: sector threat model. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which actors are relevant because of sector targeting versus capability?

### Step 6: Produce a threat model summary with assumptions and confidence.

This step should produce or protect one concrete part of the analysis: actor priority list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which technologies create exposure?

## Key Analyst Decisions

- Which actors are relevant because of sector targeting versus capability?
- Which technologies create exposure?
- Which threats are strategic versus immediate?
- Which assumptions require future validation?

## What The Analyst Gets

- Sector threat model
- Actor priority list
- ATT&CK matrix overlay
- Detection and monitoring priorities

## Common Mistakes To Avoid

- Building a generic sector report with no environment context
- Ignoring recency
- Presenting historical actors as current without evidence
- Skipping assumptions


## Handoff Guidance

Use the threat model as the starting point for detection roadmap, tabletop scenarios, and customer-facing CTI briefings.

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
