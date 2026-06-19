# Build A Client-Facing CTI Briefing: A Practical AdversaryGraph Workflow

**Subtitle:** How can a raw report become a structured, evidence-backed customer briefing?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Build A Client-Facing CTI Briefing**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A customer asks what a report means for their environment. They need a concise briefing with behaviors, relevant actors, IOCs, detection priorities, and uncertainty clearly separated.

The operational question is: **How can a raw report become a structured, evidence-backed customer briefing?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI consultant, customer-facing analyst, SOC manager, or security architect.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Source report or incident narrative
- Customer sector and technology context
- Known customer telemetry or detection stack
- Optional IOC list from the incident or report

## Before You Start

- Customer data handling rules are clear
- Sector/technology filters are available when relevant
- PDF export is working
- Enrichment keys are configured if IOC context is needed

## Step-By-Step Workflow

### Step 1: Analyze the report and review TTP mappings.

This step should produce or protect one concrete part of the analysis: customer briefing pdf. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which findings are directly evidenced by the report?

### Step 2: Filter or compare relevant actors using sector, region, technology, and TTP overlap.

This step should produce or protect one concrete part of the analysis: att&ck layer. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which findings are contextual enrichment only?

### Step 3: Open actor profiles for context but avoid making attribution claims without corroboration.

This step should produce or protect one concrete part of the analysis: actor hypothesis section. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: What matters for this customer sector and environment?

### Step 4: Extract or import IOCs and enrich them where useful.

This step should produce or protect one concrete part of the analysis: ioc appendix. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which detections are realistic with the customer telemetry?

### Step 5: Convert accepted TTPs into detection priorities based on customer telemetry.

This step should produce or protect one concrete part of the analysis: detection priority list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which findings are directly evidenced by the report?

### Step 6: Summarize what is known, what is likely, and what remains uncertain.

This step should produce or protect one concrete part of the analysis: customer briefing pdf. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which findings are contextual enrichment only?

### Step 7: Export a PDF briefing and attach Navigator layers for technical readers.

This step should produce or protect one concrete part of the analysis: att&ck layer. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: What matters for this customer sector and environment?

## Key Analyst Decisions

- Which findings are directly evidenced by the report?
- Which findings are contextual enrichment only?
- What matters for this customer sector and environment?
- Which detections are realistic with the customer telemetry?

## What The Analyst Gets

- Customer briefing PDF
- ATT&CK layer
- Actor hypothesis section
- IOC appendix
- Detection priority list

## Common Mistakes To Avoid

- Overstating attribution from similarity alone
- Including low-confidence enrichment as fact
- Delivering too many generic TTPs without prioritization
- Not separating customer-specific relevance from general threat context


## Handoff Guidance

Deliver the PDF and Navigator layer with clear confidence language. Give the SOC a shorter action list: top TTPs, top IOCs, and recommended hunts.

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
