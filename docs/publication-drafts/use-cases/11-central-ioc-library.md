# Maintain A Central IOC Library: A Practical AdversaryGraph Workflow

**Subtitle:** How can all collected observables be searched, filtered, enriched, and exported?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Maintain A Central IOC Library**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

Indicators arrive from reports, feeds, MISP, TAXII, ThreatFox, OTX, and manual uploads. They need one searchable place with source and enrichment context.

The operational question is: **How can all collected observables be searched, filtered, enriched, and exported?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: SOC analyst, CTI analyst, threat hunter, or platform operator.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Public feed IOCs
- Private/customer IOCs
- Report-derived observables
- MISP/STIX/TAXII imports
- Actor mappings where available

## Before You Start

- External persistent DB is configured
- Feed sync has run
- Search and filters are working
- API keys are configured for enrichment

## Step-By-Step Workflow

### Step 1: Open IOC Library.

This step should produce or protect one concrete part of the analysis: Searchable IOC Library. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which sources are authoritative?

### Step 2: Search by indicator, description, malware, campaign, or source.

This step should produce or protect one concrete part of the analysis: filtered ioc sets. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which IOCs are current enough for hunting?

### Step 3: Filter by type, source, and one or more actor groups.

This step should produce or protect one concrete part of the analysis: enrichment results. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should private feeds stay separate from public references?

### Step 4: Sort by last seen to prioritize current indicators.

This step should produce or protect one concrete part of the analysis: exportable lists. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which indicators need enrichment before action?

### Step 5: Open enrichment for selected IOCs.

This step should produce or protect one concrete part of the analysis: Searchable IOC Library. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which sources are authoritative?

### Step 6: Export or sync relevant subsets for downstream use.

This step should produce or protect one concrete part of the analysis: filtered ioc sets. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which IOCs are current enough for hunting?

### Step 7: Delete or separate private data when retention requires it.

This step should produce or protect one concrete part of the analysis: enrichment results. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should private feeds stay separate from public references?

## Key Analyst Decisions

- Which sources are authoritative?
- Which IOCs are current enough for hunting?
- Should private feeds stay separate from public references?
- Which indicators need enrichment before action?

## What The Analyst Gets

- Searchable IOC library
- Filtered IOC sets
- Enrichment results
- Exportable lists

## Common Mistakes To Avoid

- Mixing private and public data without labels
- No retention policy
- Acting on stale indicators
- No source quality review


## Handoff Guidance

Use the library as a pivot point for SOC enrichment, hunting seeds, and CTI reporting rather than a blind blocklist.

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
