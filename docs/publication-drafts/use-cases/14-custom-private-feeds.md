# Import Custom Private Feeds: A Practical AdversaryGraph Workflow

**Subtitle:** How can internal or customer-specific IOCs be added without losing source separation?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Import Custom Private Feeds**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

The organization has private indicators from cases, honeypots, EDR exports, customer reports, or internal research. These should persist outside the container and remain clearly labeled.

The operational question is: **How can internal or customer-specific IOCs be added without losing source separation?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: SOC platform engineer, CTI analyst, IR team, or customer environment owner.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- JSON, CSV, or TXT feed URL/path
- Feed label
- Indicator type hints if needed
- Optional actor or malware fields

## Before You Start

- External persistent DB/data directory is configured
- Feed format is known
- Sensitive data handling is approved
- Source label naming standard exists

## Step-By-Step Workflow

### Step 1: Open IOC Library or Reference Sync custom feed form.

This step should produce or protect one concrete part of the analysis: private ioc records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the feed public, customer-confidential, or internal-only?

### Step 2: Add feed label and source URL/path.

This step should produce or protect one concrete part of the analysis: source-labeled feed import. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should indicators be mapped to actors or remain unmapped?

### Step 3: Choose JSON, CSV, or TXT format.

This step should produce or protect one concrete part of the analysis: searchable and filterable indicators. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are fields normalized enough for search?

### Step 4: Sync the feed and review imported counts.

This step should produce or protect one concrete part of the analysis: optional enrichment results. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Can these IOCs be sent to VT/OTX enrichment?

### Step 5: Filter by the new source label.

This step should produce or protect one concrete part of the analysis: private ioc records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the feed public, customer-confidential, or internal-only?

### Step 6: Enrich selected indicators if allowed.

This step should produce or protect one concrete part of the analysis: source-labeled feed import. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should indicators be mapped to actors or remain unmapped?

### Step 7: Document retention and sharing restrictions.

This step should produce or protect one concrete part of the analysis: searchable and filterable indicators. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are fields normalized enough for search?

## Key Analyst Decisions

- Is the feed public, customer-confidential, or internal-only?
- Should indicators be mapped to actors or remain unmapped?
- Are fields normalized enough for search?
- Can these IOCs be sent to VT/OTX enrichment?

## What The Analyst Gets

- Private IOC records
- Source-labeled feed import
- Searchable and filterable indicators
- Optional enrichment results

## Common Mistakes To Avoid

- No source label
- Accidentally enriching sensitive IOCs externally
- Losing private data during container rebuild due to wrong volume setup
- Importing malformed CSV without validation


## Handoff Guidance

Use custom feeds for internal hunting and customer-specific context while keeping them separate from public reference intelligence.

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
