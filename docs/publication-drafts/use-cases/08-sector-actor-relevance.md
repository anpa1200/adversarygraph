# Track Actor Relevance By Sector: A Practical AdversaryGraph Workflow

**Subtitle:** Which adversaries are most relevant to a customer sector right now?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Track Actor Relevance By Sector**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A customer asks which threat actors matter to their sector and environment. The answer needs to reflect sector, geography, technology, and recency.

The operational question is: **Which adversaries are most relevant to a customer sector right now?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, customer security advisor, SOC lead, or security manager.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Target sector
- Optional geography or region
- Technology/environment filters such as cloud, Kubernetes, or Microsoft 365
- Activity window such as quarter, year, or two years

## Before You Start

- Sector intelligence data is synchronized
- Actor profiles are available
- Filters are selected carefully
- Score meaning is understood

## Step-By-Step Workflow

### Step 1: Open Sector Intel.

This step should produce or protect one concrete part of the analysis: ranked actor list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is relevance based on direct sector evidence, motivation, geography, or technology overlap?

### Step 2: Select one or more sectors.

This step should produce or protect one concrete part of the analysis: score reasons. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does recent activity matter more than historical capability?

### Step 3: Optionally select regions and technologies/environment values.

This step should produce or protect one concrete part of the analysis: relevant ttp set. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which actors should be monitored versus actively prioritized?

### Step 4: Choose the activity window.

This step should produce or protect one concrete part of the analysis: sector-specific matrix overlay. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which TTPs are actionable for the customer?

### Step 5: Review relevant actor cards and score explanations.

This step should produce or protect one concrete part of the analysis: ranked actor list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is relevance based on direct sector evidence, motivation, geography, or technology overlap?

### Step 6: Open actor info, TTP info, IOC information, or show relevant TTPs on matrix.

This step should produce or protect one concrete part of the analysis: score reasons. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does recent activity matter more than historical capability?

### Step 7: Save findings for a sector brief or detection plan.

This step should produce or protect one concrete part of the analysis: relevant ttp set. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which actors should be monitored versus actively prioritized?

## Key Analyst Decisions

- Is relevance based on direct sector evidence, motivation, geography, or technology overlap?
- Does recent activity matter more than historical capability?
- Which actors should be monitored versus actively prioritized?
- Which TTPs are actionable for the customer?

## What The Analyst Gets

- Ranked actor list
- Score reasons
- Relevant TTP set
- Sector-specific matrix overlay

## Common Mistakes To Avoid

- Assuming every high-score actor is actively targeting the customer
- Ignoring confidence and source quality
- Using broad sector labels without environment context
- Forgetting to update after sync


## Handoff Guidance

Use the ranking to drive a sector threat briefing and a focused detection review for the top actors and TTPs.

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
