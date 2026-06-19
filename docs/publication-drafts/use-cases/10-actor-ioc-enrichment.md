# Enrich Actor Profiles With Current IOCs: A Practical AdversaryGraph Workflow

**Subtitle:** What observables are currently connected to this actor or malware family?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Enrich Actor Profiles With Current IOCs**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

An actor profile is useful, but the team also needs current observables and malware context for hunting and enrichment.

The operational question is: **What observables are currently connected to this actor or malware family?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, SOC analyst, threat hunter, or malware analyst.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Actor profile
- ThreatFox, OTX, Malpedia, custom feed, or report-derived IOCs
- Optional VirusTotal key
- Actor aliases and malware names

## Before You Start

- IOC sync sources are configured
- Actor alias mapping is available
- IOC Library is reachable
- Analyst understands that many IOCs will not map cleanly to actors

## Step-By-Step Workflow

### Step 1: Open the actor page.

This step should produce or protect one concrete part of the analysis: actor-linked ioc list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the IOC directly attributed to the actor or only to a malware family?

### Step 2: Open the IOCs tab and review current mapped indicators.

This step should produce or protect one concrete part of the analysis: csv export. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is it current enough to hunt on?

### Step 3: Run source sync or actor enrichment.

This step should produce or protect one concrete part of the analysis: enrichment notes. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is it high-confidence or noisy infrastructure?

### Step 4: Review source, type, malware family, first seen, last seen, and confidence.

This step should produce or protect one concrete part of the analysis: possible ttp links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should it become a blocklist item, hunt seed, or context-only enrichment?

### Step 5: Open IOC enrichment for high-priority indicators.

This step should produce or protect one concrete part of the analysis: actor-linked ioc list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the IOC directly attributed to the actor or only to a malware family?

### Step 6: Export CSV if the SOC needs watchlist input.

This step should produce or protect one concrete part of the analysis: csv export. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is it current enough to hunt on?

### Step 7: Document unmapped but relevant indicators separately.

This step should produce or protect one concrete part of the analysis: enrichment notes. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is it high-confidence or noisy infrastructure?

## Key Analyst Decisions

- Is the IOC directly attributed to the actor or only to a malware family?
- Is it current enough to hunt on?
- Is it high-confidence or noisy infrastructure?
- Should it become a blocklist item, hunt seed, or context-only enrichment?

## What The Analyst Gets

- Actor-linked IOC list
- CSV export
- Enrichment notes
- Possible TTP links

## Common Mistakes To Avoid

- Treating every malware-family IOC as actor-specific
- Using stale IOCs as blocking rules
- Ignoring source confidence
- Expecting all actors to have current public IOCs


## Handoff Guidance

Give SOC teams current, source-labeled IOCs with clear usage guidance: block, hunt, enrich, or monitor.

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
