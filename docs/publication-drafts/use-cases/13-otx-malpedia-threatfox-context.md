# Pull Intelligence From OTX, Malpedia, And ThreatFox: A Practical AdversaryGraph Workflow

**Subtitle:** How can open intelligence enrich actors and observables beyond a single feed?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Pull Intelligence From OTX, Malpedia, And ThreatFox**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

Public IOC sources are incomplete when used alone. Combining OTX pulses, Malpedia malware knowledge, and ThreatFox observables gives broader context.

The operational question is: **How can open intelligence enrich actors and observables beyond a single feed?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, malware analyst, enrichment pipeline owner, or SOC platform operator.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- OTX API key
- ThreatFox auth key if required by deployment
- Malpedia source data
- Actor aliases and malware names
- IOC records

## Before You Start

- API keys are loaded into the API container environment
- Reference Sync is reachable
- Source usage terms are understood
- Actor alias matching is enabled where possible

## Step-By-Step Workflow

### Step 1: Open Reference Sync or actor enrichment.

This step should produce or protect one concrete part of the analysis: source-labeled ioc records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which source is authoritative for this field?

### Step 2: Run the selected source sync.

This step should produce or protect one concrete part of the analysis: malware family context. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the data current enough to use operationally?

### Step 3: Review success counts, updated records, and actor links.

This step should produce or protect one concrete part of the analysis: actor evidence notes. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Did alias matching create false positives?

### Step 4: Open enriched actor or IOC records.

This step should produce or protect one concrete part of the analysis: updated enrichment timestamps. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should enrichment update actor relevance, IOC status, or TTP mapping?

### Step 5: Check whether source labels and timestamps make sense.

This step should produce or protect one concrete part of the analysis: source-labeled ioc records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which source is authoritative for this field?

### Step 6: Use enrichment as supporting context, not final attribution.

This step should produce or protect one concrete part of the analysis: malware family context. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the data current enough to use operationally?

## Key Analyst Decisions

- Which source is authoritative for this field?
- Is the data current enough to use operationally?
- Did alias matching create false positives?
- Should enrichment update actor relevance, IOC status, or TTP mapping?

## What The Analyst Gets

- Source-labeled IOC records
- Malware family context
- Actor evidence notes
- Updated enrichment timestamps

## Common Mistakes To Avoid

- Expecting all IOCs to map to actors
- Over-trusting alias matches
- Ignoring source licensing and API limits
- Mixing low-confidence enrichment into reports


## Handoff Guidance

Use combined enrichment to improve actor pages, IOC Library records, and investigation pivots while preserving source labels.

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
