# Compare An Incident To Known APT Groups: A Practical AdversaryGraph Workflow

**Subtitle:** Which known groups have the strongest behavior overlap with this incident?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Compare An Incident To Known APT Groups**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

An incident has a set of observed techniques. The analyst needs to know whether the behavior resembles known actors, while avoiding unsupported attribution.

The operational question is: **Which known groups have the strongest behavior overlap with this incident?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, IR analyst, threat hunter, or senior SOC analyst.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Incident TTPs from AI extraction or manual selection
- ATT&CK group profiles
- Known campaign data
- Optional IOCs and malware names

## Before You Start

- ATT&CK group library is synchronized
- Incident TTPs are reviewed
- Common/generic TTPs are treated carefully
- Analyst understands Jaccard similarity limitations

## Step-By-Step Workflow

### Step 1: Load reviewed incident TTPs into My TTPs.

This step should produce or protect one concrete part of the analysis: ranked actor hypothesis list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does overlap rely on unique procedures or generic tradecraft?

### Step 2: Open Compare against groups.

This step should produce or protect one concrete part of the analysis: shared ttp table. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are there actor-specific tools, malware, sectors, or regions that support the hypothesis?

### Step 3: Review ranked results by overlap score and shared technique count.

This step should produce or protect one concrete part of the analysis: actor profile links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are there contradictions in target geography, timeline, or intrusion chain?

### Step 4: Open top actor pages and inspect aliases, description, campaigns, CTI/IR reports, and IOCs.

This step should produce or protect one concrete part of the analysis: supporting/contradicting evidence notes. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should the result influence detection priority without making attribution?

### Step 5: Separate high-signal techniques from generic techniques such as PowerShell or Scheduled Task.

This step should produce or protect one concrete part of the analysis: ranked actor hypothesis list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does overlap rely on unique procedures or generic tradecraft?

### Step 6: Document actor matches as hypotheses with supporting and contradicting evidence.

This step should produce or protect one concrete part of the analysis: shared ttp table. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are there actor-specific tools, malware, sectors, or regions that support the hypothesis?

### Step 7: Export or screenshot the comparison for the investigation record.

This step should produce or protect one concrete part of the analysis: actor profile links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are there contradictions in target geography, timeline, or intrusion chain?

## Key Analyst Decisions

- Does overlap rely on unique procedures or generic tradecraft?
- Are there actor-specific tools, malware, sectors, or regions that support the hypothesis?
- Are there contradictions in target geography, timeline, or intrusion chain?
- Should the result influence detection priority without making attribution?

## What The Analyst Gets

- Ranked actor hypothesis list
- Shared TTP table
- Actor profile links
- Supporting/contradicting evidence notes

## Common Mistakes To Avoid

- Treating overlap as proof of attribution
- Ignoring common techniques that inflate similarity
- Skipping timeline or sector checks
- Failing to document why a top match was rejected


## Handoff Guidance

Give IR and management a hypothesis list with confidence and caveats. Use the overlap to focus investigation and detection, not to claim final attribution.

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
