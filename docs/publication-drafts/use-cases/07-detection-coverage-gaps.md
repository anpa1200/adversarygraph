# Review Detection Coverage Gaps: A Practical AdversaryGraph Workflow

**Subtitle:** Which tactics or techniques are under-covered against a report, actor, or sector?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Review Detection Coverage Gaps**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

The team wants to know whether current detection work covers the behaviors that matter for a threat report, actor, or customer sector.

The operational question is: **Which tactics or techniques are under-covered against a report, actor, or sector?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: Detection engineer, SOC lead, threat hunter, or security architect.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Selected TTPs from report, actor, sector, or campaign
- Existing detection coverage or imported layer
- Telemetry inventory
- Detection quality notes

## Before You Start

- Coverage layer is available or can be imported
- Threat layer is reviewed
- Matrix view is working
- Detection owners can act on findings

## Step-By-Step Workflow

### Step 1: Load the threat behavior into Navigator.

This step should produce or protect one concrete part of the analysis: coverage gap list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is a missing technique truly relevant to the environment?

### Step 2: Import or overlay existing coverage where available.

This step should produce or protect one concrete part of the analysis: matrix overlay. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Can the technique be detected directly or only through adjacent behavior?

### Step 3: Compare selected TTPs against covered TTPs.

This step should produce or protect one concrete part of the analysis: prioritized detection candidates. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is coverage high quality or only nominal?

### Step 4: Identify missing tactics and high-value uncovered techniques.

This step should produce or protect one concrete part of the analysis: telemetry requirements. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Which gaps should become backlog items first?

### Step 5: Open TTP details for detection guidance.

This step should produce or protect one concrete part of the analysis: coverage gap list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is a missing technique truly relevant to the environment?

### Step 6: Export the gap summary and prioritize work by risk and telemetry feasibility.

This step should produce or protect one concrete part of the analysis: matrix overlay. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Can the technique be detected directly or only through adjacent behavior?

## Key Analyst Decisions

- Is a missing technique truly relevant to the environment?
- Can the technique be detected directly or only through adjacent behavior?
- Is coverage high quality or only nominal?
- Which gaps should become backlog items first?

## What The Analyst Gets

- Coverage gap list
- Matrix overlay
- Prioritized detection candidates
- Telemetry requirements

## Common Mistakes To Avoid

- Counting coverage without checking detection quality
- Ignoring environment relevance
- Trying to detect every TTP equally
- Overlooking adjacent or chained detections


## Handoff Guidance

Give the SOC a prioritized gap list tied to telemetry and expected attacker behavior, not just a colored matrix.

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
