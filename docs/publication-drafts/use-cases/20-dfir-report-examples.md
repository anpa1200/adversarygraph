# Analyze DFIR Report Examples: A Practical AdversaryGraph Workflow

**Subtitle:** How can public DFIR reports be used as validation and training examples?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Analyze DFIR Report Examples**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A team wants safe public material to test extraction, compare behavior, create demos, or train analysts without using customer data.

The operational question is: **How can public DFIR reports be used as validation and training examples?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, detection engineer, tool evaluator, trainer, or SOC team lead.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- DFIR example metadata
- Source report URL
- Known TTPs and actors when available
- AI Analysis workflow

## Before You Start

- DFIR examples index is synchronized
- Source report licensing/usage is understood
- Analysts know that metadata is not full report content
- ATT&CK data is loaded

## Step-By-Step Workflow

### Step 1: Open DFIR Examples.

This step should produce or protect one concrete part of the analysis: training case. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the report allowed to be reused for this purpose?

### Step 2: Select a report relevant to the technique, actor, or malware family of interest.

This step should produce or protect one concrete part of the analysis: extraction validation result. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does metadata coverage match the full report?

### Step 3: Review linked TTPs, actors, and source URL.

This step should produce or protect one concrete part of the analysis: expected versus actual mapping notes. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are extracted techniques supported by evidence?

### Step 4: Open the source report if full context is needed.

This step should produce or protect one concrete part of the analysis: demo-ready workflow. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: What should be used for demo, training, or validation?

### Step 5: Run AI analysis on allowed report text or excerpts.

This step should produce or protect one concrete part of the analysis: training case. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the report allowed to be reused for this purpose?

### Step 6: Compare extracted TTPs against expected mappings.

This step should produce or protect one concrete part of the analysis: extraction validation result. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does metadata coverage match the full report?

### Step 7: Use differences to improve prompts, review discipline, or detection logic.

This step should produce or protect one concrete part of the analysis: expected versus actual mapping notes. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Are extracted techniques supported by evidence?

## Key Analyst Decisions

- Is the report allowed to be reused for this purpose?
- Does metadata coverage match the full report?
- Are extracted techniques supported by evidence?
- What should be used for demo, training, or validation?

## What The Analyst Gets

- Training case
- Extraction validation result
- Expected versus actual mapping notes
- Demo-ready workflow

## Common Mistakes To Avoid

- Treating metadata as the full report
- Ignoring source usage restrictions
- Using examples without analyst review
- Overfitting prompts to one report


## Handoff Guidance

Use DFIR examples for demos, analyst training, extraction QA, and detection engineering practice without exposing private reports.

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
