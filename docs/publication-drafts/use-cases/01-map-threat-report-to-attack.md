# Map A New Threat Report To MITRE ATT&CK: A Practical AdversaryGraph Workflow

**Subtitle:** Which ATT&CK techniques are actually described in this report, and what evidence supports each mapping?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Map A New Threat Report To MITRE ATT&CK**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A new vendor report, incident writeup, customer PDF, red-team debrief, or DFIR article arrives and needs to become a structured ATT&CK layer instead of remaining free text.

The operational question is: **Which ATT&CK techniques are actually described in this report, and what evidence supports each mapping?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, detection engineer, SOC lead, or incident responder.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Threat report as PDF, DOCX, TXT, or pasted text
- Optional customer context such as affected platform, sector, or observed tools
- Configured LLM provider or local/private LLM gateway
- Current ATT&CK reference data loaded in AdversaryGraph

## Before You Start

- API and database selftest are green
- ATT&CK Enterprise/Mobile/ICS data is synchronized
- The report is allowed to be processed by the selected LLM provider
- The analyst understands that LLM mappings require review

## Step-By-Step Workflow

### Step 1: Open AI Analysis and load the report text or file.

This step should produce or protect one concrete part of the analysis: reviewed att&ck technique list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does the evidence describe procedure, or only mention a tool name?

### Step 2: Choose the analysis domain and LLM provider. Use a local/private provider for sensitive reports.

This step should produce or protect one concrete part of the analysis: evidence snippets and confidence values. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the selected technique too broad when a sub-technique is available?

### Step 3: Run extraction and wait for the structured technique list, evidence snippets, and confidence values.

This step should produce or protect one concrete part of the analysis: navigator matrix layer. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should the mapping be accepted now, or kept as needs-evidence until more telemetry exists?

### Step 4: Read each mapping against the source evidence. Confirm that the behavior matches the ATT&CK definition, not only a keyword.

This step should produce or protect one concrete part of the analysis: PDF/JSON report export. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the output for internal triage, customer delivery, or detection engineering?

### Step 5: Set review status: accepted, suggested, needs-evidence, or rejected.

This step should produce or protect one concrete part of the analysis: detection handoff candidate list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does the evidence describe procedure, or only mention a tool name?

### Step 6: Open each important TTP detail panel to review tactic context, detection notes, and related references.

This step should produce or protect one concrete part of the analysis: reviewed att&ck technique list. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the selected technique too broad when a sub-technique is available?

### Step 7: Inject accepted TTPs into Navigator and review matrix coverage.

This step should produce or protect one concrete part of the analysis: evidence snippets and confidence values. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should the mapping be accepted now, or kept as needs-evidence until more telemetry exists?

### Step 8: Export the layer, JSON, or PDF only after review is complete.

This step should produce or protect one concrete part of the analysis: navigator matrix layer. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the output for internal triage, customer delivery, or detection engineering?

## Key Analyst Decisions

- Does the evidence describe procedure, or only mention a tool name?
- Is the selected technique too broad when a sub-technique is available?
- Should the mapping be accepted now, or kept as needs-evidence until more telemetry exists?
- Is the output for internal triage, customer delivery, or detection engineering?

## What The Analyst Gets

- Reviewed ATT&CK technique list
- Evidence snippets and confidence values
- Navigator matrix layer
- PDF/JSON report export
- Detection handoff candidate list

## Common Mistakes To Avoid

- Accepting model output without source review
- Mapping generic words to techniques without behavioral evidence
- Mixing attribution claims with TTP similarity
- Exporting unreviewed findings to customers


## Handoff Guidance

Hand accepted TTPs, evidence, and confidence notes to detection engineers. Keep rejected and needs-evidence items visible for auditability and later investigation.

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
