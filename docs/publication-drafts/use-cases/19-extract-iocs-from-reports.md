# Extract IOCs From Uploaded Reports: A Practical AdversaryGraph Workflow

**Subtitle:** Which observables appear in this report and how should they be stored?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Extract IOCs From Uploaded Reports**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

A report includes domains, IPs, URLs, hashes, file names, or mutexes. The team needs to extract them, preserve source context, and decide which are useful.

The operational question is: **Which observables appear in this report and how should they be stored?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI analyst, IR analyst, SOC analyst, or malware analyst.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- Report text or file
- IOC extraction patterns
- Optional actor/malware context
- IOC Library storage

## Before You Start

- Report processing is allowed
- IOC Library is available
- Private-data rules are understood
- Enrichment keys are configured if needed

## Step-By-Step Workflow

### Step 1: Upload or paste the report in AI Analysis or report workflow.

This step should produce or protect one concrete part of the analysis: report-derived ioc set. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the string a real IOC or example text?

### Step 2: Extract observables and review normalized types.

This step should produce or protect one concrete part of the analysis: source report context. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is it current enough for operational use?

### Step 3: Remove false positives such as documentation IPs or placeholders.

This step should produce or protect one concrete part of the analysis: actor/malware links where supported. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should it be mapped to an actor, malware family, campaign, or remain unmapped?

### Step 4: Map indicators to actors or malware only when evidence supports it.

This step should produce or protect one concrete part of the analysis: CSV/STIX export options. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Can it be sent to external enrichment services?

### Step 5: Store report-derived IOCs with source context.

This step should produce or protect one concrete part of the analysis: report-derived ioc set. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the string a real IOC or example text?

### Step 6: Enrich selected indicators and export relevant subsets.

This step should produce or protect one concrete part of the analysis: source report context. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is it current enough for operational use?

## Key Analyst Decisions

- Is the string a real IOC or example text?
- Is it current enough for operational use?
- Should it be mapped to an actor, malware family, campaign, or remain unmapped?
- Can it be sent to external enrichment services?

## What The Analyst Gets

- Report-derived IOC set
- Source report context
- Actor/malware links where supported
- CSV/STIX export options

## Common Mistakes To Avoid

- Extracting false positives from code blocks or examples
- Mapping indicators without attribution evidence
- Enriching sensitive customer IOCs externally
- Keeping stale indicators without last-seen context


## Handoff Guidance

Give SOC teams cleaned, source-labeled IOCs with action guidance and confidence notes.

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
