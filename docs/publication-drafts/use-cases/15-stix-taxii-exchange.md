# Import And Export STIX/TAXII Intelligence: A Practical AdversaryGraph Workflow

**Subtitle:** How can AdversaryGraph exchange structured intelligence with other CTI tools?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Import And Export STIX/TAXII Intelligence**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

Intelligence needs to move between systems without copy-paste. STIX and TAXII provide a structured exchange path for indicators and observed data.

The operational question is: **How can AdversaryGraph exchange structured intelligence with other CTI tools?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: CTI platform engineer, SOC automation engineer, OpenCTI/MISP operator, or analyst.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- STIX bundle file or TAXII collection URL
- Optional bearer token or basic auth
- IOC records for export
- Target platform requirements

## Before You Start

- TAXII endpoint is reachable if pulling remote collections
- Credentials are available
- STIX version compatibility is understood
- Imported data handling rules are clear

## Step-By-Step Workflow

### Step 1: Export selected IOC records as STIX when sharing out.

This step should produce or protect one concrete part of the analysis: STIX export bundle. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the STIX object an indicator, observed-data, malware, relationship, or report?

### Step 2: Import a STIX file when receiving structured intelligence.

This step should produce or protect one concrete part of the analysis: Imported STIX/TAXII IOC records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should imported objects be trusted or treated as unreviewed?

### Step 3: For TAXII, provide collection objects URL and credentials if required.

This step should produce or protect one concrete part of the analysis: source-labeled structured intelligence. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Does the receiving system require a specific marking or identity?

### Step 4: Review imported indicators and observed-data records in IOC Library.

This step should produce or protect one concrete part of the analysis: Searchable IOC Library entries. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should private intelligence be exported at all?

### Step 5: Filter by source and actor where possible.

This step should produce or protect one concrete part of the analysis: STIX export bundle. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the STIX object an indicator, observed-data, malware, relationship, or report?

### Step 6: Enrich or map relevant records to TTPs after import.

This step should produce or protect one concrete part of the analysis: Imported STIX/TAXII IOC records. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should imported objects be trusted or treated as unreviewed?

## Key Analyst Decisions

- Is the STIX object an indicator, observed-data, malware, relationship, or report?
- Should imported objects be trusted or treated as unreviewed?
- Does the receiving system require a specific marking or identity?
- Should private intelligence be exported at all?

## What The Analyst Gets

- STIX export bundle
- Imported STIX/TAXII IOC records
- Source-labeled structured intelligence
- Searchable IOC Library entries

## Common Mistakes To Avoid

- Assuming all STIX producers model data the same way
- Ignoring object markings
- Importing relationships without validating context
- Exporting private data to the wrong system


## Handoff Guidance

Use STIX/TAXII for structured exchange, then use AdversaryGraph for enrichment, filtering, and analyst review.

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
