# Enrich An IOC With VirusTotal: A Practical AdversaryGraph Workflow

**Subtitle:** What does VirusTotal know about this IP, domain, URL, or hash?

## Introduction

Security teams do not need more disconnected notes. They need workflows that preserve evidence, explain reasoning, and turn raw intelligence into output that a SOC analyst, detection engineer, incident responder, or customer can actually use.

This article walks through one AdversaryGraph workflow: **Enrich An IOC With VirusTotal**.

AdversaryGraph is a self-hosted AI-assisted CTI platform for report analysis, MITRE ATT&CK mapping, actor comparison, IOC enrichment, detection engineering handoff, and structured export. It is not an attribution oracle and it is not a replacement for analyst judgment. It is a workbench for making the analyst process faster, clearer, and more repeatable.

## The Analyst Problem

An indicator appears in a report or alert. The analyst needs reputation, related context, possible malware/actor links, rule hits, and ATT&CK pivots.

The operational question is: **What does VirusTotal know about this IP, domain, URL, or hash?**

In many teams, this work is split across browser tabs, spreadsheets, SIEM notes, report PDFs, and manual ATT&CK searches. That creates two problems. First, the work is slow. Second, the reasoning is hard to audit later. AdversaryGraph is designed to keep the source, mapping, enrichment, review status, and final output connected.

## Who This Workflow Is For

Primary users: SOC analyst, CTI analyst, malware analyst, or threat hunter.

This workflow is useful when the team needs reviewed output rather than raw extraction. It can support internal investigation, customer reporting, SOC triage, threat hunting, detection engineering, or platform validation.

## Inputs You Need

- IP, domain, URL, MD5, SHA1, or SHA256
- VirusTotal API key
- Local actor and TTP database
- Optional IOC Library record

## Before You Start

- VIRUSTOTAL_API_KEY is configured in the API container
- Indicator type is normalized correctly
- Network access to VirusTotal is available
- Rate limits are understood

## Step-By-Step Workflow

### Step 1: Open VirusTotal Lookup or click Enrichment from IOC Library/actor IOC view.

This step should produce or protect one concrete part of the analysis: Structured VT enrichment. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the indicator malicious, suspicious, benign, or unknown?

### Step 2: Submit the normalized indicator.

This step should produce or protect one concrete part of the analysis: Related objects and tags. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the VT signal fresh or historical?

### Step 3: Review detection ratio, reputation, tags, categories, and last analysis stats.

This step should produce or protect one concrete part of the analysis: Possible actor/malware/TTP links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is an actor link direct or just a tag coincidence?

### Step 4: Review crowdsourced Sigma/YARA/rule context when available.

This step should produce or protect one concrete part of the analysis: Matrix pivots and My TTPs actions. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Should the indicator be blocked, hunted, monitored, or used only as context?

### Step 5: Inspect relationships such as communicating files, resolutions, downloaded files, or contacted domains.

This step should produce or protect one concrete part of the analysis: Structured VT enrichment. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the indicator malicious, suspicious, benign, or unknown?

### Step 6: Check whether tags, names, or relationships match local actors, malware families, or ATT&CK techniques.

This step should produce or protect one concrete part of the analysis: Related objects and tags. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is the VT signal fresh or historical?

### Step 7: Add relevant TTPs to My TTPs or show them on Navigator only after reviewing evidence.

This step should produce or protect one concrete part of the analysis: Possible actor/malware/TTP links. The analyst should avoid treating the tool output as final until the source context is checked.

The key review question here is: Is an actor link direct or just a tag coincidence?

## Key Analyst Decisions

- Is the indicator malicious, suspicious, benign, or unknown?
- Is the VT signal fresh or historical?
- Is an actor link direct or just a tag coincidence?
- Should the indicator be blocked, hunted, monitored, or used only as context?

## What The Analyst Gets

- Structured VT enrichment
- Related objects and tags
- Possible actor/malware/TTP links
- Matrix pivots and My TTPs actions

## Common Mistakes To Avoid

- Sending sensitive private IOCs to a third-party service without approval
- Treating vendor detections as full context
- Mapping tags to actors without evidence
- Ignoring VT rate limits or API errors


## Handoff Guidance

Use VT enrichment to decide next pivots: related files, domains, actor pages, relevant TTPs, and SOC watchlists.

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
