---
title: "AdversaryGraph v6.5: From Threat Intelligence to Defensible Detection Decisions"
description: "A practical guide to AdversaryGraph v6.5 for governed intelligence retrieval, evidence-backed ATT&CK mapping, threat hunting, detection engineering, and controlled validation."
author: "Andrey Pautov"
status: "Draft"
tags:
  - AdversaryGraph
  - Cyber Threat Intelligence
  - Detection Engineering
  - Threat Hunting
  - MITRE ATT&CK
---

# AdversaryGraph v6.5: From Threat Intelligence to Defensible Detection Decisions

**A practical guide to connecting governed intelligence retrieval, source evidence, ATT&CK mappings, telemetry requirements, threat hunts, detection rules, controlled validation, and analyst decisions in one platform.**

Cyber threat intelligence rarely fails because analysts have no data. It fails in the spaces between tools. A report contains a useful observation, an analyst maps it to MITRE ATT&CK, a detection engineer creates a rule, another team tests the rule, and the final result is copied into a report. At every handoff, evidence, assumptions, provenance, and limitations can disappear.

AdversaryGraph v6.5 is my self-hosted, AI-assisted CTI-to-detection workbench for addressing that problem. It connects intelligence analysis, ATT&CK and ATLAS mapping, IOC and CVE investigation, unified retrieval, evidence graphs, governed threat hunting, detection content, controlled attack simulation, SIEM validation, malware triage, asset exposure, and reporting. Its purpose is not to automate the analyst out of the process. Its purpose is to make the analyst's reasoning visible, repeatable, and defensible.

Version 6.5 makes the connected workflow more operational. It adds governed Threat Hunting, a source-backed Query Library, hybrid intelligence retrieval with citation-bound answers, private business-context reranking, advisory local MCP access, private local-model support, finer authorization, and stronger file, network, deployment, and audit boundaries.

This guide explains v6.5 through one practical workflow. We will begin with a fictional report describing encoded PowerShell activity, preserve the source evidence, retrieve related intelligence with citations, map the behavior to `T1059.001`, identify the required telemetry, prepare a bounded threat hunt, review detection content, validate it with safe telemetry, and record an explicit analyst decision.

The screenshots can be added directly at the marked positions. Use one consistent fictional investigation throughout the guide so the visuals reinforce a connected workflow rather than presenting unrelated product pages.

> **Scope and safety:** The walkthrough uses repository-provided fictional reports, `example` domains, RFC 5737 documentation IP addresses, synthetic events, and approved local lab fixtures. AI output, ATT&CK similarity, IOC overlap, generated detection content, and synthetic telemetry are analytical leads. They are not proof of execution, attribution, compromise, or production detection coverage.

> **Version note:** This document follows the prepared AdversaryGraph **v6.5.0 source release**, dated 25 July 2026. The source tree, backend, frontend, Helm chart, API reference, and documentation declare v6.5.0. The latest previously published immutable tag remains v6.0.0 until the protected v6.5.0 tag workflow publishes and verifies the matching images, digest manifest, metadata, and release artifacts.

## Table of contents

1. [Why I built AdversaryGraph](#why-i-built-adversarygraph)
2. [What is new in AdversaryGraph v6.5](#what-is-new-in-adversarygraph-v65)
3. [What AdversaryGraph is](#what-adversarygraph-is)
4. [The platform architecture](#the-platform-architecture)
5. [The Evidence-to-Detection Graph](#the-evidence-to-detection-graph)
6. [Preparing the demonstration environment](#preparing-the-demonstration-environment)
7. [Practical workflow: from report to analyst decision](#practical-workflow-from-report-to-analyst-decision)
   1. [Start with source evidence](#1-start-with-source-evidence)
   2. [Review AI-assisted report analysis](#2-review-ai-assisted-report-analysis)
   3. [Normalize behavior with ATTCK](#3-normalize-behavior-with-attck)
   4. [Investigate indicators and related intelligence](#4-investigate-indicators-and-related-intelligence)
   5. [Retrieve grounded intelligence with RAG](#5-retrieve-grounded-intelligence-with-rag)
   6. [Build the reasoning path](#6-build-the-reasoning-path)
   7. [Create a falsifiable threat hunt](#7-create-a-falsifiable-threat-hunt)
   8. [Review detection content in Query Library](#8-review-detection-content-in-query-library)
   9. [Validate with correct telemetry](#9-validate-with-correct-telemetry)
   10. [Record the SIEM result and analyst decision](#10-record-the-siem-result-and-analyst-decision)
8. [Additional platform workspaces](#additional-platform-workspaces)
9. [AI governance and evidence boundaries](#ai-governance-and-evidence-boundaries)
10. [Security and deployment boundaries](#security-and-deployment-boundaries)
11. [How to interpret the result](#how-to-interpret-the-result)
12. [Limitations](#limitations)
13. [Analyst checklist](#analyst-checklist)
14. [Conclusion](#conclusion)
15. [References](#references)
16. [Follow My Work](#follow-my-work)

## Why I built AdversaryGraph

Most security workflows already contain the correct individual components. Analysts have CTI reports, ATT&CK Navigator, IOC repositories, detection rules, SIEM searches, ticketing systems, lab environments, and reporting templates. The problem is that these components often preserve outputs but not reasoning.

Consider a common sequence:

```text
Report
  -> ATT&CK technique
  -> hunt query
  -> detection rule
  -> test event
  -> SIEM screenshot
  -> final report
```

The final report may show a green result, but important questions remain unanswered:

- Which exact sentence supported the ATT&CK mapping?
- Was the source describing observed behavior or a vendor hypothesis?
- Which telemetry was required to test the behavior?
- Were the necessary fields actually present?
- Was the query executed, or merely saved?
- Was the event generated by a real lab target or constructed synthetically?
- Did the SIEM receive the event, or did the detection rule match it?
- Which rule version was validated?
- What did the analyst accept, reject, or leave unresolved?

AdversaryGraph treats these questions as part of the analytical output. A missing sensor, rejected AI suggestion, contradictory source, unsupported simulation, or inconclusive result should remain visible. Hiding uncertainty makes a workflow look complete, but it does not make the conclusion stronger.

> **Screenshot to add:** A clean AdversaryGraph Discover workspace showing the main investigation and validation workspaces. Keep the platform name, module groups, and current status indicators visible.

## What is new in AdversaryGraph v6.5

AdversaryGraph v6.5 turns the platform's earlier evidence and validation foundation into a governed intelligence-to-hunt workflow. The release scope is not one isolated feature. It connects retrieval, analyst planning, detection-content provenance, external execution records, and controlled validation.

| v6.5 capability | What it adds | Evidence boundary |
|---|---|---|
| Governed Threat Hunting | Falsifiable hypotheses, bounded scope, telemetry requirements, append-only queries, reviewed findings, disposition, and handoff | A saved query is not proof that it ran |
| Threat Hunting AI | Stage-specific hypothesis, plan, query, findings, and outcome drafts | The assistant cannot create evidence, execute a query, or set the verdict |
| Query Library | Reviewed Sigma and YARA-L examples, bounded community rules, typed search, provenance, parser state, and hunt handoff | Library content remains a draft until local review and testing |
| Deterministic IOC query construction | Sigma, YARA-L, YARA, KQL, SPL, EQL, Lucene, SQL, osquery, and generic output | Generation is local, but destination fields and syntax still require validation |
| Unified hybrid RAG | Exact identifiers, PostgreSQL full-text, optional `pgvector`, reciprocal-rank fusion, and bounded relationship expansion | Retrieval relevance is not evidence confidence or attribution probability |
| Business-context assistance | Private region, sector, technology, and crown-jewel context for reranking and generation | Profile data is request context, not a public corpus record |
| Navigator intelligence assistant | Citation-bound answers and expiring ATT&CK proposals with explicit Add or Replace confirmation | Proposals do not automatically mutate or save a layer |
| Local MCP facade | Bounded search, entity reads, grounded questions, and advisory Navigator proposals over `stdio` | No arbitrary SQL, URL fetching, query execution, response action, or automatic platform mutation |
| Private local AI | An optional internal Ollama profile for governed assistance | Model availability does not remove prompt-injection or output-validation requirements |
| Saved-asset intelligence | Searchable inventory, alerts, assessment history, and evidence-labelled CVE, ATT&CK, and IOC relationships | A correlation or candidate does not prove exposure or exploitation |
| Authorized exposure assessment | Inventory-bound passive context, bounded unprivileged service discovery, web posture checks, local CVE candidates, and governed AI review | Targets must already exist in inventory and active work requires explicit authorization |
| SOC access groups | Persistent named users, 12 least-privilege profiles, grant ceilings, and consistent module/API enforcement | Module authorization is not tenant-level data isolation |
| Authorization and hardening | Finer permissions, MFA/session improvements, request limits, archive safety, SSRF controls, non-root containers, observability, and release safeguards | Separate deployments remain necessary for mutually untrusted customers |

The most visible v6.5 change is the new operational loop:

```text
stored evidence
  -> grounded retrieval and citations
  -> falsifiable hunt plan
  -> reviewed query and immutable version
  -> approved external execution
  -> evidence-backed findings
  -> controlled detection validation
  -> explicit analyst outcome
```

The prepared v6.5.0 source exposes **31 governed workspaces** across intelligence, investigation, hunting, validation, operations, administration, and support. The generated contract reference covers **28 OpenAPI groups, 322 operations, and 287 frontend API call sites**. These counts describe the prepared source contract, not the immutable artifact state.

> **Screenshot to add:** The v6.5 Discover workspace or a clean collage showing Threat Hunting, Query Library, the Navigator RAG assistant, Evidence Graph, and Threat Radar asset intelligence. Label it **AdversaryGraph v6.5.0 source release** until the immutable v6.5.0 tag is published.

## What AdversaryGraph is

AdversaryGraph is a self-hosted platform for moving from threat intelligence to defensive action while preserving evidence and review state. It combines several connected workflows:

| Area | Main purpose | Example workspaces |
|---|---|---|
| Intelligence | Collect, retrieve, and structure reports, actors, techniques, sectors, and emerging signals | Discover, AI Analysis, Intelligence RAG Assistant, ATT&CK Group Library, Sector Intel, Threat Radar |
| Enrichment | Preserve indicators, vulnerability context, sources, and relationships | IOC Library, IOC Investigation, CVE Library, Feeds |
| Reasoning | Connect evidence, claims, behaviors, telemetry, detections, and decisions | Evidence Graph, Compare, Asset Surface |
| Operationalization | Turn intelligence into bounded hunts and versioned, reviewed detection content | Threat Hunting, Query Library, Operations, Pipeline |
| Validation | Test telemetry and detection behavior in controlled environments | Attack Simulation, SIEM forwarding, lab fixtures |
| Malware analysis | Triage samples and connect static or dynamic findings to wider investigations | Malware Analysis, Unpacker, String Analyzer, Debugger, Dynamic Analysis |
| Reporting and governance | Preserve reports, lifecycle state, audit events, health, and operational evidence | Investigation Report, Observability, Help, Troubleshooting |

The platform is not a replacement for a SIEM or EDR. It does not execute saved threat-hunt queries against production telemetry. It is not an autonomous attribution system, and it does not treat AI output as ground truth. Attack Simulation is not a general exploit framework and is restricted to predefined scenarios and approved lab targets.

These boundaries are intentional. They allow the platform to connect analytical and engineering work without falsely claiming that a stored query ran, that a generated event represents real adversary behavior, or that a visual similarity proves attribution.

> **Screenshot to add:** Discover with the primary workflow cards and platform counters. Use this as the broad platform overview before moving into the practical case.

## The platform architecture

AdversaryGraph v6.5 uses a React frontend and a FastAPI backend. PostgreSQL stores structured platform data, typed Evidence Graph nodes, retrieval documents, vectors, and relationships. The deployment can use `pgvector` for semantic retrieval, while exact-identifier and PostgreSQL full-text retrieval remain available without an embedding model. Redis and Celery support bounded background reconciliation and retention jobs. LLM providers are optional and governed according to the selected TLP and data-handling boundary.

```text
Analyst
   |
   v
React workspace
   |
   v
FastAPI services
   |
   +--> PostgreSQL / pgvector
   +--> Redis / Celery
   +--> unified normalized intelligence corpus
   +--> approved local or remote LLM provider
   +--> local stdio MCP facade
   +--> isolated malware-analysis services
   +--> approved lab fixtures and test collectors
```

The architecture separates the core system of record from optional assistance and validation services. This matters because a model failure should not erase stored evidence, and a simulation failure should not rewrite an analyst decision. Each component contributes evidence or workflow support; none of them becomes the sole trust anchor.

The v6.5 retrieval path normalizes allowlisted records instead of embedding raw provider responses or adding opaque vector fields to every source table. Source updates change document hashes and replace their chunks. Removed records are tombstoned during reconciliation. Search combines exact identifiers, lexical matches, optional vector similarity, reciprocal-rank fusion, private business-context reranking, and a bounded one-hop expansion over allowlisted stored relationships.

The v6.5 MCP integration is a separate `stdio` process that calls the same authenticated RAG API boundary. It exposes bounded read-only or advisory functions and does not import database, Redis, feed, or provider credentials. It cannot confirm a proposal, save a Navigator layer, reindex data, execute a hunt query, or perform a response action.

> **Screenshot to add:** A simple architecture diagram or an AdversaryGraph documentation architecture image. Avoid a dense infrastructure screenshot that cannot be read during a presentation.

## The Evidence-to-Detection Graph

The Evidence-to-Detection Graph is the reasoning layer at the center of AdversaryGraph. It preserves the path from a raw source to a reviewed defensive outcome:

```text
Evidence
  -> Claim
  -> Behavior
  -> ATT&CK Technique
  -> Required Telemetry
  -> Detection Candidate
  -> Detection Rule
  -> Validation Scenario
  -> SIEM Result
  -> Analyst Decision
```

This is not a decorative graph. Each node has a defined role, and each relationship should be explainable.

| Node | Analytical question |
|---|---|
| Evidence | What exact artifact, quote, event, or observation do we have? |
| Claim | What statement is being made from that evidence? |
| Behavior | What normalized activity does the claim describe? |
| ATT&CK Technique | Which ATT&CK or ATLAS behavior is supported, and why? |
| Required Telemetry | Which sensor, data component, and fields are needed? |
| Detection Candidate | What testable defensive hypothesis follows? |
| Detection Rule | What exact logic and version implements the candidate? |
| Validation Scenario | How was the rule tested, and under which conditions? |
| SIEM Result | Was the event delivered, parsed, and matched? |
| Analyst Decision | What was accepted, rejected, escalated, or left unresolved? |

The graph also supports uncertainty. Relationships can represent contradiction, weakening evidence, or a blocking gap. AI-generated nodes remain drafts until reviewed. A readiness score describes operational completeness; it does not prove that an environment has complete detection coverage.

> **Screenshot to add:** Evidence Graph in Reasoning Path view, with the full sequence visible from evidence to analyst decision.

## Preparing the demonstration environment

The repository contains a safe deterministic demo corpus. It is suitable for screenshots, training, and a live presentation because it does not contain malware, live infrastructure, private intelligence, credentials, or operational attack instructions.

### Verify the v6.5 source state

Before preparing data or screenshots, record the declared version and exact commit:

```bash
cat VERSION
git rev-parse HEAD
git status --short
```

For the prepared release source, `VERSION` should report `6.5.0`. The commit identifies the exact implementation shown, while `git status` reveals local changes that may make the demonstration differ from the documented release boundary.

For a source deployment, follow the repository quick start:

```bash
cp .env.example .env
docker compose config --quiet
docker compose pull
docker compose up -d --build
./scripts/selftest.sh
```

The base platform does not require a cloud AI provider. Version 6.5 supports an optional private Ollama Compose profile as well as governed operator-approved providers. Do not display `.env`, provider keys, session tokens, database credentials, or MCP bearer tokens during the presentation.

The canonical v6.5 source release gate is:

```bash
./scripts/release-readiness.sh --full
```

Run the full gate before the presentation, not during it. The repository's recorded candidate validation covers backend tests and coverage, frontend lint/build/browser tests, module and API-contract consistency, Compose and Helm rendering, documentation, dependency audits, secret scanning, container builds, and strict image scans. A successful local gate validates the source environment; it does not create the immutable tag or published artifact evidence.

Use these fixtures:

| Purpose | File |
|---|---|
| General fictional CTI report | `demo/sample-report.md` |
| Expected ATT&CK output | `demo/expected-techniques.json` |
| Expected analyst summary | `demo/expected-report.md` |
| Focused Evidence Graph report | `demo/evidence-graph/sample-report.md` |
| Safe process and network events | `demo/evidence-graph/sample-logs.jsonl` |
| Expected reasoning graph | `demo/evidence-graph/expected-graph.json` |
| Expected gaps | `demo/evidence-graph/expected-gaps.json` |
| Safe IOC inventory | `demo/iocs.csv` |

Before a live walkthrough:

1. Start the documented deployment and confirm required services are healthy.
2. Run the repository self-test.
3. Confirm the selected AI provider is available, or prepare a completed analysis session as a fallback.
4. Load the fictional report and create the expected Evidence Graph case.
5. Prepare a draft hunt for `T1059.001` without completing the analyst decision.
6. Prepare a reviewed query and safe validation event.
7. Confirm the approved test collector and SIEM destination are reachable.
8. Remove credentials, environment files, internal URLs, personal identifiers, and private recent-item history from every visible screen.
9. Record the demonstrated commit and label the environment **AdversaryGraph v6.5.0 source release** until the v6.5.0 tag and artifacts are published.
10. Build or refresh the v6.5 RAG index and confirm that exact/lexical retrieval is ready; if semantic retrieval is enabled, confirm the private embedding model and dimensions match the indexed corpus.
11. Use a dedicated, least-privilege analyst identity for the optional MCP demonstration.

The focused report describes the following fictional observation:

> Endpoint telemetry later showed `powershell.exe` launching with encoded command arguments.

It also states that Script Block Logging is unavailable. This gives us a useful analytical boundary: process telemetry may support an encoded-command finding, but it cannot reveal the decoded script content by itself.

## Practical workflow: from report to analyst decision

### 1. Start with source evidence

Open **AI Analysis** and paste or upload `demo/evidence-graph/sample-report.md`. Before running any model, inspect the source as an analyst.

The report gives us several direct observations:

- the event concerns `WS-DEMO-01`;
- `powershell.exe` launched with encoded command arguments;
- the host contacted a documentation-safe IP address;
- no malware binary is part of the case;
- Script Block Logging is unavailable.

It also contains hypotheses, including the proposed mapping to `T1059.001` and the need for network telemetry. These hypotheses are useful, but they are not the same as observed events.

| Evidence state | Example from the case |
|---|---|
| Observed in the fictional source | `powershell.exe` launched with encoded arguments |
| Analyst hypothesis | The behavior maps to `T1059.001` |
| Required corroboration | Process-event fields and event provenance |
| Known limitation | No PowerShell 4104 Script Block Logging |
| Unsupported conclusion | The decoded command content or malware family |

This distinction should remain visible throughout the investigation. A platform cannot repair weak source discipline later with a higher confidence score.

> **Screenshot to add:** AI Analysis input with the source sentence and analyst hypothesis visible. Use the fictional report only.

### 2. Review AI-assisted report analysis

Run the configured provider or open the prepared completed analysis. AdversaryGraph can extract ATT&CK candidates, IOCs, actor mentions, summaries, and validation gaps from report text. The important result is not simply a list of technique IDs. The useful result keeps each candidate connected to its supporting excerpt.

For this case, the expected lead is:

| Field | Value |
|---|---|
| Candidate | `T1059.001` |
| Technique | PowerShell |
| Source evidence | `powershell.exe` launched with encoded command arguments |
| Confidence basis | Direct behavior phrase in the supplied report |
| Required validation | Process creation telemetry and command-line fields |
| Limitation | Script content is unavailable without additional telemetry |

Review the result against the original source. Reject mappings that rely only on keywords, unsupported assumptions, or behavior not described in the report. If the model provides an actor hypothesis, treat it separately from the behavior mapping. Common PowerShell behavior has little attribution value by itself.

AI analysis can fail because of provider configuration, credentials, rate limits, response validation, or unavailable models. The safe fallback is a stored completed session or the deterministic expected output—not live troubleshooting of keys during a presentation.

> **Screenshot to add:** The evidence-backed `T1059.001` result, including confidence, quoted evidence, and validation gaps. Do not crop out warnings or model/provider status.

### 3. Normalize behavior with ATT&CK

Open **Navigator**, select the Enterprise ATT&CK domain, and focus `T1059.001`. ATT&CK provides a common behavioral vocabulary. It helps analysts connect reporting, telemetry, detection content, and defensive coverage without inventing a platform-specific taxonomy for every case.

The mapping should be based on behavior:

```text
Observed process: powershell.exe
Observed argument pattern: encoded command
Normalized behavior: PowerShell command execution
ATT&CK candidate: T1059.001
```

The mapping does not establish:

- which actor executed the command;
- whether the command was malicious;
- which script content was decoded;
- whether the event represents initial access, execution, persistence, or another stage without additional context;
- whether the organization detects every implementation of `T1059.001`.

Navigator can compare selected techniques with groups, campaigns, and reports. Use those results to generate questions and prioritize review. Do not turn visual overlap into attribution.

> **Screenshot to add:** Enterprise Navigator focused on `T1059.001`, with the technique detail and selected domain visible.

### 4. Investigate indicators and related intelligence

The report also includes documentation-safe infrastructure. Open **IOC Library** or **IOC Investigation** and inspect one indicator with its source and relationships.

An IOC record should answer:

- What is the indicator type?
- Where did it come from?
- When was the source published or ingested?
- Is the value active, historical, reserved, private, or documentation-only?
- Which reports, techniques, malware findings, assets, actors, or CVEs are connected?
- Which relationships are direct and which are inferred?

In this demo, `203.0.113.44` belongs to an address block reserved for documentation. That status should prevent it from being treated like active hostile infrastructure. Similarly, `example` domains exist to support safe examples, not reputation scoring.

IOC overlap can support correlation when provenance and timing align, but it does not prove ownership or actor attribution. A hash statically present in a report, a domain found in a binary string, and a destination observed at runtime are different evidence classes and should not be collapsed into one generic “IOC found” statement.

> **Screenshot to add:** IOC detail showing the indicator, source, type, relationships, and enrichment state. The reserved or documentation status should be readable.

### 5. Retrieve grounded intelligence with RAG

AdversaryGraph v6.5 builds a normalized retrieval corpus across IOC, CVE, ATT&CK, actor observations, campaigns, reports, knowledge, Threat Radar, Threat Hunting, Evidence Graph, and sanitized asset records. Open **ATT&CK Navigator**, then open the **Intelligence RAG assistant**.

The shortest safe demonstration uses two questions:

```text
Find evidence relevant to encoded PowerShell execution and T1059.001.
```

Then:

```text
Propose the relevant Enterprise ATT&CK techniques for this investigation.
```

The first response should return source cards and citations. Review each citation against the stored record. A citation establishes that the stored source contains the quoted context. It does not prove that the behavior occurred in the local environment.

The second response can produce an expiring Navigator proposal. The backend validates proposed ATT&CK identifiers against the local catalog and binds the preview to source state and checksums. The analyst must choose **Add** or **Replace** explicitly. Confirmation changes the current preview state; it does not automatically save a named Navigator layer.

The retrieval pipeline is deliberately bounded:

```text
exact identifier lookup
  + lexical search
  + optional vector search
  -> reciprocal-rank fusion
  -> private business-profile reranking
  -> optional one-hop relationship expansion
  -> source cards, scores, markings, freshness, and warnings
  -> citation-bound synthesis
```

Vector similarity is a retrieval aid. It is not confidence, attribution probability, risk, or proof of targeting. Relationship expansion is also a lead: an actor-to-IOC or actor-to-CVE link still requires provenance and evidence review.

Saved business profiles can add private region, sector, technology, and crown-jewel context to request-time reranking and generation. The profile is not added to the globally searchable corpus. Use only synthetic business context during a public presentation.

> **Screenshot to add:** Navigator Intelligence RAG assistant with the question, cited source cards, lexical/vector status, warnings, and TLP/provider boundary visible.

> **Screenshot to add:** Expiring ATT&CK proposal preview before explicit Add or Replace confirmation.

#### Optional local MCP demonstration

Version 6.5 also exposes the governed retrieval boundary through a local `stdio` MCP server. Use it only if the audience needs an integration example. Demonstrate a bounded intelligence search or grounded question, then return to the main browser workflow.

State the boundary clearly: MCP cannot run arbitrary SQL, fetch arbitrary URLs, execute a hunt query, confirm a Navigator proposal, save a layer, or perform a response action. Use a dedicated account with `run_analysis`, a loopback API origin for the standard host-side configuration, and no remote MCP transport.

> **Screenshot to add:** Optional MCP client response showing cited AdversaryGraph sources and an advisory result. Do not show bearer tokens, client configuration secrets, or environment variables.

### 6. Build the reasoning path

Open **Evidence Graph** and create or load the fictional investigation. The expected path for this case is:

```text
Evidence:
  report excerpt describing powershell.exe with encoded arguments

Claim:
  encoded PowerShell was observed on WS-DEMO-01

Behavior:
  PowerShell command execution

ATT&CK Technique:
  T1059.001

Required Telemetry:
  process creation and PowerShell Script Block Logging

Detection Candidate:
  alert when powershell.exe uses encoded-command flags

Detection Rule:
  reviewed Sigma or backend-specific implementation

Validation Scenario:
  replay a safe Sysmon-style process event

SIEM Result:
  rule matched the controlled event

Analyst Decision:
  accept the staged process-event path; preserve the 4104 telemetry gap
```

The expected telemetry record includes fields such as timestamp, host, user, image, command line, parent image, and event source. Process creation data can support the encoded-command detection path. The absence of Script Block Logging means the graph should retain a telemetry gap rather than silently upgrading the result to complete PowerShell-content coverage.

Use the Graph Overview to understand the case, Reasoning Path to explain the sequence, Gap View to find missing work, and the review queue to accept or reject drafts. Keep AI-created relationships visibly separate from analyst-reviewed edges.

> **Screenshot to add:** Evidence Graph overview.

> **Screenshot to add:** Linear reasoning path from report evidence to `T1059.001`.

> **Screenshot to add:** Gap View showing the missing PowerShell 4104 telemetry.

### 7. Create a falsifiable threat hunt

Open **Threat Hunting** and create a hunt from the report, selected ATT&CK technique, or reviewed query. A useful hunt begins with a statement that can be tested and potentially rejected.

For this case:

> If unauthorized encoded PowerShell execution occurred on managed Windows endpoints during the demo interval, process-creation telemetry should show `powershell.exe` with encoded-command flags. The absence of Script Block Logging limits content-level conclusions.

Define the hunt before writing the final query:

| Hunt element | Demo value |
|---|---|
| Scope | Managed Windows endpoints; focus on `WS-DEMO-01` |
| Time range | The bounded fictional incident interval |
| Technique | `T1059.001` |
| Data source | Sysmon Event ID 1, Windows 4688, or equivalent EDR process telemetry |
| Required fields | Timestamp, host, user, image, command line, parent process |
| Expected evidence | PowerShell process with a recognized encoded-command switch |
| Benign alternatives | Approved administration, deployment tooling, security testing |
| Exclusions | Known signed automation and approved maintenance windows |
| Limitation | No script-block content and incomplete command semantics |
| Negative-result meaning | No match in the searched scope; not proof of a clean environment |

The hunt lifecycle should preserve draft, planning, execution, review, completion, cancellation, and archive states. Query versions should remain append-only so later edits do not rewrite what an analyst actually reviewed or ran.

AdversaryGraph records the plan and outcome, but it does not execute the saved query against the SIEM, EDR, or data lake. The analyst must copy the reviewed query to an approved telemetry backend, run it under local authorization and cost controls, and record the resulting evidence.

> **Screenshot to add:** Threat Hunting hypothesis and scope.

> **Screenshot to add:** Telemetry requirements, expected evidence, false-positive considerations, and readiness state.

### 8. Review detection content in Query Library

Open **Query Library** and search for:

```text
ttp:T1059.001
```

Add a language filter when needed, for example:

```text
ttp:T1059.001 lang:sigma
```

Query Library combines reviewed AdversaryGraph examples with bounded community content indexed through Pipeline. Each item should preserve its source, upstream rule identifier, license, format, parser or validation state, ATT&CK mapping, and synchronization time.

A library rule is a starting point, not a production detection. Before use:

1. Confirm the source and license.
2. Read the rule logic rather than relying on its title.
3. Validate the ATT&CK mapping against the behavior detected.
4. Translate generic fields to the destination schema.
5. Confirm the required sensor, fields, parser, timestamps, and retention.
6. Add environment-specific exclusions and false-positive controls.
7. Test syntax in the destination product.
8. Evaluate known-positive and representative benign data.
9. Preserve the reviewed version and result in the hunt.

Query Library can also construct field-aware queries from IOCs for formats including Sigma, YARA-L, YARA, KQL, SPL, EQL, Lucene, SQL, osquery, and generic output. This construction is deterministic and local; ordinary IOC query generation does not require sending indicators to an LLM.

In v6.5, Query Library is part of the primary intelligence-to-hunt workflow. It can hand a reviewed starting point into a canonical hunt draft, but the analyst must still define scope, time, telemetry, required fields, exclusions, ownership, and TLP before the hunt is ready.

> **Screenshot to add:** Query Library filtered for `T1059.001`.

> **Screenshot to add:** Query detail showing rule content, source, license, ATT&CK mapping, and version metadata.

### 9. Validate with correct telemetry

Open **Attack Simulation** and select the relevant technique or prepared endpoint scenario. The validation design must begin with the sensor that would observe the behavior.

| Behavior family | Appropriate telemetry examples |
|---|---|
| Windows process execution | Sysmon, Windows Security, EDR process events |
| PowerShell content | Script Block Logging 4104, module logging, AMSI/EDR content where authorized |
| Web exploitation | Web server, application, WAF, proxy, and relevant network logs |
| Authentication activity | Identity provider, VPN, Windows logon, MFA, and SSO events |
| DNS or network behavior | Resolver, proxy, firewall, NDR, and endpoint network telemetry |

AdversaryGraph distinguishes real lab telemetry from synthetic telemetry:

| Property | Real lab telemetry | Synthetic telemetry |
|---|---|---|
| Origin | An approved lab fixture | A template or governed generation service |
| Execution | A predefined safe scenario interacts with the fixture | No behavior is executed; event data is constructed |
| Useful for | Sensor behavior and realistic collection paths | Parser, field mapping, routing, and rule plumbing |
| Does it prove real-behavior detection? | Stronger evidence, but still requires review | No |
| Required label | Real lab | Synthetic or replayed |

For the PowerShell case, the current simulation catalog includes a safe encoded-command telemetry scenario that validates process-event handling without executing PowerShell. Use only the documented, approved scenario and test destination.

Watch each stage separately:

```text
event created
  -> event delivered
  -> collector accepted it
  -> parser recognized it
  -> expected fields populated
  -> detection rule evaluated
  -> rule matched or did not match
```

An HTTP success response proves only that the collector accepted the request. It does not prove that the parser created the intended event or that the detection rule matched.

> **Screenshot to add:** Attack Simulation matrix with the selected technique.

> **Screenshot to add:** Per-technique page showing approved target, expected telemetry, and safety notes.

> **Screenshot to add:** Real or synthetic telemetry label with the event fields visible.

> **Screenshot to add:** SIEM delivery history and detection result, presented as separate states.

### 10. Record the SIEM result and analyst decision

Return to **Evidence Graph** or the Threat Hunting outcome. Attach the reviewed result to the exact rule and query version that was tested.

The final decision for this fictional case can be expressed as:

| Decision element | Result |
|---|---|
| Process-event detection | Matched the controlled encoded-command event |
| Tested rule | Exact reviewed version recorded |
| Test source | Safe replay or approved lab scenario, explicitly labeled |
| Analyst decision | Accept as a staged detection path for the demo |
| Remaining gap | PowerShell 4104 coverage is unavailable |
| Unsupported claim | Full script-content visibility or complete `T1059.001` coverage |
| Next step | Validate production telemetry availability and benign administrative baselines |

This is more useful than a simple pass or fail. The positive result remains connected to the test conditions, and the missing telemetry remains connected to the decision. Another analyst can reconstruct what was tested without relying on personal memory or a detached screenshot.

> **Screenshot to add:** Completed reasoning path or hunt outcome showing the SIEM result, analyst decision, and remaining limitation together.

## Additional platform workspaces

The focused workflow demonstrates the platform's main analytical chain, but AdversaryGraph supports several related starting points and pivots.

### Threat Radar

Threat Radar connects external and internal threat signals to products, components, dependencies, exposure, and operational workflows. It is useful for PSIRT, detection, incident response, legal, and threat-hunt handoffs. Risk scoring remains a prioritization aid and must be reviewed against actual product exposure and telemetry readiness.

### Asset Surface

Asset Surface normalizes inventory data and maps services, identities, cloud resources, and exposure hypotheses to relevant ATT&CK techniques. Inventory-derived mappings are leads until the analyst confirms reachability, configuration, business context, and available monitoring.

### Threat Radar saved assets and authorized assessment

Version 6.5 adds a searchable saved-asset registry and dedicated asset intelligence pages. Each asset can expose normalized inventory, alerts, assessment history, CVE candidates, ATT&CK techniques, and IOC relationships. The evidence label matters: an exact identity match, a source-backed threat-signal relationship, an inventory-derived CPE candidate, and a scan-derived candidate are not equivalent findings.

The v6.5 release scope permits assessment only for an IP address or HTTP(S) host already recorded on the selected asset. The workflow can combine configured passive OSINT, bounded unprivileged Nmap service discovery, safe web posture checks, read-only DNS and TLS posture, local CVE candidates, and governed AI review. Active discovery requires explicit authorization and the relevant Attack Simulation permission. Newly observed IP, domain, or URL facts do not silently rewrite inventory; they require a controlled merge action.

Current development after the prepared v6.5.0 boundary moves scanner tools into a separate authenticated, non-root `scanner-mcp` container on a private control network. If that newer architecture is demonstrated, label it as post-v6.5 source work unless the published v6.5 artifact manifest includes the scanner image.

> **Screenshot to add:** Threat Radar saved asset page showing normalized inventory, evidence-labelled CVE/TTP/IOC relationships, authorization state, and assessment history. Do not use a live external target.

### SOC users, groups, and module authorization

Version 6.5 introduces persistent named users and access groups that govern both sidebar visibility and direct API access. Twelve built-in least-privilege profiles cover Platform Administrators, SOC Manager, SOC Tier 1/2/3, Threat Intelligence, Threat Hunting, Detection Engineering, Incident Response/DFIR, Vulnerability Management, Intelligence Feed Operations, and Audit/Read Only.

Permissions control actions such as analysis, upload, intelligence management, detection changes, feed administration, export, simulation, SIEM forwarding, authentication, user management, and audit access. Module membership controls which governed workspaces the account may open. Grant ceilings prevent delegated administrators from assigning authority they do not possess, and continuity checks protect the last user-management principal.

> **Screenshot to add:** Administration access-group view with one least-privilege SOC profile and its module/action matrix. Use a fictional named account and hide session identifiers.

### Malware-analysis workspaces

The Malware Analysis, Unpacker, String Analyzer, Debugger, and Dynamic Analysis workspaces support safe triage and deeper reverse engineering. Static strings, imports, API names, entropy, packer hints, and decompiler output indicate possible capabilities. They do not prove runtime behavior. Dynamic execution remains isolated and disabled by default unless the analyst deliberately uses an approved environment.

### Intelligence retrieval and MCP

Version 6.5 includes unified hybrid retrieval, a citation-bound Navigator assistant, private business-profile context, and local advisory MCP integration. Retrieved passages retain source cards, TLP/legal state, freshness, scores, and warnings. Retrieval similarity is not evidence by itself, and external content remains untrusted data rather than executable instruction.

### Reports and observability

Investigation Report, Operations, Pipeline, and Observability preserve outputs, lifecycle, ingestion state, failures, and audit evidence. These workspaces are important because a defensible workflow includes operational provenance as well as analytical conclusions.

> **Screenshot to add:** A collage or two selected additional workspaces relevant to the audience. Do not attempt to show every module in one unreadable image.

## AI governance and evidence boundaries

AI is useful in AdversaryGraph when it reduces repetitive analytical work without erasing the distinction between source evidence and generated interpretation.

The assistant may help draft:

- report summaries and evidence-backed ATT&CK candidates;
- IOC and entity extraction;
- hunt hypotheses, plans, and query suggestions;
- telemetry requirements and benign alternatives;
- detection candidates and validation ideas;
- explanation and report text.

Version 6.5 applies provider policy to the workflow. Local/private processing is the default trust direction. Configured cloud providers remain governed by operator policy, TLP eligibility, and explicit per-request remote-processing acknowledgment. `TLP:AMBER+STRICT` and `TLP:RED` remain local-only for governed Threat Hunting assistance. Later hunt stages require saved canonical hunt state rather than an untracked browser draft.

For report-to-hypothesis generation, the assistant reads a bounded portion of an already stored report or research session. It does not accept a new URL, fetch another source, or search enterprise telemetry as part of that request. Exact citations are checked against the stored source, invalid citations are removed, and changed source state causes stale-context rejection.

The assistant must not independently:

- approve a source claim;
- establish actor attribution;
- declare a detection production-ready;
- execute a hunt query;
- mark a finding malicious;
- claim that a simulation represents real behavior when it is synthetic;
- make the final analyst decision.

The analyst should always ask four questions:

1. **What exact evidence did the model receive?**
2. **Did any evidence leave the local environment?**
3. **Which parts of the output are direct extraction, public-knowledge explanation, or inference?**
4. **Which conclusion requires independent validation?**

Sensitive reports may require a local provider or approved private gateway. Report text, strings, prompts, retrieved passages, and model output can contain credentials, personal data, customer identifiers, or attacker-controlled prompt-injection text. They must be handled as untrusted, potentially sensitive evidence.

## Security and deployment boundaries

AdversaryGraph is designed for controlled self-hosted deployment. Its security model should be explained directly:

- the default deployment should not be exposed to the internet without a documented architecture and hardening review;
- current workspace authorization should not be presented as hardened multi-tenant SaaS isolation;
- v6.5 provides finer route and action permissions for analysis, uploads, intelligence, detections, feeds, exports, simulation, SIEM, authentication, users, and audit access, but permissions do not create tenant-level data ownership across every table;
- imported reports, files, archives, URLs, feeds, and model content cross explicit untrusted-input boundaries;
- decoded uploads and remote responses are bounded, archive paths are validated, and caller-controlled outbound HTTP is restricted by scheme, destination, DNS revalidation, redirect, proxy, and response-size controls;
- cloud AI is optional and subject to data-classification and provider policy;
- unsaved Threat Hunting plan drafts can use an enabled cloud provider only with an eligible explicit TLP marking and per-request acknowledgment; restricted markings remain local-only;
- secrets belong in protected configuration, never screenshots, source control, reports, or model prompts;
- malware workflows require isolation and bounded processing;
- dynamic malware execution is disabled by default;
- Attack Simulation is restricted to approved local lab targets and predefined scenarios;
- external SIEM, feed, and enrichment integrations should use least-privilege credentials and restricted destinations;
- audit records and failure states should be preserved rather than hidden.
- the analyst-facing MCP facade uses authenticated `stdio`, not an exposed remote MCP transport, and should use a dedicated least-privilege analyst account;
- v6.5 asset assessment is inventory-bound, permission-gated, auditable, and restricted to approved target forms; it is not an autonomous vulnerability scanner;
- persistent SOC access groups enforce modules and actions in the UI and API, but mutually untrusted organizations still require separate deployments.

The public demo should never use customer intelligence, live credentials, real malicious infrastructure, production endpoints, or unrestricted simulation targets.

## How to interpret the result

The completed workflow supports a bounded conclusion:

> A fictional source and safe process event support a `T1059.001` encoded-PowerShell detection candidate. The reviewed rule matched the controlled event under the recorded test conditions. The result does not establish script content, actor attribution, malicious intent, or complete production coverage. Missing PowerShell 4104 telemetry remains an explicit gap.

This conclusion is stronger than a broad claim because it identifies exactly what the evidence supports and what it does not.

Use the following evidence ladder:

```text
source statement
  -> structured candidate
  -> analyst-reviewed mapping
  -> telemetry-backed observation
  -> tested detection behavior
  -> bounded analyst finding
```

Do not skip levels. A report sentence alone does not become a confirmed local observation. A generated query does not become a validated rule. An IOC relationship does not become attribution. A synthetic event does not become real adversary execution.

## Limitations

AdversaryGraph improves workflow traceability, but it cannot make weak evidence strong.

- AI provider output varies and can be incomplete, malformed, biased, or incorrect.
- ATT&CK mappings depend on source specificity and analyst interpretation.
- IOC enrichment depends on source freshness, provenance, and external service availability.
- Similarity and graph proximity do not prove a relationship.
- Saved threat-hunt queries are not automatically executed against enterprise telemetry.
- RAG results can degrade to lexical-only retrieval when embeddings are unavailable; vector or relationship rank is not evidence confidence.
- Business-profile context improves prioritization but cannot prove that an actor targets the selected organization.
- MCP provides only the bounded advisory operations exposed by v6.5 and is not a general automation or response channel.
- Asset exposure results include passive observations and unconfirmed candidates; discovered services or CVEs are not automatically confirmed vulnerabilities.
- The prepared release documents 31 governed workspaces and a validated API contract, but those inventories do not guarantee that every optional provider, feed, scanner, or lab dependency is configured in a deployment.
- Detection content requires local schema translation, tuning, peer review, and validation.
- Synthetic telemetry validates limited parts of the pipeline and cannot replace realistic authorized lab testing.
- A successful lab result does not guarantee production sensor coverage, parser consistency, retention, or performance.
- Static malware-analysis findings describe possible capability, not confirmed runtime behavior.
- Current deployment boundaries should not be represented as hardened multi-tenant SaaS isolation.
- The v6.5.0 source metadata and local release gate are prepared, but immutable publication remains incomplete until merge CI and the protected tag workflow verify images, scans, registry readability, digests, metadata, tag protection, and release assets.

These limitations should appear in the presentation and final report. A transparent boundary increases trust more than an unsupported claim of completeness.

## Analyst checklist

Before presenting or using an AdversaryGraph investigation, confirm:

- [ ] The source is preserved and classified correctly.
- [ ] Direct observations are separated from hypotheses and AI suggestions.
- [ ] Every ATT&CK mapping has a behavior-specific rationale and evidence.
- [ ] IOC type, provenance, timing, and evidence class are recorded.
- [ ] Similarity and overlap are not described as attribution.
- [ ] Every RAG answer has reviewed citations, markings, freshness, and fallback warnings.
- [ ] Business-profile relevance is not described as targeting evidence.
- [ ] Asset correlations and scan-derived CVE candidates are not described as confirmed exposure or exploitation.
- [ ] The presenter account uses a least-privilege v6.5 SOC group.
- [ ] Required sensors and minimum fields are identified.
- [ ] Missing telemetry remains visible.
- [ ] The hunt has a falsifiable hypothesis, bounded scope, and benign alternatives.
- [ ] The saved query version matches the externally executed version.
- [ ] Query provenance, source, and license are recorded.
- [ ] Real, synthetic, and replayed telemetry are labeled accurately.
- [ ] Collector delivery is separated from parser success and rule matching.
- [ ] The validation result names the exact rule and test conditions.
- [ ] The analyst decision includes confidence, limitations, and next steps.
- [ ] Screenshots contain no credentials, internal identifiers, or private intelligence.
- [ ] The environment is labeled v6.5.0 source release until immutable v6.5.0 publication is complete.

## Conclusion

AdversaryGraph v6.5 is built around a simple principle: a useful security decision should remain traceable to evidence, assumptions, required telemetry, validation conditions, and human review.

The practical workflow begins with an exact source observation. It separates the claim from the raw evidence, normalizes supported behavior with ATT&CK, preserves IOC and intelligence provenance, defines the telemetry required to test the hypothesis, creates a bounded threat hunt, reviews detection content, validates it with correctly labeled evidence, and records the final analyst decision without hiding unresolved gaps.

Hybrid retrieval can find relevant stored context. AI can accelerate extraction and drafting. ATT&CK can provide a common vocabulary. A graph can preserve relationships. Query Library can preserve detection provenance. Lab and SIEM integrations can provide validation evidence. None of these components replaces analytical discipline.

The most important outcome is not a large number of mapped techniques or a green dashboard. It is a conclusion another analyst can inspect, reproduce, challenge, and improve.

> **AdversaryGraph does not replace analyst judgment. It preserves the evidence and reasoning that make analyst judgment defensible.**

## References

- [AdversaryGraph repository](https://github.com/anpa1200/adversarygraph)
- [AdversaryGraph project page](https://1200km.com/adversarygraph/)
- [AdversaryGraph documentation](https://1200km.com/adversarygraph-docs/)
- [Live intelligence workspace](https://1200km.com/threat-matrix/)
- [AdversaryGraph v6.5.0 release notes](../release-notes/v6.5.0.md)
- [AdversaryGraph v6.5.0 release summary](../release-summary-v6.5.0.md)
- [AdversaryGraph version matrix](../version-matrix.md)
- [AdversaryGraph Module Reference and Casebook](../module-reference.md)
- [AdversaryGraph Threat Hunting Guide](../threat-hunting-guide.md)
- [Threat Hunting Query Library](../query-library.md)
- [Unified Intelligence RAG and MCP](../unified-rag-and-mcp.md)
- [Threat Radar](../threat-radar.md)
- [Evidence-to-Detection Graph](../evidence-to-detection-graph.md)
- [Attack Simulation](../attack-simulation.md)
- [Validation and limitations](../validation-and-limitations.md)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator)
- [MITRE ATT&CK: T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Sigma specification and documentation](https://sigmahq.io/docs/)
- [OASIS STIX Version 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [RFC 5737: IPv4 Address Blocks Reserved for Documentation](https://www.rfc-editor.org/rfc/rfc5737)

## Follow My Work

I publish practical cybersecurity research, CTI workflows, detection engineering notes, malware-analysis projects, AI-security research, open-source tools, labs, and technical guides.

- [Website — 1200km.com](https://1200km.com/)
- [Medium — @1200km](https://medium.com/@1200km)
- [LinkedIn — Andrey Pautov](https://www.linkedin.com/in/andrey-pautov/)
- [GitHub — tools and labs](https://github.com/anpa1200)
- [Contact — 1200km@gmail.com](mailto:1200km@gmail.com)
