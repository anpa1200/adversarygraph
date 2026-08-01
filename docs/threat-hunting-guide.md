# Threat Hunting: From Hypothesis to Defensible Detection

> A practical, evidence-led guide for building, running, reviewing, and improving
> threat hunts. This edition uses MITRE ATT&CK v19
> terminology and was reviewed on 25 July 2026 against the current v19 release
> and v19.1 data. Revalidate ATT&CK mappings whenever the platform's ATT&CK
> content is upgraded.

Threat hunting is a disciplined search for adversary behavior that may not have
triggered an alert. Its output is not just a list of matches. A defensible hunt
connects a reason to hunt, a falsifiable hypothesis, an authorized scope,
sufficient telemetry, a reviewed analytic, reproducible run records, preserved
evidence, and an explicit decision.

This guide is written for SOC analysts, detection engineers, incident
responders, threat-intelligence analysts, platform administrators, and security
leaders. The core methodology is vendor-neutral. Query examples are pseudocode
and must be adapted to the local schema, backend, retention window, and business
context before use.

AdversaryGraph resources:
[platform](https://1200km.com/adversarygraph/) ·
[operator guide](threat-hunting-with-adversarygraph.md) ·
[GitHub](https://github.com/anpa1200/adversarygraph) ·
[documentation](https://1200km.com/adversarygraph-docs/)

## Table of Contents

1. [Purpose and outcomes](#1-purpose-and-outcomes)
2. [What threat hunting is—and is not](#2-what-threat-hunting-isand-is-not)
3. [Operating principles](#3-operating-principles)
4. [The end-to-end hunt lifecycle](#4-the-end-to-end-hunt-lifecycle)
5. [Build a sustainable hunt program](#5-build-a-sustainable-hunt-program)
6. [Turn intelligence and risk into a hypothesis](#6-turn-intelligence-and-risk-into-a-hypothesis)
7. [Use ATT&CK v19 correctly](#7-use-attck-v19-correctly)
8. [Engineer telemetry before analytics](#8-engineer-telemetry-before-analytics)
9. [Design portable, reviewable analytics](#9-design-portable-reviewable-analytics)
10. [Run hunts safely and reproducibly](#10-run-hunts-safely-and-reproducibly)
11. [Investigate matches and preserve evidence](#11-investigate-matches-and-preserve-evidence)
12. [Decide, escalate, and close](#12-decide-escalate-and-close)
13. [Convert learning into durable defense](#13-convert-learning-into-durable-defense)
14. [Security, privacy, and operational boundaries](#14-security-privacy-and-operational-boundaries)
15. [Metrics and maturity](#15-metrics-and-maturity)
16. [Twenty worked hunt playbooks](#16-twenty-worked-hunt-playbooks)
17. [Reusable templates](#17-reusable-templates)
18. [Operational checklists](#18-operational-checklists)
    - [Governed AI assistance review](#188-governed-ai-assistance-review)
19. [Primary references](#19-primary-references)

## 1. Purpose and outcomes

The purpose of a hunt is to reduce uncertainty about a specific adversary
behavior in a defined environment. A hunt is useful when it produces one or more
of these outcomes:

- confirmed malicious activity that moves into incident response;
- suspicious activity requiring deeper investigation;
- a well-supported benign explanation and a better baseline;
- a detection candidate or an improvement to an existing rule;
- a documented telemetry, retention, parsing, or asset-visibility gap;
- validation that a control or analytic observes the intended behavior;
- a repeatable search scheduled for future execution; or
- a defensible negative result limited to the data actually searched.

A hunt that finds no malicious activity can still be successful. It fails only
when its scope, data, analytic, execution, or decision cannot be explained and
reproduced. The correct negative statement is “no matching evidence was found in
the searched data,” not “the environment is clean.”

NIST's enhanced security requirements explicitly call for an established and
maintained threat-hunting capability, including a defined frequency. The
companion assessment guide expects assessable artifacts such as hunt plans,
reports, audit records, event logs, tools, processes, and personnel evidence.
These enhanced requirements are selectively imposed: agencies choose which
requirements apply based on mission and risk, and selected requirements flow
down by contract or agreement; the hunting requirement applies only when
selected. See [NIST SP 800-172r3](https://csrc.nist.gov/pubs/sp/800/172/r3/final)
(accessed 17 July 2026) and
[NIST SP 800-172Ar3](https://csrc.nist.gov/pubs/sp/800/172/a/r3/final)
(accessed 17 July 2026).

## 2. What threat hunting is—and is not

### 2.1 Working definition

Threat hunting is an authorized, hypothesis-led or behavior-led search across
security-relevant data for activity that existing preventive and detective
controls may have missed. It combines intelligence, knowledge of the protected
environment, analytics, investigation, and analyst judgment.

MITRE's official TTP-Based Hunting material presents a six-stage flow:
understand fundamentals, develop a hypothesis or abstract analytic, identify
data requirements, identify collection gaps, implement and test analytics, and
perform the hunt. This guide operationalizes that flow rather than treating a
query as the whole hunt. See
[MITRE TTP-Based Hunting training](https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/)
(accessed 17 July 2026).

### 2.2 Hunting compared with adjacent work

| Activity | Starts with | Typical output | Relationship to hunting |
|---|---|---|---|
| Alert triage | A fired detection | True/false positive and next action | A match may become a hunt pivot, but triage is reactive. |
| Incident response | A suspected or confirmed incident | Containment, eradication, recovery, lessons learned | A hunt escalates when evidence meets the incident threshold. |
| Threat-intelligence research | Actors, campaigns, reports, infrastructure, or vulnerabilities | Assessed intelligence | Intelligence prioritizes hypotheses; it is not evidence that behavior occurred locally. |
| Intelligence retrohunt | Historical intelligence, reports, indicators, techniques, and stored evidence | Repeated intelligence patterns and pivots | Intelligence retrohunt searches intelligence holdings; enterprise threat hunting searches authorized operational telemetry. |
| Detection engineering | A behavior to detect continuously | Tested and governed detection content | A successful hunt often becomes a detection candidate. |
| Vulnerability management | Exposure and weakness data | Prioritized remediation | Exposure can trigger a hunt for exploitation behavior. |
| Penetration testing or attack simulation | Authorized control validation | Test evidence and remediation | Simulation can validate a hunt analytic, but only within an approved lab or test scope. |

### 2.3 What a hunt must not claim

A hunt cannot prove absence beyond its effective time range, collected assets,
telemetry coverage, parser quality, and analytic sensitivity. An indicator match
does not prove compromise. ATT&CK overlap does not prove actor attribution. An
AI-generated explanation is not analyst-validated evidence. A successful query
is not proof that the underlying logs were complete.

## 3. Operating principles

1. **Start with a question, not a tool.** State what behavior is being tested and
   why it matters before choosing a query language.
2. **Make hypotheses falsifiable.** Specify expected evidence and
   counter-evidence. “Look for bad activity” is not a hypothesis.
3. **Prove data fitness.** Check source coverage, fields, timestamps, parsing,
   identity resolution, retention, and known gaps before interpreting results.
4. **Prefer behavior over brittle indicators.** IOCs are valuable pivots and
   scoping aids, but adversaries can rotate infrastructure quickly.
5. **Separate facts, inferences, and decisions.** Preserve the event or source
   reference, then record the analyst's interpretation and final disposition
   separately.
6. **Keep confidence, severity, impact, and disposition distinct.** A
   high-confidence benign event is not high severity; a low-confidence lead may
   still have high potential impact.
7. **Design for reproducibility.** Version the analytic and record the exact
   scope, parameters, effective time range, backend, schema mapping, analyst,
   truncation, and errors for every run.
8. **Treat gaps as results.** Missing endpoint coverage or an unparsed field is a
   concrete defensive finding, not a reason to quietly close the hunt.
9. **Use least privilege and bounded execution.** Read-only credentials, narrow
   time ranges, row and cost limits, cancellation, and audit records are normal
   controls for hunt infrastructure.
10. **Keep humans accountable.** Automation can draft hypotheses, translate
    queries, cluster results, and summarize evidence; an authorized analyst
    approves execution and owns the decision.

NIST notes that sophisticated adversaries may manipulate or evade analytics,
which is one reason human monitoring and review remain necessary. See the
discussion of cyber-resiliency analysis in
[NIST SP 800-172r3](https://csrc.nist.gov/pubs/sp/800/172/r3/final)
(accessed 17 July 2026).

## 4. The end-to-end hunt lifecycle

```text
trigger and context
    -> falsifiable hypothesis
    -> scope and authorization
    -> ATT&CK behavior and detection model
    -> telemetry requirements and readiness
    -> versioned analytic and peer review
    -> bounded execution
    -> triage, pivots, timeline, and evidence
    -> disposition and escalation
    -> detection, gap, simulation, or recurring-hunt handoff
    -> review and measurable improvement
```

### 4.1 Stage 1: select a trigger

Useful triggers include:

- a new campaign, actor behavior, or procedure in reviewed CTI;
- an IOC or infrastructure cluster relevant to local assets;
- a critical vulnerability with credible exploitation behavior;
- a detection gap identified in ATT&CK coverage review;
- an incident retrospective or near miss;
- an anomalous baseline shift;
- a high-value asset, identity, service, or business process;
- a control change, new log source, merger, or cloud migration;
- a safe attack-simulation result; or
- a scheduled recurring requirement.

Record the source type, source reference, publication or observation time, and
why it is relevant locally. Recency alone is not prioritization: combine threat
likelihood, business impact, exposure, visibility, and cost.

### 4.2 Stage 2: write the hypothesis

Use this structure:

> Because **[context]**, an adversary may use **[behavior and ATT&CK
> technique]** against **[assets, identities, or environment]** to achieve
> **[objective]**. If this occurred during **[time and scope]**, we expect
> **[ordered observable evidence]** in **[telemetry]**. The hypothesis is
> weakened by **[counter-evidence or benign explanation]**. If required telemetry
> is insufficient, the result is **`inconclusive` or `telemetry_gap`**, not a clean
> bill of health.

### 4.3 Stage 3: bound and authorize the hunt

Define:

- business owner and hunt owner;
- assets, tenants, identities, networks, and exclusions;
- requested and maximum lookback;
- data sets and systems authorized for access;
- handling classification and residency constraints;
- query cost, row, concurrency, and runtime limits;
- incident-escalation contacts and thresholds; and
- whether any validation activity is permitted and where.

### 4.4 Stage 4: model behavior and data

Map the behavior to current ATT&CK techniques and, where available, current
Detection Strategies and Analytics. Translate each behavioral step into a data
requirement: source, channel, component, field, coverage, retention, and quality
test. Do this before writing backend syntax.

### 4.5 Stage 5: implement and review the analytic

Create a vendor-neutral behavioral analytic first, then one or more backend
implementations. Add expected benign cases, known blind spots, cost assumptions,
and a test plan. A second analyst should review high-impact or expensive hunts.

### 4.6 Stage 6: execute and investigate

Run a small preflight window, confirm field population and result shape, then
expand within the approved bounds. Triage results, pivot across entities and
time, build a timeline, preserve evidence references, and record both supporting
and contradictory facts.

### 4.7 Stage 7: decide and improve

Choose a controlled disposition, document limitations, and create explicit
follow-up work. Promote durable analytics to the detection lifecycle, track data
gaps, escalate incidents, or schedule the hunt. Review whether the original
hypothesis, data, and analytic were fit for purpose.

## 5. Build a sustainable hunt program

### 5.1 Define roles

| Role | Accountabilities |
|---|---|
| Hunt lead | Owns hypothesis, scope, execution plan, decision, and final report. |
| Supporting analyst | Reviews results, challenges assumptions, and provides peer review. |
| Detection engineer | Converts validated behavior into governed detection content. |
| Telemetry owner | Confirms collection, parsing, retention, time quality, and gap remediation. |
| Threat-intelligence analyst | Assesses source credibility, relevance, procedures, and attribution limits. |
| Incident responder | Accepts escalations and preserves incident-handling continuity. |
| Platform administrator | Manages roles, connectors, secrets, limits, backups, and auditability. |
| Privacy/legal stakeholder | Defines handling, proportionality, retention, cross-border, and workforce-monitoring constraints where applicable. |

The person who wrote an analytic may run it, but high-risk findings should have
independent review. Destructive record deletion, connector administration, and
secret access should not be routine analyst privileges.

### 5.2 Prioritize the backlog

Score candidates using a transparent rubric rather than analyst intuition
alone. One practical model rates each dimension from 0 to 3:

- threat relevance: evidence the behavior is used against the organization,
  sector, geography, or technology;
- exposure: reachable assets, vulnerable systems, privileged identities, or
  business dependency;
- impact: safety, confidentiality, integrity, availability, regulatory, and
  operational consequences;
- detection uncertainty: known coverage gap or unvalidated rule;
- telemetry readiness: whether the hunt can produce a meaningful answer; and
- urgency: active incident, exploitation, or time-sensitive intelligence.

Do not let high urgency conceal zero telemetry readiness. Run an explicit gap
assessment in parallel, or narrow the claim to available data.

### 5.3 Establish cadence

A healthy program mixes:

- event-driven hunts for active intelligence or incidents;
- recurring hunts for high-value behaviors and assets;
- validation hunts after detection, telemetry, or platform changes;
- exploratory hunts for unknown patterns; and
- retrospective hunts after new intelligence or newly available logs.

The cadence must be defined, owned, and reviewable. NIST's hunt requirement is
not satisfied by an undocumented “as needed” practice; the organization should
be able to show plans, executions, results, and follow-up artifacts
([NIST SP 800-172r3](https://csrc.nist.gov/pubs/sp/800/172/r3/final),
accessed 17 July 2026;
[NIST SP 800-172Ar3](https://csrc.nist.gov/pubs/sp/800/172/a/r3/final),
accessed 17 July 2026).

### 5.4 Create quality gates

Use [checklist 18.1](#181-ready-to-run-gate) as the single authoritative
ready-to-run gate. Before closure, apply [checklist 18.4](#184-hunt-closeout) to
run provenance, reviewed findings, disposition, limitations, the result
summary, and follow-up ownership and dates.

## 6. Turn intelligence and risk into a hypothesis

### 6.1 Start from behavior

Reports often emphasize malware, infrastructure, or actor names. Translate the
source into observable behavior:

1. What action did the adversary perform?
2. On which object or resource?
3. What preceded and followed the action?
4. Which local systems could expose that sequence?
5. Which legitimate workflows can produce the same pattern?
6. What evidence would materially weaken the hypothesis?

For example, replace “hunt for Actor X” with “hunt for a web service process
spawning an interpreter and making a new outbound connection on internet-facing
servers.” The behavior is testable even if attribution is wrong.

### 6.2 Decompose broad questions

A broad campaign hunt should become smaller linked hypotheses. A ransomware
question might be decomposed into:

- initial valid-account access from new infrastructure;
- discovery activity on a newly accessed host;
- remote-service movement between peer servers;
- security-tool impairment;
- recovery inhibition; and
- bulk file modification or encryption.

Each sub-hypothesis has different telemetry and false-positive assumptions. A
graph or timeline can connect their results without hiding uncertainty.

### 6.3 Record assumptions and counter-evidence

Common assumptions include:

- host clocks are synchronized;
- an endpoint sensor covered the full interval;
- identity logs distinguish interactive and service activity;
- NAT, proxy, and VPN attribution is understood;
- asset identifiers can be resolved across products; and
- administrative automation is inventoried.

Counter-evidence may include a signed and approved binary, a matching change
ticket, a known scanner identity, a consistent long-term baseline, an authorized
administrator confirmation, or absence of the follow-on sequence despite
complete telemetry. Counter-evidence should reduce confidence; it should not be
discarded simply because the original hypothesis was plausible.

## 7. Use ATT&CK v19 correctly

### 7.1 Pin the content version

ATT&CK changes over time. Every hunt should retain:

- ATT&CK release or content version;
- technique and sub-technique IDs, not names alone;
- domain, such as Enterprise, Mobile, or ICS;
- tactic relationships relevant to the hypothesis;
- Detection Strategy, Analytic, and Data Component identifiers where used; and
- the retrieval or review date.

This guide uses the current ATT&CK v19 terminology. As reviewed on 18 July 2026,
MITRE lists ATT&CK v19 as the current release and publishes v19.1 data. Consult
the official [ATT&CK version history](https://attack.mitre.org/resources/versions/)
(accessed 18 July 2026) and
[ATT&CK v19 release notes](https://attack.mitre.org/resources/updates/updates-april-2026/)
(accessed 18 July 2026) before upgrading stored mappings.

### 7.2 Use the current defensive model

ATT&CK v18 deprecated the legacy top-level Data Source objects and introduced a
defensive model centered on Detection Strategies, Analytics, and updated Data
Components. New hunt content should not be designed around the old Data Source
vocabulary. See MITRE's
[October 2025 ATT&CK update](https://attack.mitre.org/resources/updates/updates-october-2025/)
(accessed 17 July 2026) and the current
[Detection Strategies catalog](https://attack.mitre.org/detectionstrategies/)
(accessed 17 July 2026).

Use the model at three levels:

1. **Detection Strategy** — the behavioral detection approach.
2. **Analytic** — concrete logic and context for observing the behavior.
3. **Data Components and log channels** — the evidence needed to implement the
   analytic in the local environment.

Detection Strategy pages can list required channels, mutable elements, and
analytics. They are design inputs, not guaranteed deployable queries. For an
example of the current structure, see the
[MITRE ATT&CK Detection Strategies catalog](https://attack.mitre.org/detectionstrategies/)
(accessed 17 July 2026).

### 7.3 Understand the v19 tactic change

Enterprise ATT&CK v19 replaces the former broad Defense Evasion tactic with two
more precise tactics:

- **Stealth** — behavior intended to reduce visibility, blend in, or evade
  observation; and
- **Defense Impairment** — behavior that disables, modifies, or degrades
  defensive controls.

Do not persist `defense-evasion` as the current tactic for new v19 content.
Re-evaluate the technique relationship instead. For example,
[T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
is associated with Stealth, while
[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) is
associated with Defense Impairment (accessed 17 July 2026). The v19 migration
revoked the older Impair Defenses/Disable or Modify Tools objects, including the
former `T1562.001` mapping; new v19 hunts must use the current object and ID.
MITRE published an official Defense Evasion split crosswalk in
[JSON](https://attack.mitre.org/docs/subtechniques/de-split-crosswalk.json)
(accessed 17 July 2026) and
[CSV](https://attack.mitre.org/docs/subtechniques/de-split-crosswalk.csv)
(accessed 17 July 2026) formats that maps every former Defense Evasion technique
and sub-technique to its v19 object; consult it before remapping stored content.
A technique may relate to more than one tactic.
[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/), for example,
spans Initial Access, Persistence, Privilege Escalation, and Stealth in the
current model (accessed 17 July 2026).

### 7.4 ATT&CK is a map, not a verdict

An ATT&CK ID describes behavior; it does not establish actor identity, malicious
intent, or local occurrence. Preserve the source evidence and reasoning for each
mapping. Prefer a sub-technique when evidence supports it, but do not select a
more specific mapping merely to increase precision on paper.

For automated synchronization, use the official ATT&CK STIX/TAXII resources and
retain object IDs, versions, and revoked/deprecated state. MITRE documents the
supported data access methods in
[Working with ATT&CK](https://attack.mitre.org/resources/working-with-attack/)
(accessed 17 July 2026).

## 8. Engineer telemetry before analytics

### 8.1 Define a telemetry requirement

For every expected event, record:

| Field | Question |
|---|---|
| Source and channel | Which product, service, API, table, index, or stream records it? |
| Data Component | Which current ATT&CK Data Component best describes the evidence? |
| Required fields | Which time, entity, action, result, parent/child, network, and object fields are essential? |
| Coverage | Which assets, identities, tenants, regions, and network segments are represented? |
| Retention | Is the full hunt interval searchable, including delayed ingestion? |
| Time quality | Are event time, ingest time, timezone, clock drift, and late arrival understood? |
| Parsing | Are fields consistently typed and normalized? What remains in raw text? |
| Identity and asset resolution | Can product-specific IDs be joined without guessing? |
| Access and sensitivity | Who may query and view the data? Which fields require redaction? |
| Quality test | How will the analyst prove the channel is present and representative? |

### 8.2 Test data fitness

Before running the hunt analytic:

1. query a narrow recent window for basic event volume;
2. measure null rates for required fields;
3. inspect representative raw and normalized events;
4. compare reporting assets with inventory or sensor coverage;
5. check event-time versus ingest-time delay;
6. verify expected benign activity can be observed;
7. confirm parsing did not collapse distinct actions or outcomes; and
8. record gaps explicitly.

CISA recommends enabling detailed logging, centralizing logs, protecting them
from unauthorized access and tampering, and retaining them long enough to
support investigations. See
[CISA guidance on logging](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems)
(accessed 17 July 2026). In a 2025 proactive hunt, CISA and the U.S. Coast Guard
(USCG) treated insufficient logging itself as a material finding even though no
malicious activity was identified; that is the correct model for a hunt with
visibility limits. See the joint CISA-USCG advisory
[AA25-212A, “CISA and USCG Identify Areas for Cyber Hygiene Improvement After Conducting Proactive Threat Hunt at US Critical Infrastructure Organization”](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-212a)
(accessed 17 July 2026).

### 8.3 Normalize without losing provenance

Normalization makes analytics portable, but raw provenance must remain
available. Store or reference:

- original source and event identifier;
- raw-event location or immutable evidence reference;
- schema and mapping version;
- normalized fields and transformations;
- event time and ingest time; and
- parser errors or dropped-field indicators.

OCSF provides an open, vendor-neutral event schema. Its Detection Finding class
models concepts such as finding information, evidence, observables, confidence,
status, time, and affected resources. Pin the stable schema version used by each
connector; do not silently mix versions. See the
[OCSF schema browser](https://schema.ocsf.io/) (accessed 17 July 2026) and
[Detection Finding class](https://schema.ocsf.io/classes/detection_finding)
(accessed 17 July 2026).

Elastic Common Schema is another useful normalization target for event
categories and common entity fields. Its official documentation includes
category definitions and field-value guidance; record extensions and product
specifics rather than pretending every source is identical. See
[ECS reference](https://www.elastic.co/guide/en/ecs/current)
(accessed 17 July 2026) and
[ECS event category values](https://www.elastic.co/guide/en/ecs/current/ecs-category-field-values-reference.html)
(accessed 17 July 2026).

### 8.4 Classify readiness honestly

Use a simple per-requirement state:

- **ready** — representative data and required fields are searchable for the
  intended scope and period;
- **partial** — some coverage, fields, or retention are missing, and the claim
  will be narrowed;
- **unverified** — configuration says the source exists, but samples have not
  proved it;
- **missing** — the required evidence is not collected or searchable; or
- **failed** — collection, parsing, or query access is currently broken.

A percentage alone can conceal a critical missing channel. Always show the
individual requirement state and the effect on the hypothesis.

## 9. Design portable, reviewable analytics

### 9.1 Separate the abstract analytic from backend syntax

Write the behavioral logic first:

```text
entity: managed Windows endpoint
event: powershell process start or script-block execution
condition:
  encoded-command indicator or decode primitive
  AND parent, user, path, or follow-on behavior outside the approved baseline
sequence:
  execution -> optional file/network/child-process activity within 10 minutes
grouping: host + user + process entity
exceptions: signed approved automation with matching change context
```

Then create implementations for Sigma, KQL, SPL, EQL, Lucene, SQL, osquery,
YARA, YARA-L 2.0 over Google SecOps UDM, or another backend. Record which parts
were changed because the backend lacks a field, sequence operator, lookup, or
aggregation.

### 9.2 Version every analytic

A production hunt record should identify:

- immutable query or analytic version and checksum;
- author, reviewer, and approval time;
- query language and backend dialect/version;
- schema mapping and normalization version;
- parameters, lookups, and suppression lists;
- expected volume and cost;
- test fixtures and observed results;
- known false positives and false negatives; and
- change reason from the previous version.

Editing a single query text field in place destroys reproducibility. If the
current workflow stores only one text body, preserve older versions in the hunt
notes or external version control and include the exact version in every run
record.

### 9.3 Use Sigma deliberately

Sigma is a portable detection format, not a universal execution engine. The
official Sigma specification supports individual detections, reusable filters,
and correlation rules. Preserve the rule status, log source, detection logic,
references, false-positive notes, severity level, tags, and backend/pipeline
assumptions. Review converted output before execution because field mappings and
backend semantics differ. See the
[Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
(accessed 17 July 2026),
[correlation rule specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
(accessed 17 July 2026),
and [filters documentation](https://sigmahq.io/docs/meta/filters.html)
(accessed 17 July 2026).

### 9.4 Build context into the analytic

Useful context includes:

- asset criticality and exposure;
- identity privilege and normal working pattern;
- parent/child or initiating-process chain;
- signer, hash reputation, package source, and file prevalence;
- domain and destination prevalence;
- peer group and historical baseline;
- change, deployment, vulnerability, and maintenance records; and
- neighboring events before and after the match.

Avoid enormous static allowlists. Prefer scoped, owned, expiring exceptions with
a reason, evidence, and review date.

### 9.5 Test sensitivity and specificity

Use safe, authorized validation evidence:

- known benign examples prove the fields and pipeline exist;
- historical confirmed incidents test whether the analytic would have matched;
- synthetic fixtures test parsing and logic without touching production;
- approved lab simulations test telemetry end to end; and
- shadow-mode execution measures volume before operational use.

Do not execute adversary procedures on production systems merely to make a hunt
return data. Attack simulation belongs in an isolated, specifically authorized
lab and does not replace production telemetry review.

## 10. Run hunts safely and reproducibly

### 10.1 Preflight

Before execution, confirm that the approved scope, data, analytic, access,
limits, handling, stop behavior, and review remain current. The authoritative
full gate is [checklist 18.1](#181-ready-to-run-gate).

### 10.2 Expand progressively

Use staged execution:

1. **Schema check:** a tiny recent sample confirms names, types, and timestamps.
2. **Volume check:** a short interval estimates rows, cardinality, and cost.
3. **Logic check:** inspect representative matches and non-matches.
4. **Scoped run:** search the highest-priority assets or identities.
5. **Approved expansion:** widen time or population only when the earlier stages
   behave as expected.

If results are truncated, timed out, sampled, or partially unavailable, mark the
run accordingly. Never summarize a partial run as complete.

### 10.3 Record per-run provenance

At minimum capture:

- hunt ID and analytic version/checksum;
- connector and backend, without embedding secrets;
- schema and field-mapping version;
- resolved parameters and exclusions;
- requested and effective time range;
- execution start/end and analyst;
- assets, identities, tenants, or partitions searched;
- rows or bytes scanned and results returned when available;
- truncation, sampling, warnings, and errors;
- exported result reference and integrity hash when appropriate; and
- query-job or audit identifier from the source platform.

### 10.4 Stop conditions

Pause or stop when:

- the query exceeds approved cost or runtime;
- a source begins failing or produces unbounded results;
- the scope resolves to unauthorized data;
- result content violates handling restrictions;
- evidence meets the incident-escalation threshold; or
- a critical assumption is false, such as missing endpoint coverage.

Stopping safely is not a failed hunt. Record the reason, preserve partial
provenance, and choose `telemetry_gap`, `inconclusive`, or `query_failure` as
appropriate.

## 11. Investigate matches and preserve evidence

### 11.1 Triage the match, not just the indicator

For each candidate:

1. confirm the event is parsed correctly and the timestamp is meaningful;
2. resolve the host, identity, workload, or cloud resource;
3. inspect parent, child, session, process, request, or API context;
4. compare with the entity's baseline and peers;
5. look backward for initial access or preparation;
6. look forward for persistence, movement, collection, or impact;
7. test benign explanations using independent records; and
8. record what supports and weakens the hypothesis.

### 11.2 Pivot systematically

Common pivot keys include:

- device ID, hostname, IP, cloud instance, container, or workload identity;
- user, service account, session, token, role, or application ID;
- process entity, parent entity, executable hash, signer, or command line;
- domain, URL, certificate, JA4/JA3-like fingerprint, autonomous system, or
  destination account;
- file path, object key, registry path, scheduled task, service, or persistence
  record; and
- event correlation ID, request ID, trace ID, or provider audit identifier.

Treat IP addresses as time-bound observations. NAT, VPN, proxy, and cloud egress
can make an address belong to many identities.

### 11.3 Build a timeline

Keep event time and ingest time separate. Normalize timezone for comparison but
retain original values. A useful timeline includes:

| Time | Entity | Source | Observed fact | Analyst inference | Confidence | Evidence reference |
|---|---|---|---|---|---:|---|
| 09:14:03Z | host-17/user-a | EDR | PowerShell started with encoded argument | Possible obfuscated execution | 65 | `edr:event/…` |
| 09:14:11Z | host-17 | DNS | First-seen domain queried by same process tree | Possible command channel | 70 | `dns:event/…` |

Facts should be independently recoverable. Inferences should explain the
reasoning and uncertainty.

### 11.4 Preserve evidence responsibly

For each finding retain or reference:

- evidence type and immutable source reference;
- event identifier, source, dataset, and schema version;
- event and ingest time;
- raw hash or export hash when evidence is copied;
- minimal normalized excerpt needed for review;
- linked entities and observables;
- ATT&CK relationship and supporting rationale;
- analyst annotations, confidence, severity, and status; and
- access classification, retention, and redaction decisions.

Do not paste tokens, passwords, full browser histories, message contents, or
unnecessary personal data into a broadly accessible hunt note. Store sensitive
raw evidence in the approved evidence system and link to it using an
access-controlled reference.

## 12. Decide, escalate, and close

### 12.1 Use controlled outcomes

Use one primary disposition, with limitations in the summary:

- **`undetermined`** — the default state before review is complete and before
  the evidence supports a final decision;
- **`no_matches`** — no matching evidence was found in the complete, searched
  scope; this is not proof of absence outside it;
- **`benign`** — evidence supports an expected or authorized explanation;
- **`benign_policy_relevant`** — the activity has no supported malicious intent
  but violates policy or warrants governance follow-up;
- **`suspicious`** — concerning behavior remains unresolved and needs deeper
  investigation or incident review;
- **`confirmed_malicious`** — evidence supports malicious behavior and the
  incident process has accepted or is accepting the case;
- **`inconclusive`** — evidence conflicts or is insufficient despite the
  available data;
- **`telemetry_gap`** — required telemetry, parsing, retention, or analytic
  capability was insufficient; or
- **`query_failure`** — execution did not complete reliably and must not be
  interpreted as a hunt result.

Use `no_matches` only when the bounded search completed against fit-for-purpose
telemetry; use `telemetry_gap` or `query_failure` when the available evidence
cannot support a negative result.

### 12.2 Separate decision dimensions

| Dimension | Question | Example |
|---|---|---|
| Confidence | How strongly does the available evidence support the interpretation? | 80/100 that the process execution was unauthorized |
| Severity | How urgently should this finding be handled? | High because a privileged identity is involved |
| Impact | What could or did happen to the business or system? | Potential access to regulated data |
| Disposition | What is the reviewed outcome? | `suspicious`, escalated for incident review |
| Finding status | Where is the evidence item in its workflow? | New, reviewed, escalated, or closed |

### 12.3 Escalate without losing continuity

Escalate when evidence meets the organization's incident criteria. The handoff
should include the hunt ID, hypothesis, scope, timeline, affected entities,
evidence references, analytical limitations, actions already taken, and the
person accepting the case. Do not perform containment simply because a hunt
matched unless the responder is authorized and the incident plan permits it.

NIST SP 800-61r3 frames incident response as part of broader cybersecurity risk
management and emphasizes preparation, detection, response, recovery, and
continuous improvement. Align hunt handoffs with the organization's incident
process rather than inventing a parallel path. See
[NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
(accessed 17 July 2026).

### 12.4 Close with limitations

A final summary should say:

- what was tested and why;
- exactly what scope and time were searched;
- what data was ready, partial, missing, or failed;
- what analytic version ran and whether results were complete;
- what evidence was found and how it was reviewed;
- the disposition and confidence;
- what the result does not establish; and
- each follow-up action, owner, and date.

## 13. Convert learning into durable defense

### 13.1 Detection candidate

Promote a hunt analytic when the behavior is valuable for continuous monitoring
and the signal can be operationalized. The detection handoff should contain:

- behavior and ATT&CK mapping;
- reviewed logic and backend implementation;
- required telemetry and coverage assumptions;
- validation evidence;
- expected volume, false-positive cases, and tuning history;
- severity and routing guidance;
- owner, review frequency, and retirement conditions; and
- links back to the originating hunt and evidence.

### 13.2 Telemetry-gap backlog

A gap record should include affected hypotheses and assets, missing source or
field, business consequence, interim compensating evidence, owner, target date,
and verification test. “Enable more logging” is not actionable enough.

### 13.3 Recurring hunt

Schedule only after defining:

- frequency and lookback overlap;
- late-arriving data handling;
- owner and backup owner;
- approved analytic version;
- result-volume threshold;
- review service level;
- suppression expiry; and
- conditions for conversion to a detection or retirement.

### 13.4 Validation loop

Where safe and authorized, validate in a lab:

```text
reviewed behavior
    -> safe test scenario
    -> expected telemetry
    -> hunt or detection analytic
    -> observed SIEM result
    -> analyst decision
    -> logic, parser, or sensor improvement
```

Keep simulation evidence distinct from production observations. A lab pass
shows that the test path can be observed under test conditions; it does not
prove coverage of every production asset or adversary variant.

## 14. Security, privacy, and operational boundaries

### 14.1 Authorization and least privilege

- Query only systems and data explicitly in scope.
- Use separate read-only hunt identities for telemetry backends.
- Separate analyst, reviewer, connector administrator, and destructive
  administrative permissions.
- Store secret references in a secret manager; never copy credentials into hunt
  records, queries, evidence, screenshots, or exports.
- Require reauthentication or approval for sensitive evidence access where the
  organization's risk model calls for it.

NIST SP 800-53r5 provides a broad control catalog for access control, audit and
accountability, system integrity, incident response, and related safeguards;
apply the organization's selected controls to the hunt service and its data
paths. See [NIST SP 800-53r5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
(accessed 17 July 2026).

### 14.2 Connector and query safety

For any future direct connector:

- maintain an endpoint and protocol allowlist to reduce SSRF and data-exfiltration
  risk;
- validate TLS and pin organizational trust requirements;
- deny write, delete, response, isolation, and configuration APIs by default;
- enforce server-side lookback, row, byte, runtime, concurrency, and export
  limits;
- support cancellation and reliable timeouts;
- isolate tenants and verify authorization again on every object access;
- redact credentials and sensitive values from errors and audit logs;
- record connector, query, actor, scope, and outcome in an immutable audit trail;
  and
- test parsers and converters against malformed and adversarial input.

### 14.3 Privacy and proportionality

Threat telemetry may contain personal, communications, location, or employee
activity data. Collect and expose only what is necessary for the authorized
hypothesis. Define purpose, access, retention, redaction, export, and deletion
rules. Use entity tokens or controlled references when broad collaboration does
not require raw identity. Follow local law, contracts, labor obligations, and
organizational policy; this guide is not legal advice.

### 14.4 Evidence integrity

- Prefer immutable source identifiers or access-controlled evidence packages.
- Hash copied exports and record who collected them, when, from where, and how.
- Preserve raw/normalized distinction and parser version.
- Do not overwrite analyst decisions; append review history.
- Keep incident evidence in the approved case/evidence system when legal hold or
  forensic chain-of-custody requirements apply.

### 14.5 AI boundary

AI may assist with hypothesis drafts, Enterprise ATT&CK candidates, hunt plans,
query translation, organization of analyst-selected finding summaries, and
outcome summaries. Every response is an untrusted suggestion. It must not:

- execute queries or simulations;
- broaden scope or access new data;
- create evidence or claim that a report describes local activity;
- create, review, escalate, or close a finding;
- mark an event malicious or close a hunt;
- invent evidence, source references, ATT&CK versions, or query results;
- publish a detection directly to production; or
- initiate containment or external communication.

Threat Hunting AI uses the local OpenAI-compatible provider by default. Cloud
AI is disabled by default for this feature. An operator must first allow cloud
use, and the analyst must explicitly acknowledge that the bounded assistant
input will leave the deployment before each cloud-backed request is accepted.
Cloud eligibility is still subject to organizational provider, model, data-term,
region, and retention policy.

Provider status deliberately separates three questions that were historically
easy to confuse:

- `configured`: is the required key or private endpoint setting present?
- `available`: do operator policy and local runtime checks permit selection?
- `status` and `reason`: if unavailable, is the cause missing configuration,
  policy, an unreachable local endpoint, authentication, or a missing model?

The platform does not test cloud credentials while rendering the provider
catalog. Eligible remote entries therefore say `configured_and_permitted`, not
`ready`; credential validity, connectivity, and model access are checked on
generation. The platform does perform a bounded local `/models` readiness check
because an endpoint URL alone does not prove a private model server is running.
The self-test integration inventory likewise means *configured*, not live and
policy-approved.

For an isolated Compose-managed Ollama service, set `LOCAL_LLM_MODEL` and run
`make local-ai-up`. The overlay exposes Ollama only inside the Compose network.

`TLP:AMBER+STRICT` and `TLP:RED` assistant inputs are local-only; enabling cloud
AI does not override that rule. `TLP:CLEAR`, `TLP:GREEN`, and `TLP:AMBER` may use
an approved cloud provider only after both gates are satisfied. This also
applies to an unsaved **Plan and scope** draft when it carries an explicit valid
TLP marking; the response remains a suggestion and does not create or save a
hunt. Query, findings, and outcome assistance still require a saved hunt so the
server can use canonical state. A stored report has an authoritative server-side
marking and defaults conservatively to `TLP:AMBER+STRICT`. Only the
`manage_intel` report-edit path may change it. A hypothesis request may raise
the effective marking but cannot lower the stored value; the effective marking
must cover every source and hunt field included in the request.

The label `local` means an operator-configured OpenAI-compatible endpoint. The
operator must verify that its address, hosting, logging, retention, and access
controls satisfy the intended local/private policy; the label alone does not
prove that data stays on the host.

Generated content is marked and linked to provenance metadata. Before a remote
call, the server commits a redacted, correlation-ID-based egress attempt audit;
a matching immutable event records success or a safe failure category. The
events retain provider/model, effective TLP, acknowledgement state, actor, and
input checksum, but no prompt, draft text, raw response, credential, or
exception. A successful generation also creates the append-only assistance
record with the optional hunt and stored-session IDs, task/stage, `suggested`
lifecycle, provider/model, prompt version, effective TLP, sanitized source
references, recorded remote-processing acknowledgement, bounded validated
citations, input/output checksums, structured output, warnings, and actor/time.
It does not retain the raw prompt, full raw report, raw provider response,
credentials, or provider exception. Prompt injection inside a source report
remains possible model input; the fixed task boundary, structured validation,
citations, and human review reduce risk but do not make the output authoritative.

### 14.6 Response boundary

Hunting is read-oriented investigation. Quarantine, account disablement,
blocking, credential rotation, file deletion, or service changes are response
actions and require incident authority. A connector built for hunting should
not inherit response permissions merely for convenience.

## 15. Metrics and maturity

### 15.1 Measure defensive improvement

Prefer metrics that show quality and risk reduction:

- percentage of completed hunts with fit-for-purpose telemetry;
- percentage with reproducible run provenance and peer review;
- critical telemetry gaps opened, aged, and closed;
- validated detection candidates promoted and later tuned;
- time from intelligence trigger to approved hypothesis;
- time from suspicious evidence to incident acceptance;
- recurring hunts run on schedule and reviewed within service level;
- proportion of findings with explicit benign evidence and limitations;
- asset and identity coverage for priority behaviors; and
- ATT&CK content or schema versions requiring remapping.

Avoid rewarding raw query count, total matches, number of ATT&CK techniques, or
the percentage of hunts that “found something.” Those measures encourage broad
queries and confirmation bias.

### 15.2 A five-level maturity model

| Level | Characteristics | Next improvement |
|---|---|---|
| 1 — Reactive | Ad hoc searches, limited provenance, alert-driven pivots | Standard hypothesis, scope, and result templates |
| 2 — Repeatable | Owned backlog, basic data checks, saved analytics, documented outcomes | Version queries and formalize review/gap tracking |
| 3 — Governed | Role separation, bounded execution, evidence references, defined cadence and metrics | Integrate telemetry owners, detection lifecycle, and incident handoff |
| 4 — Measured | Coverage and quality metrics, recurring hunts, validation, schema governance | Automate safe readiness checks and feedback loops |
| 5 — Adaptive | Intelligence, risk, telemetry, detection, incidents, and validation continuously reprioritize hunting | Preserve human accountability while improving assisted analysis |

### 15.3 Common failure modes

- starting with a favorite query instead of a hypothesis;
- mapping an actor name directly to local compromise;
- treating data-source configuration as proof of event coverage;
- using legacy ATT&CK Data Source or Defense Evasion terminology for new v19
  records;
- mutating query text without retaining versions;
- equating no matches with no intrusion;
- counting every raw row as a finding;
- suppressing benign activity without owner or expiry;
- allowing hunt credentials to perform response actions;
- moving AI-generated content to production without review; and
- closing a hunt without owners for gaps and follow-up work.

## 16. Twenty worked hunt playbooks

The following playbooks are starting points. Each must be adapted to the local
environment and peer reviewed. Field names are illustrative; map them to a
pinned OCSF, ECS, or native schema. Links point to the current official ATT&CK
technique pages, which should be checked again when ATT&CK content changes.
Platform-specific recordkeeping examples are maintained in the separate
[AdversaryGraph operator guide](threat-hunting-with-adversarygraph.md).

### 16.1 Encoded or obfuscated PowerShell execution

**Question and hypothesis.** An adversary may use PowerShell with encoded
arguments, runtime decoding, or an unusual process chain to execute a payload on
managed Windows endpoints. If so, endpoint process and script telemetry should
show the interpreter, decode behavior, initiating context, and follow-on file,
process, or network activity.

**ATT&CK v19.** Map supported behavior to
[T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001/) under
Execution and, only when obfuscation is evident,
[T1027 Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
under Stealth.

**Minimum telemetry.** Process creation and EDR process ancestry; PowerShell
Script Block Logging where policy permits; file and network events linked to the
process entity. Required fields include event time, host, user/session, process
and parent entity IDs, executable path, command line, integrity level, signer or
hash, script-block ID/text or protected reference, destination, and sensor
health.

**Candidate analytic.**

```text
FROM process_start OR powershell_script
WHERE interpreter is PowerShell
  AND (encoded flag OR decode primitive OR high-entropy/obfuscated content)
GROUP BY host, user, process_entity
ENRICH parent_chain, signer, prevalence, change_window
```

**Procedure.**

1. Confirm which PowerShell hosts and versions are expected and whether
   script-block, module, and process logging covered the requested assets and interval.
2. Run a 24-hour volume preflight for encoded flags and decode primitives. Split
   interactive users, service accounts, deployment systems, and security tools.
3. Decode content only in an approved analysis environment; preserve the
   original event reference and hash, and do not execute recovered content.
4. Review the full process ancestry. Prioritize Office, browser, archive tool,
   web service, or first-seen unsigned parents over known management agents.
5. Pivot 10 minutes before and after by process entity, host, and user. Inspect
   child processes, file writes, DNS, connections, registry changes, and
   authentication events.
6. Compare command, signer, path, account, target group, and schedule with
   approved automation. Obtain the related change record rather than relying on
   a name-based allowlist.
7. Cluster identical commands across hosts. A widespread, scheduled, signed
   management action may be benign; a single rare chain on a high-value host may
   be more important.
8. Create one finding per related execution chain. Reference raw events and
   record the decoded behavior as analyst-derived evidence, not as raw fact.

**Triage and decision.** Supporting evidence includes an unusual parent,
download or credential access, a first-seen destination, unexpected privilege,
or tampering with logging. Counter-evidence includes a verified deployment
record and stable historical pattern. Missing script telemetry narrows the
claim; it does not make the process event benign. Escalate unauthorized execution
with credible follow-on behavior. Otherwise close as `benign` with evidence, or
as `telemetry_gap` if content visibility was essential.

**Safe validation.** Use inert encoded text in an isolated endpoint lab and
verify process, script, and downstream event correlation. Do not use a live
payload or bypass controls in production.


### 16.2 Access to LSASS memory or credential-dump artifacts

**Question and hypothesis.** An adversary may access LSASS memory or create a
dump to obtain credentials. If this occurred, process-access, file, process,
driver, and subsequent authentication telemetry should reveal an unusual actor,
access relationship, dump artifact, or credential-use sequence.

**ATT&CK v19.** Use
[T1003.001 OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
under Credential Access when evidence specifically concerns LSASS memory.

**Minimum telemetry.** EDR or Sysmon-like process access, Windows security and
process creation, image load/driver telemetry where available, file creation,
sensor health, and identity authentication. Required fields include source and
target process entities, access rights, user, integrity level, signer/hash,
file path/hash, host, and event/ingest time.

**Candidate analytic.**

```text
FROM process_access OR file_create OR process_start
WHERE target_process is LSASS
   OR file name/path resembles a process dump created near LSASS access
EXCLUDE only scoped, signed, verified security/diagnostic baselines
CORRELATE subsequent authentication by host, account, and time
```

**Procedure.**

1. Verify endpoint sensor coverage and whether the product exposes source-target
   access rights. A plain process list is not sufficient to answer the
   hypothesis.
2. Build a baseline of products that legitimately access LSASS: EDR, identity,
   backup, crash diagnostics, and approved support tools. Record signer, path,
   service identity, version, and expected hosts.
3. Search for LSASS access outside that baseline, unexpected dump utilities,
   suspicious DLL or driver loads, and `.dmp` files in user-writable or temporary
   paths.
4. Review the full initiating process tree and the account's privilege. Check
   whether the process was remotely created, launched by a service, or preceded
   by privilege escalation.
5. Pivot to file deletion, archive creation, network transfer, and log or sensor
   impairment on the same host.
6. Review authentication after the event for new source hosts, privileged logon
   types, remote service use, or access inconsistent with the account baseline.
7. Validate any claimed legitimate tool with inventory, signature, package
   source, configuration, and a change or support record.
8. Preserve access-event and artifact references; do not collect or open a live
   memory dump outside the approved forensic process.

**Triage and decision.** Unexpected LSASS access by an unsigned or user-writable
binary, a dump artifact, and follow-on credential use is an urgent escalation.
A verified security product may be benign, but a changed signer/path or
first-seen version warrants review. If the endpoint product does not expose process
access or coverage was absent, use `telemetry_gap` rather than `no_matches`.

**Safe validation.** Use vendor-provided benign test events or an approved lab
fixture that exercises the sensor without extracting real credentials. Validate
event fields and analytic logic, not credential theft.


### 16.3 Periodic DNS or TLS command-channel behavior

**Question and hypothesis.** A compromised host may use repeated low-volume DNS
or TLS connections to rare infrastructure as a command channel. The data should
show periodicity, destination rarity, stable client characteristics, and an
initiating process or host context inconsistent with normal software.

**ATT&CK v19.** Relevant mappings include
[T1071.004 Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)
and
[T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
under Command and Control. Periodicity by itself does not establish either
technique.

**Minimum telemetry.** Resolver or DNS sensor logs, proxy/TLS/firewall/flow data,
endpoint network-to-process linkage, DHCP/NAT/VPN attribution, and asset
inventory. Useful fields include source entity/IP, query name/type/result,
destination IP/port, certificate or TLS fingerprint, bytes, process entity,
event time, and action/result.

**Candidate analytic.**

```text
GROUP connections BY source_entity, destination_domain_or_ip
CALCULATE event_count, interarrival_distribution, jitter, bytes, active_hours,
          domain_prevalence, first_seen, process_prevalence
WHERE repeated AND low_jitter AND rare_destination
RANK WITH endpoint/process and asset criticality context
```

**Procedure.**

1. Establish whether DNS is logged at the endpoint, resolver, network sensor, or
   all three. Account for encrypted DNS and clients using external resolvers.
2. Resolve source IPs to devices over time using DHCP, NAT, VPN, and cloud
   metadata. Do not assign 1 week of traffic to today's IP owner.
3. Calculate inter-arrival intervals per source and destination over at least
   several expected beacon cycles. Record missing intervals and log delays.
4. Rank low-jitter, low-volume relationships by destination and process rarity,
   new registration or first-seen time when available, and asset criticality.
5. Compare candidates with known update, monitoring, messaging, VPN, browser,
   certificate, and cloud-service patterns. Check maintenance schedules and
   fleet-wide prevalence.
6. Pivot from the domain to resolved IPs, certificates, related domains, proxy
   requests, flow bytes, and endpoint processes. Treat reputation as context,
   not a verdict.
7. Inspect activity immediately before the relationship began: new process,
   service, scheduled task, file, login, or software install.
8. Record the statistical method, interval, threshold, and completeness. A
   screenshot of a periodic chart is not reproducible evidence without the
   underlying run reference.

**Triage and decision.** A rare destination plus a rare unsigned process and
coincident persistence strongly supports escalation. A fleet-wide signed update
agent with a known owner is likely benign. If endpoint attribution or
encrypted-DNS visibility is absent, state the blind spot. Tune with scoped, expiring
software identities rather than permanent domain allowlists.

**Safe validation.** Generate harmless scheduled requests to a controlled lab
domain and verify the expected DNS, TLS, flow, and process evidence. Do not test
covert channels through production networks.


### 16.4 Valid-account abuse in cloud or identity systems

**Question and hypothesis.** An adversary may use a valid account from a new
device or network and perform privilege, credential, persistence, or resource
access inconsistent with the identity's history. Identity and cloud audit logs
should reveal the full authentication and action sequence.

**ATT&CK v19.** Use
[T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) with the
supported current tactic relationship: Initial Access, Persistence, Privilege
Escalation, or Stealth (accessed 17 July 2026). Add more specific techniques
only when the subsequent behavior supports them.

**Minimum telemetry.** Identity-provider sign-ins, MFA events, conditional-access
decisions, device and session context, cloud control-plane audit,
privilege changes, mailbox or application audit where relevant, VPN, and asset
inventory. Required fields include immutable user ID, application/resource,
source IP and network, device ID/trust, authentication factors, result and
reason, session/token ID, role, action, and event/ingest time.

**Candidate analytic.**

```text
FROM successful_authentication
WHERE new_device_or_network OR atypical_country_or_ASN OR unusual_factor_sequence
FOLLOWED WITHIN risk_window BY
  role_change OR credential_change OR persistence_change OR atypical_resource_access
GROUP BY immutable_identity, session, source_context
```

**Procedure.**

1. Define peer and individual baselines using immutable identity IDs, not
   display names. Document VPN, mobile carrier, shared egress, travel, and
   break-glass exceptions.
2. Verify that “success” represents completed authentication and distinguish
   interactive, non-interactive, refresh-token, workload, and legacy flows.
3. Search for first-seen device/network/factor combinations, impossible or
   implausible session overlap, repeated failures followed by success, and risky
   sign-in decisions.
4. Correlate the session or nearest supported identifier to role, credential,
   consent, forwarding, access-policy, application, storage, and secret actions.
5. Compare accessed resources, time of day, client application, and action
   sequence with the identity and peer baseline.
6. Validate travel, device replacement, automation, or administrative change
   using independent asset and change records. Do not contact the potentially
   compromised account through an untrusted channel.
7. Pivot to other identities using the same source, device, application,
   credential, or infrastructure and to the same identity's activity in other
   tenants or services.
8. Escalate via the identity/cloud incident playbook when high-risk actions are
   unexplained; let authorized responders decide on token revocation, password
   reset, or session termination.

**Triage and decision.** A new source alone is weak. A new source plus unusual
factor sequence and privileged follow-on actions is materially stronger.
Incomplete non-interactive or control-plane logs require a narrowed conclusion.
Record whether location is inferred from IP and its known uncertainty.

**Safe validation.** Use a designated test identity and approved tenant to
generate a new-device sign-in and benign role-change fixture. Never weaken MFA
or conditional access in production to test the analytic.


### 16.5 Unexpected scheduled-task persistence

**Question and hypothesis.** An adversary may create or modify a Windows
scheduled task to persist or execute tooling. Task Scheduler, process, file, and
registry evidence should reveal the creator, task definition, action, and
follow-on execution.

**ATT&CK v19.** Map supported behavior to
[T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
under Execution, Persistence, and/or Privilege Escalation as appropriate.

**Minimum telemetry.** Task Scheduler operational and security logs, process
creation, EDR process ancestry, task files or registry changes, file metadata,
and change/deployment inventory. Fields include host, task name/path, creator,
principal, trigger, action, command, run level, process entity, file hash/signer,
result, and time.

**Candidate analytic.**

```text
FROM task_created OR task_modified OR task_started
WHERE new_or_changed_task
  AND (user_writable_action_path OR interpreter_action OR unusual_principal
       OR hidden_or_rare_task OR creation_tool_outside_baseline)
CORRELATE creator_process AND later_task_execution
```

**Procedure.**

1. Confirm task creation/modification and execution events are collected, not
   just periodic task inventory.
2. Build a scoped baseline by product, task path, signer, principal, target
   population, deployment owner, and expected creation method.
3. Search new and modified tasks, emphasizing hidden tasks, unusual folders,
   user-writable action paths, interpreters, remote paths, highest privileges,
   and tasks created outside change windows.
4. Review the creating process, remote session, account, and authentication
   context. Determine whether the XML or task definition differs from the
   approved baseline.
5. Pivot to the referenced executable or script: origin, hash, signer,
   prevalence, write time, and network activity.
6. Correlate scheduled executions with child processes, failures, outbound
   connections, and file or registry changes.
7. Confirm legitimate deployment or maintenance with the owning team and change
   record. Give allowlist entries an owner and expiry.
8. Preserve task definition and event references before an authorized responder
   modifies the task.

**Triage and decision.** A task created remotely by an unexpected privileged
identity and pointing to a new user-writable binary merits escalation. A known
task name alone is not enough; adversaries can imitate it. If only current
inventory exists, state that deleted or short-lived tasks may not be visible.

**Safe validation.** Create an inert task in a disposable Windows lab through
the approved simulation workflow and verify creation, execution, and cleanup
telemetry.


### 16.6 Web-shell behavior on an internet-facing server

**Question and hypothesis.** A compromised web application may execute a web
shell, causing a web service process to spawn a shell/interpreter, write
executable server-side content, or initiate unusual outbound traffic. Web,
endpoint, file-integrity, and network evidence should form a consistent chain.

**ATT&CK v19.** Use
[T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
under Persistence when supported, and
[T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
for evidenced command execution.

**Minimum telemetry.** Web access/error or application gateway logs, WAF,
process ancestry, file create/modify, file integrity, authentication, and
network-to-process data. Required fields include request ID, method/path/status,
source, virtual host, application or pool identity, process entities, command,
file path/hash, destination, and event/ingest time.

**Candidate analytic.**

```text
FROM process_start OR file_change OR web_request
WHERE web_service_process SPAWNS shell_or_interpreter
   OR web_service_identity WRITES executable_content INTO served_or_temp_path
CORRELATE request_id_or_time, host, process_tree, file, destination
```

**Procedure.**

1. Inventory web runtimes, worker-process names, application pools, deployment
   paths, management consoles, and legitimate child processes.
2. Verify endpoint visibility on the actual workload type—host, VM, container,
   or managed service—and document serverless or platform blind spots.
3. Search web service parents spawning shells, interpreters, discovery tools,
   download utilities, or archive tools. Include unexpected outbound
   connections from the web identity.
4. Search new or changed executable server-side files and compare hashes and
   paths with the signed or approved deployment manifest.
5. Correlate process/file events to web requests using request or trace IDs;
   otherwise use a narrow time window and state the weaker relationship.
6. Review source, method, URI, status, user agent, authentication, WAF decision,
   and neighboring requests. Avoid treating a suspicious URL string alone as
   execution evidence.
7. Pivot backward to exploitation evidence and forward to credentials, new
   accounts, services/tasks, lateral movement, staging, and outbound transfer.
8. Preserve volatile and file evidence through the incident process before
   remediation. Do not browse to or execute a suspected web shell.

**Triage and decision.** A web worker spawning a shell and writing a new script
with correlated requests is a high-priority escalation. Deployment systems and
administrative consoles can create similar chains; verify package and change
provenance. Managed-service gaps should be tracked rather than filled with
unsupported assumptions.

**Safe validation.** Use an isolated attack-lab web target and inert test
commands designed for telemetry validation. Keep the target unreachable from
production and follow the platform's simulation boundaries.


### 16.7 Remote-service lateral movement

**Question and hypothesis.** An adversary with credentials may use RDP, SMB,
SSH, WinRM, or another remote service to move from one managed system to
another. Authentication, network, endpoint, and service telemetry should reveal
an unusual source-target-account relationship and remote execution context.

**ATT&CK v19.** Use the supported sub-technique of
[T1021 Remote Services](https://attack.mitre.org/techniques/T1021/), such as
[T1021.001 RDP](https://attack.mitre.org/techniques/T1021/001/),
[T1021.002 SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/),
[T1021.004 SSH](https://attack.mitre.org/techniques/T1021/004/), or
[T1021.006 WinRM](https://attack.mitre.org/techniques/T1021/006/), under Lateral
Movement.

**Minimum telemetry.** Source and target authentication, network flow/firewall,
RDP/SMB/SSH/WinRM service events, endpoint process and logon/session telemetry,
identity privilege, and asset role/criticality. Fields include source and target
entities, immutable account ID, protocol/service, logon/session ID, result,
authentication method, process, share or command context, and time.

**Candidate analytic.**

```text
FROM successful_remote_authentication OR remote_service_session
WHERE new_source_target_account_edge
   OR peer_group_violation
   OR service_account_interactive_use
CORRELATE target_process_or_service_activity WITH session/account/time
```

**Procedure.**

1. Build an allowed administrative-path baseline from network segmentation,
   jump hosts, management tooling, service-account policy, and asset roles.
2. Verify both successful and failed authentication collection on source and
   target. Resolve NAT, bastion, and load-balancer effects.
3. Model source-target-account edges over an appropriate baseline period. Rank
   first-seen edges, workstation-to-server movement, peer server movement,
   service-account interactive use, and access outside maintenance windows.
4. Confirm the protocol and session, then inspect target-side process creation,
   service/task activity, share access, shell commands, or file writes.
5. Pivot backward on the source host for credential access, unusual login,
   exploit, or tool transfer. Pivot forward to additional targets using the same
   identity or source.
6. Compare with change tickets, help-desk sessions, orchestration jobs, and
   administrator rosters. Verify the actual operator through an approved channel.
7. Build a graph of the movement sequence with event times and confidence; do
   not infer a direct edge when only shared egress is known.
8. Escalate unexplained privileged movement or a multi-host chain. Let incident
   responders decide containment so evidence and business operations are not
   disrupted prematurely.

**Triage and decision.** A new edge is a lead, not a finding by itself. New
privileged access followed by remote process execution and tool transfer is much
stronger. If target endpoint logging is missing, authentication may establish a
session but not what occurred within it; record that limitation.

**Safe validation.** Use designated lab hosts and a test identity to establish
one approved remote session, then verify source, network, target, and process
correlation. Do not scan or authenticate broadly in production.


### 16.8 Cloud account manipulation and added privileges

**Question and hypothesis.** An adversary may modify a cloud identity by adding
credentials, roles, group membership, federation, device registration, or other
access that survives the original session. Identity and control-plane audit logs
should identify the actor, target identity, change, authorization path, and
subsequent use.

**ATT&CK v19.** Map supported behavior to
[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) under
Persistence and/or Privilege Escalation. When evidence is specific, use a
sub-technique such as
[T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
or
[T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/).

**Minimum telemetry.** Identity directory audit, cloud control-plane audit,
privileged-access management, application/credential inventory, device
registration, policy changes, authentication, and ticket/change records. Fields
include immutable actor and target IDs, action, old/new value or diff, role,
resource, credential/application/device ID, authorization result, source,
request/session ID, and time.

**Candidate analytic.**

```text
FROM identity_or_role_change
WHERE credential_added OR role_added OR group_added OR federation_changed
   OR device_registered OR recovery_method_changed
RANK BY target_privilege, actor_rarity, source_novelty, change_window
CORRELATE subsequent_authentication_or_privileged_action
```

**Procedure.**

1. Inventory privileged roles, emergency accounts, service principals,
   federated trusts, allowed credential types, and approved provisioning systems.
2. Confirm audit logs include both successful and attempted changes and preserve
   old/new values. Note providers that expose only current state.
3. Search additions and modifications outside the approved provisioning path,
   especially self-assignment, direct permanent grants, dormant-account changes,
   and credentials with long expiry.
4. Resolve the initiating actor, source, device, session, and authorization
   mechanism. Determine whether the actor had normal responsibility for the
   target.
5. Correlate backward to risky sign-in, token activity, privilege activation, or
   application consent; correlate forward to use of the new role, credential, or
   device.
6. Compare with change, onboarding, break-glass, infrastructure-as-code, and
   access-review records. Validate automation by immutable application ID and
   deployment context, not display name.
7. Review whether the change was later removed and by whom. Removal reduces
   current exposure but does not make the original action benign.
8. Escalate unauthorized privilege or credential persistence. Authorized
   responders, not hunt queries, should remove access and revoke sessions.

**Triage and decision.** An unplanned permanent role assigned by a newly seen
session, followed by use, strongly supports compromise. A known provisioning
application with an approved request may be benign. Missing old/new values or
short retention can leave the hunt inconclusive even if current configuration
looks normal.

**Safe validation.** Use a disposable test role and identity in a non-production
tenant. Verify audit, authentication, and analytic correlation, then remove the
fixture through the approved administrative process.


### 16.9 Ingress tool transfer followed by execution

**Question and hypothesis.** An adversary may transfer a tool or payload to a
host and execute it shortly afterward. Network, proxy, file, process, and
reputation evidence should connect the source, transferred object, destination
path, and execution chain.

**ATT&CK v19.** Use
[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) under
Command and Control when the transfer behavior is supported. Add the observed
execution technique separately rather than assuming it.

**Minimum telemetry.** Proxy or network gateway, endpoint network-to-process,
DNS, file creation/download metadata, process ancestry, browser or email
download context when applicable, and software inventory. Fields include URL or
source, destination, initiating process, bytes/hash, file path, zone or origin
metadata, signer, process entity, user, host, and time.

**Candidate analytic.**

```text
SEQUENCE BY host, user, file_hash_or_path WITHIN 30m
  [network_download OR file_written_from_remote_source]
  [file_executed OR interpreter_reads_file]
WHERE source_or_file_is_rare OR path_is_user_writable OR signer_is_untrusted
```

**Procedure.**

1. Confirm which download paths preserve URL, referrer, message, browser, or
   process attribution and where TLS inspection or endpoint linkage is absent.
2. Baseline approved package managers, software distribution, update agents,
   developer repositories, and administrative transfer tools.
3. Search first-seen or rare downloads to executable/script/archive formats,
   unusual content types, user-writable paths, and transfers initiated by a
   shell, service, document process, or uncommon client.
4. Join file events using hash where possible. If joining by path and time,
   record the weaker confidence and account for path reuse.
5. Review signer, origin, prevalence, package source, reputation, and static
   metadata without executing the file.
6. Correlate execution, child processes, persistence, network connections, and
   credential or discovery behavior. Determine whether the downloaded object
   itself ran or was unpacked into another object.
7. Validate legitimate software deployment with an approved package manifest,
   owner, target population, and change window.
8. Preserve the file hash and evidence reference. Acquisition of the binary for
   malware analysis must follow quarantine and evidence-handling policy.

**Triage and decision.** Download plus execution from a rare source by an
unexpected parent is stronger than either event alone. Developer systems may
legitimately fetch and run rare files, so use role and package context. Missing
network attribution may allow a conclusion about execution but not transfer
origin.

**Safe validation.** Transfer a harmless signed fixture in an isolated lab and
verify URL/process/file/hash/execution correlation. Do not retrieve a known
malicious sample into production.


### 16.10 Burst of host, account, and network discovery

**Question and hypothesis.** After gaining execution, an adversary may rapidly
enumerate system, account, domain, and neighboring host information. Process,
script, shell, and audit data should show a rare sequence or burst inconsistent
with the user's role and normal administration.

**ATT&CK v19.** Map only observed behaviors, such as
[T1082 System Information Discovery](https://attack.mitre.org/techniques/T1082/),
[T1087 Account Discovery](https://attack.mitre.org/techniques/T1087/), and
[T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018/),
under Discovery.

**Minimum telemetry.** Endpoint process and command/script telemetry, shell
history or audit where authorized and reliable, directory queries, network flow,
and asset/identity roles. Fields include process ancestry, command or API action,
host, user/session, target, result, integrity, signer, and event time.

**Candidate analytic.**

```text
WINDOW 10m BY host, user, session_or_parent_process
COUNT DISTINCT discovery_categories and commands/APIs
WHERE categories >= threshold
  AND initiating_context_outside_admin_or_inventory_baseline
```

**Procedure.**

1. Define behavioral categories—system, account, domain, network, security
   product, share, and process discovery—rather than relying only on command
   names.
2. Verify command-line/script visibility and note APIs or built-in tools that the
   current telemetry cannot distinguish.
3. Baseline inventory, configuration management, vulnerability scanners,
   support tooling, developers, and administrators by signer, parent, account,
   schedule, and target population.
4. Aggregate distinct discovery categories within a short window, grouped by
   session or parent process when possible. Rank new combinations and high-value
   targets.
5. Inspect the first process in the burst. A document, browser, web service, or
   newly downloaded tool is more concerning than a signed management agent.
6. Pivot backward to initial access, exploitation, or unusual authentication and
   forward to remote services, credential access, staging, or tool transfer.
7. Compare exact schedule and targets with the responsible administrative or
   scanning owner. A generic “IT activity” label is not enough.
8. Record each evidenced technique separately and connect them through the
   shared process/session timeline.

**Triage and decision.** Discovery commands are often legitimate. Sequence,
initiating context, target choice, and follow-on behavior determine importance.
If command-line collection is incomplete, do not claim the absence of discovery
through APIs, scripts, or remote services.

**Safe validation.** Replay synthetic process-event fixtures or use approved,
non-invasive inventory commands on lab systems. Do not enumerate production
networks merely to test the rule.


### 16.11 Security-tool disablement or configuration impairment

**Question and hypothesis.** An adversary may disable, reconfigure, exclude,
uninstall, or tamper with defensive tooling to reduce visibility. Control-plane,
endpoint, service, policy, and sensor-health data should reveal the actor,
change, affected control, and resulting health degradation.

**ATT&CK v19.** Use
[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)
under the current **Defense Impairment** tactic (accessed 17 July 2026). The
older `T1562.001` mapping is revoked in v19; do not copy it into a new record or
label the behavior with the legacy Defense Evasion tactic. T1685 has
sub-techniques, including
[T1685.001 Disable or Modify Windows Event Log](https://attack.mitre.org/techniques/T1685/001/)
(accessed 17 July 2026) and
[T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/)
(accessed 17 July 2026). Map to the most specific sub-technique the evidence
supports, consistent with Section 7.4; retain the parent-level T1685 mapping when
the evidence does not justify a narrower mapping.

**Minimum telemetry.** EDR/AV administrative audit, policy changes, endpoint
process and service events, agent uninstall/tamper events, sensor health and
heartbeat, identity/privilege, and change management. Fields include actor,
action, target control, old/new policy, exclusion, endpoint, result, session,
process, health state, and event/ingest time.

**Candidate analytic.**

```text
FROM security_control_change OR service_change OR sensor_health
WHERE protection_disabled OR exclusion_added OR agent_stopped_or_removed
   OR policy_weakened OR heartbeat_lost_after_suspicious_action
EXCLUDE scoped approved changes with immutable change context
```

**Procedure.**

1. Inventory all ways controls can be changed: product console, local command,
   API, policy object, service manager, package removal, registry/config file,
   and cloud security setting.
2. Confirm the administrative audit itself is centrally protected. Local logs
   alone may disappear when the tool is impaired.
3. Search disable, exclusion, uninstall, tamper, policy downgrade, and
   service-state events. Separately analyze heartbeat loss; outages and network failures
   can cause the same symptom.
4. Resolve actor, source, privilege activation, session, and approval. Review the
   process tree for local changes.
5. Correlate policy changes to affected assets and actual sensor-health changes.
   Determine whether the change succeeded and how long it remained active.
6. Pivot backward to unusual login, exploit, tool transfer, or privilege change
   and forward to credential access, movement, collection, or impact.
7. Validate maintenance and troubleshooting through change records and product
   owners. Check whether the scope exceeded the request.
8. Escalate unexplained successful impairment immediately; responders should
   restore protection through an approved path while preserving evidence.

**Triage and decision.** A failed disable attempt is still meaningful evidence
but has different impact from a successful, fleet-wide policy change. A missing
heartbeat without a change event is suspicious but not proof of impairment.
Record central-log gaps as high-value remediation items.

**Safe validation.** Use vendor-supported test controls or a disposable lab
sensor. Never disable production defenses or add real exclusions to prove the
analytic.


### 16.12 Recovery inhibition and ransomware-impact sequence

**Question and hypothesis.** Before or during ransomware impact, an adversary
may inhibit recovery and then cause widespread file encryption or destructive
modification. Endpoint, backup, storage, process, and file telemetry should show
the recovery change, initiating context, affected population, and impact
sequence.

**ATT&CK v19.** Use
[T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
and, when supported,
[T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
under Impact. Do not infer encryption solely from a recovery-setting change.

**Minimum telemetry.** Process and command/script telemetry, backup platform
audit, shadow-copy/recovery configuration, storage and file-change telemetry,
endpoint health, identity privilege, and asset criticality. Fields include actor,
host/resource, action/result, backup object, process chain, file operation counts
and extensions, bytes, entropy signal if used, and time.

**Candidate analytic.**

```text
SEQUENCE BY host_or_tenant WITHIN 2h
  [recovery_or_backup_disabled_or_deleted]
  [high_rate_file_rewrite_or_rename OR storage_snapshot_deletion]
RANK BY privileged_actor, host_count, criticality, first_seen_process
```

**Procedure.**

1. Inventory backup, snapshot, recovery, and retention controls by platform,
   including legitimate maintenance and disaster-recovery tests.
2. Confirm audit visibility for both control-plane actions and local recovery
   commands; verify that backup logs are isolated from the protected workload.
3. Search snapshot, catalog, recovery, backup-agent, retention, and service
   changes outside approved workflows. Record whether each action succeeded.
4. Identify the actor, session, source, and process chain. Check for recent
   privilege changes, unusual remote access, or tool transfer.
5. Measure file or object change rate by host/share/bucket and process. Compare
   with backup, indexing, build, migration, and bulk-maintenance baselines.
6. Correlate across assets for a common identity, binary hash, destination,
   command, or start time. Prioritize simultaneous activity on critical systems.
7. Look backward for defense impairment, credential access, and lateral movement;
   look forward for ransom notes, service outages, or destructive actions.
8. Escalate immediately when recovery inhibition and unexplained bulk impact
   align. Preserve logs outside affected systems and follow the ransomware
   response plan.

**Triage and decision.** Backup deletion is high impact but may be authorized.
High file churn may be migration or build activity. The combined, unauthorized
sequence with common initiating context is the stronger signal. Endpoint-only
visibility cannot prove cloud or appliance backup state.

**Safe validation.** Use synthetic file-event fixtures and a disposable lab
snapshot. Do not delete production backups or encrypt production data.


### 16.13 Archive creation and data staging

**Question and hypothesis.** An adversary may collect and archive data into a
staging location before exfiltration. Process, file, object-access, and storage
telemetry should reveal unusual input scope, archive creation, staging path,
actor, and subsequent movement.

**ATT&CK v19.** Use
[T1560.001 Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)
under Collection when a utility or equivalent archive behavior is evidenced.

**Minimum telemetry.** Process/command/script telemetry, file and directory
access where proportionate, archive/file creation, DLP or storage audit, endpoint
network linkage, and asset/data classification. Fields include process chain,
user, input paths or resource scope, output path/hash/size, file counts, labels,
destination, and time.

**Candidate analytic.**

```text
FROM archive_process_or_archive_file_creation
WHERE output_path_is_staging_like OR input_scope_is_unusual
   OR archive_size/count_exceeds_peer_baseline OR encryption_option_used
CORRELATE subsequent_upload, transfer, deletion, or removable_media_activity
```

**Procedure.**

1. Define approved archive workflows for backup, development, deployment,
   records, support, and user productivity. Include path, tool, owner, schedule,
   and expected size.
2. Verify which sources expose archive command arguments, input files, output
   size, encryption, and subsequent transfer. Avoid collecting unnecessary file
   contents.
3. Search rare archive tools, user-writable or temporary staging paths, unusual
   extensions, password/encryption options, and large or rapid archive creation.
4. Review the process parent, user/session, privilege, host role, and input data
   classification. A common utility invoked by an unusual parent is significant.
5. Compare volume, time, and target paths with the entity's baseline and peer
   group. Consider build artifacts and log rotation.
6. Correlate to file discovery, share access, database export, screenshot or
   collection activity before staging.
7. Correlate forward to cloud uploads, email, network transfer, removable media,
   deletion, or cleanup. Keep collection and exfiltration decisions separate.
8. Preserve metadata and evidence references. Access archive contents only under
   incident and privacy procedures.

**Triage and decision.** An encrypted archive in a temporary path followed by a
rare outbound upload is more concerning than archive creation alone. Missing
file-access telemetry may prevent identifying the data collected even when the
archive event is clear.

**Safe validation.** Archive non-sensitive synthetic files in a lab and verify
process, file, size, and transfer correlation without using real organizational
data.


### 16.14 Exfiltration to personal or rare cloud storage

**Question and hypothesis.** An adversary or malicious insider may upload
sensitive data to a personal or unusual cloud-storage service. Proxy, CASB/SSE,
endpoint, DLP, identity, and storage events should connect the actor, source
data, destination account/service, volume, and initiating process.

**ATT&CK v19.** Use
[T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002/)
under Exfiltration when the transfer to cloud storage is supported.

**Minimum telemetry.** Secure web gateway or proxy, CASB/SSE, DNS/TLS/flow,
endpoint network-to-process, DLP, identity, cloud application discovery, and
data classification. Useful fields include user/device, destination service and
tenant/account when available, URL category, action, bytes, process, file label
or hash token, session, result, and time.

**Candidate analytic.**

```text
FROM outbound_web_upload
WHERE cloud_storage_service
  AND (personal_or_unmanaged_tenant OR rare_service OR unusual_volume)
CORRELATE source_process, archive_or_file_access, identity, data_label
```

**Procedure.**

1. Define sanctioned services, managed tenants, permitted user groups, and
   data-handling policy. A domain allowlist alone cannot distinguish corporate and
   personal accounts.
2. Verify whether the telemetry distinguishes uploads from downloads and exposes
   destination tenant/account. Document encrypted or unmanaged-device blind
   spots.
3. Establish per-user and peer baselines for upload volume, service, time, and
   initiating application. Account for backup and collaboration clients.
4. Search personal/unmanaged tenant use, first-seen storage services, large or
   bursty uploads, unusual hours, and command-line or archive-tool initiated
   traffic.
5. Correlate with recent archive creation, bulk file access, database export,
   removable-media events, or classification/DLP matches.
6. Confirm identity and device through session and endpoint evidence. Do not
   attribute shared proxy egress directly to a user without supporting data.
7. Review approved business workflows, migrations, support transfers, and
   data-protection exceptions with their owners.
8. Escalate unexplained sensitive-data transfer through insider-risk or incident
   processes as policy requires. Avoid downloading the remote content during the
   hunt.

**Triage and decision.** Volume alone is weak; managed-tenant state, data label,
source process, user role, and preceding collection materially improve the
assessment. If account-level destination data is unavailable, say that the
service was observed but personal ownership was not established.

**Safe validation.** Use non-sensitive synthetic files and a designated test
tenant under DLP/CASB policy. Never upload real sensitive data to a personal
service for validation.


### 16.15 Suspicious OAuth application consent or token use

**Question and hypothesis.** An adversary may obtain application consent, add an
application credential or role, steal an application token, or use a token from
unexpected infrastructure to access cloud resources. Identity, consent,
application, token, and resource audit should show the grant or credential,
principal, permissions, session context, and subsequent use.

**ATT&CK v19.** Depending on the evidence, use
[T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
under Credential Access,
[T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) for
credential/role persistence, or
[T1550.001 Use Alternate Authentication Material: Application Access Token](https://attack.mitre.org/techniques/T1550/001/)
when token use is supported. Do not infer token theft from a consent grant alone.

**Minimum telemetry.** Identity-provider consent and directory audit,
application/service-principal inventory, credential and role changes, token and
sign-in logs, cloud/application resource audit, and approved-app catalog. Fields
include application and service-principal IDs, publisher/verification, actor,
target, permission/scope, consent type, credential ID/expiry, token/session ID,
source/device, resource, action/result, and time.

**Candidate analytic.**

```text
FROM app_consent OR app_credential_change OR app_role_assignment OR app_signin
WHERE high_risk_permission OR unverified_or_new_app OR rare_actor
   OR new_credential OR token_used_from_new_source
CORRELATE grant_or_change TO later_resource_access BY immutable_app/principal IDs
```

**Procedure.**

1. Inventory sanctioned applications, immutable IDs, verified publishers,
   owners, approved permissions, credential rotation, and expected source
   infrastructure.
2. Confirm whether tenant-wide and user consent, application credentials,
   delegated/application permissions, and non-interactive sign-ins are all
   logged.
3. Search new consents, high-impact scopes, tenant-wide grants, new secrets or
   certificates, role assignments, and changes made outside the approved
   deployment path.
4. Resolve the consenting or modifying actor, source, device, authentication
   method, privilege activation, and session risk.
5. Correlate the application/principal ID to token use and resource actions.
   Look for first-seen source networks, unusual tenants, mailbox/file access,
   directory enumeration, or access beyond the application's baseline.
6. Validate the exact immutable IDs, owner, code/deployment provenance, and
   change request. Display names and publisher text can be imitated.
7. Check credential age, expiry, and whether the observed key matches inventory.
   Distinguish a legitimate rotation from an extra untracked credential.
8. Escalate unauthorized grants, credentials, or token use. Authorized cloud
   responders should revoke grants/tokens and preserve provider evidence.

**Triage and decision.** A new high-privilege consent by a risky user followed by
resource access is stronger than an unused grant. Application-only activity may
not have a human user; do not invent one. Gaps in non-interactive sign-in or
resource audit can make use of a credential unobservable.

**Safe validation.** Use a low-privilege test application in a non-production
tenant, approved synthetic resources, and a short-lived test credential. Remove
it through normal governance after verifying events.


### 16.16 Unexpected Windows service creation or modification

**Question and hypothesis.** An adversary may create or modify a Windows service
to gain execution, persistence, or elevated context. Service Control Manager,
registry, process, file, and authentication telemetry should identify the
creator, service configuration, binary, logon account, and execution.

**ATT&CK v19.** Use
[T1543.003 Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/)
under Persistence and/or Privilege Escalation when supported. If the evidence is
specifically remote or local command execution through a service, assess
[T1569.002 System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/)
separately rather than adding an unsupported tactic relationship to T1543.003.

**Minimum telemetry.** Service creation/configuration and start events, process
creation, registry, file metadata, remote administration, authentication, and
software/change inventory. Fields include service name/display name, binary
path and arguments, start type, account, actor, source, process ancestry,
signer/hash, result, and time.

**Candidate analytic.**

```text
FROM service_created OR service_configuration_changed OR service_started
WHERE new_or_changed_service
  AND (binary_in_user_writable_or_remote_path OR interpreter_command
       OR rare_service_account OR unsigned_or_first_seen_binary)
CORRELATE creator_process, remote_session, and service_process
```

**Procedure.**

1. Baseline service installations by package, signer, path, account, start type,
   target population, deployment system, and maintenance window.
2. Verify visibility for service creation and later configuration changes; a
   service can be hijacked without a new-service event.
3. Search new/modified services with user-writable, temporary, network, or
   interpreter-based paths; unusual accounts; auto-start changes; and names
   resembling known products but with different binaries.
4. Review the creator process, actor, remote session, privilege, and source host.
   Determine whether a management agent or interactive tool made the change.
5. Inspect binary origin, signer, hash, prevalence, write time, package
   provenance, and related file events without executing it.
6. Correlate service starts with child processes, failures, outbound traffic,
   credential access, or defense impairment.
7. Validate legitimate installation against the exact package and change record;
   a familiar display name is not validation.
8. Preserve configuration and event references before authorized response
   changes or removes the service.

**Triage and decision.** A remotely created auto-start service pointing to a new
unsigned binary and followed by outbound traffic warrants escalation. Software
installers commonly create services, so deployment provenance is essential.
Registry-only coverage without creator context limits attribution.

**Safe validation.** Install and start an inert lab service through an approved
fixture, then confirm creator, configuration, process, and network event fields.


### 16.17 Multi-factor authentication request generation and fatigue

**Question and hypothesis.** An adversary with a password may repeatedly trigger
MFA requests to pressure a user into approving one, then use the resulting
session. Identity logs should show repeated challenges, denials or timeouts, an
approval or alternate factor, and subsequent activity linked to the source and
session.

**ATT&CK v19.** Use
[T1621 Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)
under Credential Access when repeated adversary-generated requests are
supported. Multiple failures alone do not establish this technique.

**Minimum telemetry.** Primary authentication, MFA challenge events and method,
push-number matching or equivalent details where available, device/source,
help-desk and factor-reset audit, session/token, conditional access, and
subsequent resource actions. Fields include immutable identity, source, device,
challenge/result/reason, factor, request/session ID, application/resource, and
time.

**Candidate analytic.**

```text
WINDOW 30m BY identity, source_context
WHERE repeated_MFA_challenges AND denials_or_timeouts
FOLLOWED BY approval_or_success
CORRELATE successful_session TO subsequent_resource_or_privilege_activity
```

**Procedure.**

1. Document provider semantics for challenge sent, viewed, denied, timed out,
   number-matched, approved, and authentication success. Do not equate a push
   delivery with a completed login.
2. Baseline normal retry behavior for mobile connectivity, VPN, shared devices,
   and legacy applications. Separate user, workload, and automated flows.
3. Aggregate repeated challenges by immutable identity and source context over a
   short window. Rank sequences ending in approval, factor change, help-desk
   reset, or login from a new device/network.
4. Inspect whether challenges came from one or multiple sources and applications.
   Check preceding password failures or credential-stuffing patterns.
5. Correlate the accepted session or nearest supported identifier to mailbox,
   storage, directory, privilege, credential, or application actions.
6. Validate legitimate user behavior through a trusted incident or help-desk
   channel. Do not send a new push to ask whether previous pushes were valid.
7. Pivot to other identities targeted by the same infrastructure or application
   and to factor/policy changes made around the sequence.
8. Escalate suspicious accepted sessions. Authorized identity responders should
   terminate sessions, reset credentials/factors, and preserve audit evidence.

**Triage and decision.** Repeated denials followed by a successful new-device
session and sensitive action is high concern. Repeated timeouts with no success
may be an attempted attack, not compromise. If the provider omits challenge
detail, record the resulting uncertainty.

**Safe validation.** Use a designated test identity and provider-supported
simulation. Avoid sending repeated production pushes to a real user.


### 16.18 Credentials accessed from web-browser stores

**Question and hypothesis.** An adversary may access browser credential,
cookie, or profile databases to obtain stored authentication material. Endpoint
process/file-access telemetry and follow-on authentication should reveal a
non-browser process accessing protected profile artifacts and subsequent use.

**ATT&CK v19.** Use
[T1555.003 Credentials from Password Stores: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
under Credential Access when access to browser credential stores is evidenced.

**Minimum telemetry.** Endpoint process and ancestry, file access where
available and proportionate, browser profile paths and versions, EDR behavioral
events, process memory/security alerts, identity authentication, and software
inventory. Fields include actor process entity/path/signer/hash, target file or
profile, access operation, user, host, session, result, and time.

**Candidate analytic.**

```text
FROM file_access OR EDR_behavior
WHERE target_is_browser_credential_cookie_or_profile_store
  AND accessor_is_not_expected_browser_or_approved_management_process
CORRELATE archive/file_copy, child_process, and later_authentication
```

**Procedure.**

1. Inventory browser products, profile locations, enterprise management tools,
   password managers, backup/indexing agents, and security products that may
   legitimately access profile files.
2. Confirm whether the endpoint source records file opens/reads or only changes.
   File creation telemetry alone cannot answer a read-access hypothesis.
3. Search non-browser processes accessing credential, cookie, login-data, or key
   material, emphasizing unsigned/user-writable binaries, shells, archive tools,
   and unusual parent processes.
4. Review process signer, hash, prevalence, path, parent chain, user/session, and
   privilege. Check whether it was remotely launched or recently downloaded.
5. Correlate copies, temporary files, archives, deletion, network connections,
   clipboard access if governed, and process injection alerts.
6. Review identity and application sessions after the event for new device,
   source, token, or resource access. Do not assume every later login used the
   accessed material.
7. Validate legitimate support, migration, backup, or security activity with
   its owner and exact binary provenance.
8. Store only minimal file metadata and evidence references in the hunt. Do not
   copy browser databases or expose stored credentials outside forensics.

**Triage and decision.** A rare process copying browser credential files and
then connecting externally strongly supports escalation. Browser update or
enterprise migration components can access profiles legitimately. If read
auditing was unavailable, record a visibility gap rather than inferring no
access.

**Safe validation.** Use a synthetic browser profile with fake credentials in a
disposable lab and replay or generate approved access events. Never use a real
employee profile as a fixture.


### 16.19 Unexpected container-administration command

**Question and hypothesis.** An adversary with orchestrator access may execute a
command inside a running container to inspect, modify, or pivot through a
workload. Kubernetes or container control-plane audit, identity, runtime, and
network telemetry should reveal the actor, target namespace/workload/container,
command request, authorization decision, and follow-on activity.

**ATT&CK v19.** Use
[T1609 Container Administration Command](https://attack.mitre.org/techniques/T1609/)
under Execution when a container administration interface is used to run a
command.

**Minimum telemetry.** Orchestrator API audit at metadata/request level under
approved policy, identity and RBAC, admission/controller logs, container runtime
events, workload inventory, network flow, and cloud control-plane audit. Fields
include actor, groups/role, source, user agent, verb, resource/subresource,
namespace, pod/workload/container, response code, request ID, command metadata
as policy allows, and time.

**Candidate analytic.**

```text
FROM orchestrator_audit
WHERE subresource_is_exec_or_attach AND request_allowed
  AND (actor_not_in_admin_baseline OR production_namespace
       OR source_or_user_agent_is_new OR target_is_sensitive)
CORRELATE runtime_process AND network_activity BY pod/container/time
```

**Procedure.**

1. Define approved break-glass and operational exec workflows, administrator
   identities, automation, bastions, namespaces, and maintenance windows.
2. Verify API audit includes request identity, subresource, target, decision, and
   source. Apply policy-based redaction to secrets and command content.
3. Search allowed and denied `exec`, `attach`, or equivalent administration
   requests, ranking production targets, service-account use, new source/user
   agent, and high-privilege namespaces.
4. Resolve the federated human or workload identity behind the request, including
   assumed role and impersonation. Review recent role bindings or credential
   changes.
5. Correlate the request with runtime process events, image baseline, filesystem
   changes, secret access, service-account token use, and outbound network flow.
6. Review what preceded the request: unusual sign-in, exposed dashboard,
   compromised CI/CD, or stolen kubeconfig/token indicators.
7. Validate legitimate troubleshooting using ticket, owner, exact target, time,
   and approved access path. Confirm the session did not exceed the requested
   scope.
8. Escalate unexplained production exec or follow-on activity. Authorized
   responders should rotate tokens or isolate workloads through the container
   incident process.

**Triage and decision.** An exec event is not inherently malicious; operators
use it for troubleshooting. Unexpected identity/source plus secret access or
external connection is stronger. In managed environments without runtime
telemetry, the API event may prove command access but not the command's effect.

**Safe validation.** Use a non-production namespace and benign command that
prints a fixed test marker. Do not access secrets, privileged pods, host mounts,
or production workloads.


### 16.20 Unix shell download-and-execute chain

**Question and hypothesis.** An adversary may use a Unix shell on a Linux host
to retrieve content into a writable location and execute it or pipe it to an
interpreter. Process, shell/audit, file, package, and network telemetry should
connect the initiating session, transfer, file or stream, and execution.

**ATT&CK v19.** Use
[T1059.004 Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
under Execution and
[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) under
Command and Control only when the respective behaviors are observed.

**Minimum telemetry.** Linux audit/eBPF or EDR process ancestry, command/script
metadata under policy, authentication and sudo, file create/modify/execute,
package-manager logs, DNS/network-to-process, and workload/asset role. Fields
include process/parent entities, user/session, effective UID, executable,
arguments, path/hash, source/destination, container/host context, result, and
time.

**Candidate analytic.**

```text
SEQUENCE BY host, session_or_parent_process WITHIN 20m
  [shell_or_download_client contacts rare source]
  [file_created_in_writable_path OR data_piped_to_interpreter]
  [new_file_executed OR interpreter_or_shell_child]
RANK BY privilege, parent_rarity, signer/package provenance, persistence
```

**Procedure.**

1. Inventory approved package managers, configuration tools, build agents,
   bootstrap scripts, administrators, containers, and expected download clients.
2. Confirm process ancestry and network linkage across host and container
   boundaries. Shell history is user-controlled and should not be the only
   source.
3. Search shell, download client, and interpreter chains involving rare
   destinations, direct IPs, user-writable locations, temporary paths, permission
   changes, or pipe-to-interpreter patterns.
4. Review authentication, session, sudo/effective UID, parent process, working
   directory, environment context, and whether execution came from a web service,
   cron job, CI runner, or interactive login.
5. Correlate downloaded content using hash, path, process entity, or a narrow
   time window. Preserve uncertainty when content was streamed without a file.
6. Inspect file/package provenance, hash prevalence, static metadata, child
   processes, persistence, credential access, discovery, and outbound traffic
   without executing the object.
7. Validate legitimate bootstrap/build/deployment activity against the approved
   repository, commit or package, runner identity, target population, and change
   context.
8. Escalate unexplained privileged or service-context execution with credible
   follow-on behavior. Acquire files only through the approved forensic or
   malware-analysis boundary.

**Triage and decision.** `curl` or `wget` use alone is common. A rare source,
service parent, temporary executable, privilege, and persistence sequence is
materially stronger. Missing container attribution or process-to-network linkage
must narrow the conclusion.

**Safe validation.** Retrieve and execute an inert signed fixture in a disposable
Linux lab, using a controlled destination. Do not pipe unreviewed remote content
to a shell or test against production.


## 17. Reusable templates

Copy these templates into the appropriate governed system. Replace every
placeholder; do not leave “TBD” fields in a hunt marked ready.

### 17.1 Hunt charter

```markdown
# Hunt: [specific behavior and scope]

- Hunt ID:
- Status: draft | planned | running | review | completed | archived
- Owner:
- Supporting analyst / reviewer:
- Priority and rationale:
- Created / last reviewed:
- Trigger type: CTI | IOC | CVE | asset risk | incident | detection gap |
  anomaly | validation | recurring | manual
- Trigger reference and observed/published time:
- ATT&CK domain and version:
- Technique/sub-technique IDs and tactic context:
- Detection Strategy / Analytic / Data Component references:

## Hypothesis

Because [context], an adversary may use [behavior] against [scope] to achieve
[objective]. If this occurred during [time/environment], we expect [ordered
evidence] in [telemetry]. The hypothesis is weakened by [counter-evidence].

## Scope and authorization

- Assets / identities / tenants / regions:
- Time range and maximum lookback:
- Explicit exclusions:
- Authorized data systems:
- Handling classification / privacy constraints:
- Query limits and stop conditions:
- Incident threshold and contact:

## Evidence model

- Expected supporting evidence:
- Expected counter-evidence:
- Known benign patterns:
- Critical assumptions:
- Known blind spots:

## Plan

- Telemetry requirements:
- Query/analytic version:
- Preflight method:
- Investigation pivots:
- Safe validation method:
- Review and completion criteria:
```

### 17.2 Telemetry requirement matrix

| Requirement ID | Behavioral evidence | ATT&CK Data Component / channel | Local source/index | Required fields | Coverage | Retention | Time/parse quality | Readiness | Gap effect | Owner |
|---|---|---|---|---|---|---|---|---|---|---|
| TR-01 | Process creation and ancestry | [current component/channel] | [EDR index] | time, host, user, process, parent, command | 94% managed Windows | 30 days | 2% parent nulls | partial | Six critical servers absent | Endpoint team |

For `partial`, `unverified`, `missing`, or `failed`, add a gap record and state
which part of the hypothesis can no longer be assessed.

### 17.3 Query or analytic version record

```yaml
analytic_id: HUNT-0000-A1
version: 1.0.0
checksum: sha256:[value]
status: draft | test | approved | retired
abstract_behavior: >-
  [vendor-neutral behavior, sequence, grouping, threshold, and context]
language: sigma | kql | spl | eql | lucene | sql | osquery | generic | other
backend_and_version: [value]
schema_and_mapping_version: [value]
parameters:
  lookback: [value]
  threshold: [value]
lookups:
  - name: [value]
    version: [value]
    owner: [value]
    expires: [date]
assumptions:
  - [value]
known_benign_cases:
  - [value]
known_blind_spots:
  - [value]
expected_volume_and_cost: [value]
test_fixtures_and_results:
  - [reference]
author: [identity]
reviewer: [identity]
approved_at: [timestamp]
change_reason: [value]
```

Store the query body beside this metadata in version control or an immutable
query-version object. Do not put credentials or sensitive lookup contents in the
record.

### 17.4 Hunt run record

```yaml
run_id: [immutable ID]
hunt_id: [ID]
analytic_id_and_version: [ID/version/checksum]
requested_by: [identity]
executed_by: [human and/or service identity]
connector_and_backend: [non-secret reference]
source_job_or_audit_id: [value]
schema_and_mapping_version: [value]
resolved_parameters: [redacted as needed]
scope_partitions: [assets/tenants/indices]
requested_time_range: [start/end]
effective_time_range: [start/end]
execution_time: [start/end]
limits: [runtime/rows/bytes/concurrency]
rows_or_bytes_scanned: [value or unavailable]
results_returned: [value]
complete: true | false
sampled_or_truncated: true | false
warnings_and_errors: [values]
result_export_reference: [access-controlled reference]
result_integrity_hash: [value if exported]
reviewed_by: [identity]
```

### 17.5 Finding and evidence record

```markdown
## Finding: [evidence-based title]

- Finding ID / hunt ID:
- Status: new | reviewed | escalated | closed
- Analyst / reviewer:
- Event time / ingest time:
- Evidence type and access-controlled reference:
- Source event or request IDs:
- Raw/export integrity hash, if applicable:
- Schema/parser version:
- Affected assets, identities, sessions, or resources:
- Observables (time-bound and typed):
- Supported ATT&CK techniques and rationale:
- Observed facts:
  - [fact recoverable from evidence]
- Analyst inferences:
  - [inference and why]
- Counter-evidence / benign explanation:
- Confidence (0–100) and rationale:
- Severity and rationale:
- Handling/redaction notes:
- Decision and next action:
```

### 17.6 Final hunt report

```markdown
# Final report: [hunt title]

## Executive result

[One paragraph: question, scope, outcome, confidence, and required action.]

## Hypothesis and trigger

[Original hypothesis, source, relevance, ATT&CK version/mappings.]

## Scope and data fitness

[Assets/identities/tenants, requested/effective time, ready/partial/missing data,
retention, parser/time limitations, exclusions.]

## Analytic and execution

[Query version/checksum, backend/mapping, run IDs, parameters, completeness,
truncation, errors, and review.]

## Findings and timeline

[Reviewed facts, evidence references, pivots, counter-evidence, and uncertainty.]

## Disposition

undetermined | no_matches | benign | benign_policy_relevant | suspicious |
confirmed_malicious | inconclusive | telemetry_gap | query_failure

[Explain why and what this disposition does not establish.]

## Follow-up

| Action | Type | Owner | Due | Acceptance evidence | Status |
|---|---|---|---|---|---|
| [value] | incident / detection / telemetry / validation / recurring hunt | [value] | [date] | [test or artifact] | open |

## Review

- Hunt lead:
- Peer reviewer:
- Incident/detection/telemetry handoff accepted by:
- Completion time:
```

### 17.7 Detection handoff

```markdown
- Detection candidate ID:
- Originating hunt and finding IDs:
- Behavior and ATT&CK version/mapping:
- Detection Strategy / Analytic references:
- Required telemetry, fields, coverage, and gap state:
- Approved query/rule version and backend mapping:
- Test and safe-simulation evidence:
- Expected volume and false-positive cases:
- Severity, routing, and response guidance:
- Suppressions with owner and expiry:
- Owner and reviewer:
- Monitoring, tuning, and review cadence:
- Retirement conditions:
```

### 17.8 Recurring-hunt schedule

```yaml
schedule_id: [ID]
hunt_id: [ID]
owner: [identity]
backup_owner: [identity]
frequency: [cron or plain-language schedule]
timezone: UTC
lookback: [duration]
overlap_for_late_data: [duration]
analytic_id_and_version: [immutable reference]
scope: [approved scope reference]
maximum_runtime_and_results: [limits]
review_due_after_run: [service level]
alert_or_escalation_threshold: [value]
missed_run_policy: [value]
suppression_review_date: [date]
next_formal_review: [date]
conversion_or_retirement_condition: [value]
```

## 18. Operational checklists

### 18.1 Ready-to-run gate

- [ ] The hypothesis is behavior-specific, falsifiable, and locally relevant.
- [ ] Trigger, source reference, publication/observation time, and relevance are recorded.
- [ ] Scope, exclusions, lookback, owner, requested data-access authorization, and a bounded run plan are explicit and approved.
- [ ] ATT&CK domain/version provenance, technique IDs, and current v19 tactic relationships are recorded.
- [ ] Current Detection Strategy/Analytic/Data Component references were reviewed where available.
- [ ] Every required telemetry source and field has a sampled readiness result.
- [ ] Coverage, retention, parser, event-time, and ingest-time limitations are documented.
- [ ] Expected evidence, counter-evidence, benign alternatives, and assumptions are written.
- [ ] The analytic is versioned, mapped to the backend, syntax-validated, tested, and peer reviewed as risk requires.
- [ ] Read-only connector credentials/access and server-side lookback/time/row/memory/cost/concurrency limits are configured, and estimated cost is acceptable.
- [ ] Sensitive-output handling, retention, evidence storage, and redaction are defined.
- [ ] Incident thresholds, stop conditions, cancellation and timeout behavior, and contacts are ready.

### 18.2 Per-run execution

- [ ] Record hunt, analytic version/checksum, connector/backend, mapping version, and analyst.
- [ ] Record requested and effective time range and resolved scope.
- [ ] Run a schema and volume preflight before expansion.
- [ ] Confirm expected benign data is present.
- [ ] Monitor cost, runtime, volume, errors, and source health.
- [ ] Stop if scope becomes unauthorized or limits are exceeded.
- [ ] Record rows/bytes and result counts when the backend exposes them.
- [ ] Mark sampling, truncation, timeout, partition failure, or delayed data.
- [ ] Preserve source job/audit ID and access-controlled result reference.
- [ ] Hash exported evidence where policy requires integrity verification.

### 18.3 Finding triage

- [ ] Verify parse quality, event time, and source provenance.
- [ ] Resolve asset, identity, session, process, workload, and network attribution.
- [ ] Inspect initiating context and full relevant chain.
- [ ] Compare with individual, peer, and administrative baselines.
- [ ] Pivot backward and forward within an authorized, bounded window.
- [ ] Collect both supporting and contradictory evidence.
- [ ] Validate change, deployment, and owner claims independently.
- [ ] Keep fact, inference, confidence, severity, impact, and disposition separate.
- [ ] Minimize sensitive data and link raw evidence rather than copying it.
- [ ] Escalate when the incident threshold is met; do not take unauthorized response action.

### 18.4 Hunt closeout

- [ ] Every run has completeness and error status.
- [ ] Material evidence clusters have reviewed findings and references.
- [ ] Result summary states scope, time, data fitness, analytic version, and limitations.
- [ ] Disposition is the narrowest outcome supported by evidence.
- [ ] Disposition is one of `undetermined`, `no_matches`, `benign`,
      `benign_policy_relevant`, `suspicious`, `confirmed_malicious`,
      `inconclusive`, `telemetry_gap`, or `query_failure`.
- [ ] `no_matches` is not used when telemetry or execution was insufficient.
- [ ] A `suspicious` or `confirmed_malicious` disposition has an accepted incident or investigation handoff.
- [ ] Detection candidates include tests, data requirements, owner, and review plan.
- [ ] A `telemetry_gap` disposition has concrete remediation, owner, date, and verification test.
- [ ] Recurring searches have schedule, lookback overlap, owner, and retirement rule.
- [ ] Peer review and final completion time are recorded.

### 18.5 Telemetry-gap acceptance

- [ ] The missing source, field, asset set, period, or parser behavior is specific.
- [ ] Affected hypotheses and business risk are named.
- [ ] Current coverage and evidence proving the gap are attached.
- [ ] Compensating telemetry and its limitations are documented.
- [ ] Data minimization and privacy implications were considered.
- [ ] Remediation owner, priority, due date, and dependency are set.
- [ ] A verification query or event fixture defines “fixed.”
- [ ] The hunt will be rerun or its conclusion amended after validation.

### 18.6 Connector security review

- [ ] Connector purpose, data owner, tenant, endpoint, and protocol are approved.
- [ ] Endpoint allowlist, DNS behavior, proxy path, TLS validation, and certificate policy are enforced.
- [ ] Credentials are read-only, least-privileged, rotated, and held only by a secret manager.
- [ ] Write, delete, response, configuration, and isolation APIs are denied.
- [ ] Server-side lookback, runtime, row, byte, export, and concurrency limits exist.
- [ ] Cancellation, timeout, retries, and partial-result behavior are tested.
- [ ] Cross-tenant and object authorization tests pass.
- [ ] Errors and audit records redact credentials and sensitive query values.
- [ ] Query actor, scope, time, connector, and outcome are immutably audited.
- [ ] Parser, converter, and export paths tolerate malformed/adversarial input.
- [ ] Retention, redaction, residency, and deletion meet organizational policy.
- [ ] Credential compromise and connector-disable runbooks are tested.

### 18.7 Monthly program review

- [ ] Reprioritize backlog from current intelligence, exposure, incidents, and gaps.
- [ ] Review overdue hunts, unreviewed runs, stale suppressions, and orphaned schedules.
- [ ] Review priority telemetry coverage, parser health, and retention changes.
- [ ] Track gap closure by verified evidence, not configuration claims.
- [ ] Review detection promotions, tuning, misses, and retirements.
- [ ] Confirm incident handoffs and post-incident hunts were completed.
- [ ] Check ATT&CK, schema, backend, and connector versions for remapping needs.
- [ ] Sample completed hunts for scope, provenance, evidence, and decision quality.
- [ ] Review access, audit, secret rotation, exports, and privacy exceptions.
- [ ] Report risk reduction and remaining uncertainty, not only activity counts.

### 18.8 Governed AI assistance review

- [ ] The source is a stored report/research session or canonical saved-hunt
      context; the assistant did not fetch a new source or telemetry.
- [ ] The hunt's effective TLP was reviewed; its `TLP:AMBER` draft default was
      raised when the hunt context or organizational policy required it.
- [ ] For report-to-hypothesis assistance, the authoritative stored report TLP
      was reviewed; its conservative `TLP:AMBER+STRICT` default was changed
      only by an authorized `manage_intel` user, and the request did not lower
      that stored marking.
- [ ] Report-to-hypothesis input uses the Enterprise ATT&CK domain.
- [ ] A remote provider was enabled by policy and explicitly acknowledged, or
      the configured local provider was used.
- [ ] `TLP:AMBER+STRICT` and `TLP:RED` context remained local-only.
- [ ] Every technique, field assumption, citation, query fragment, and scope
      statement was reviewed against the source and local environment.
- [ ] For query assistance, the selected target language matches the destination
      platform, the returned query label matches that language, and the explicit
      Use/Replace action was followed by syntax and field validation.
- [ ] Dropped-citation and truncation warnings were resolved or recorded as
      limitations; any stale-context conflict was retried against current data,
      and later source/hunt edits were checked manually.
- [ ] AI prose was not recorded as evidence and did not replace a source event,
      external run ID, reviewed finding, or analyst decision.
- [ ] **Apply safe fields**, **Apply safe suggestions**, **Use/Replace query
      draft**, or **Open editable draft** was followed by review and a separate
      normal Save action.
- [ ] No generated content changed lifecycle, disposition, finding review state,
      incident handling, response, or production detection state automatically.
- [ ] The append-only assistance record contains only the validated structured
      suggestion, governed metadata, and bounded validated citation excerpts;
      no full raw report, prompt, provider response, credential, or provider
      exception was persisted there.
- [ ] When the Navigator RAG assistant supplied the trigger, every carried-over
      IOC, CVE, actor, campaign, technique, or asset claim was checked through
      its canonical route; retrieval score and relationship expansion were not
      recorded as confidence, targeting, exploitation, or compromise evidence.
- [ ] A saved business profile was treated as private ranking context, not
      source evidence; prompt-only business language was recorded as
      non-authoritative context.
- [ ] A RAG proposal changed only the reviewed in-memory Navigator selection
      after explicit confirmation. Layer saving and hunt creation were separate
      actions, and the MCP surface was not used to bypass browser confirmation.
- [ ] The hunt record distinguishes RAG research sources from the later external
      telemetry run and evidence that support the local disposition.

## 19. Primary references

This guide uses first-party standards, frameworks, and public-sector operational
guidance. Product-specific implementation details should use the corresponding
vendor's official documentation.

### MITRE ATT&CK

- [TTP-Based Hunting training](https://attack.mitre.org/resources/learn-more-about-attack/training/threat-hunting/) (accessed 17 July 2026).
- [ATT&CK version history](https://attack.mitre.org/resources/versions/) (accessed 18 July 2026).
- [ATT&CK v19 release notes](https://attack.mitre.org/resources/updates/updates-april-2026/) (accessed 18 July 2026).
- [Defense Evasion split crosswalk (JSON)](https://attack.mitre.org/docs/subtechniques/de-split-crosswalk.json) (accessed 17 July 2026).
- [Defense Evasion split crosswalk (CSV)](https://attack.mitre.org/docs/subtechniques/de-split-crosswalk.csv) (accessed 17 July 2026).
- [October 2025 defensive-model update](https://attack.mitre.org/resources/updates/updates-october-2025/) (accessed 17 July 2026).
- [Detection Strategies](https://attack.mitre.org/detectionstrategies/) (accessed 17 July 2026).
- [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/) (accessed 17 July 2026).
- [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) (accessed 17 July 2026).
- [Working with ATT&CK data](https://attack.mitre.org/resources/working-with-attack/) (accessed 17 July 2026).

### NIST

- [NIST SP 800-172r3: Enhanced Security Requirements for Protecting Controlled Unclassified Information](https://csrc.nist.gov/pubs/sp/800/172/r3/final) (accessed 17 July 2026).
- [NIST SP 800-172Ar3: Assessing Enhanced Security Requirements for Controlled Unclassified Information](https://csrc.nist.gov/pubs/sp/800/172/a/r3/final) (accessed 17 July 2026).
- [NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (accessed 17 July 2026).
- [NIST SP 800-53r5: Security and Privacy Controls](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf) (accessed 17 July 2026).
- [NIST Log Management project](https://csrc.nist.gov/Projects/log-management) (accessed 17 July 2026).
- [NIST SP 800-92r1: Cybersecurity Log Management Planning Guide (Initial Public Draft)](https://csrc.nist.gov/pubs/sp/800/92/r1/ipd) (accessed 17 July 2026).

At the time of this guide, NIST identifies SP 800-92r1 as an Initial Public
Draft, not a final publication. Check the official project and publication pages
before citing it as current normative guidance.

### CISA

- [Use Logging on Business Systems](https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/use-logging-on-business-systems) (accessed 17 July 2026).
- Joint CISA and U.S. Coast Guard (USCG) advisory [AA25-212A: CISA and USCG Identify Areas for Cyber Hygiene Improvement After Conducting Proactive Threat Hunt at US Critical Infrastructure Organization](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-212a) (accessed 17 July 2026).
- [Identifying and Mitigating Living Off the Land Techniques](https://www.cisa.gov/sites/default/files/2025-03/Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf) (accessed 17 July 2026).

The joint living-off-the-land guidance is especially useful when behavior uses
legitimate tools: detection depends on baselining, process and identity context,
centralized logs, and sequences rather than tool names alone.

### Schemas and detection content

- [Open Cybersecurity Schema Framework](https://ocsf.io/) (accessed 17 July 2026).
- [OCSF schema browser](https://schema.ocsf.io/) (accessed 17 July 2026).
- [OCSF Detection Finding](https://schema.ocsf.io/classes/detection_finding) (accessed 17 July 2026).
- [Elastic Common Schema reference](https://www.elastic.co/guide/en/ecs/current) (accessed 17 July 2026).
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) (accessed 17 July 2026).
- [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) (accessed 17 July 2026).
- [Sigma filters](https://sigmahq.io/docs/meta/filters.html) (accessed 17 July 2026).

---

The strongest hunt is not the one with the most matches. It is the one another
analyst can understand, rerun, challenge, and turn into a better defensive
decision.
