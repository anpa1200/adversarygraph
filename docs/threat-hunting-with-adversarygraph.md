# Threat Hunting with AdversaryGraph

> A practical operator guide for turning intelligence, ATT&CK context, IOCs,
> CVEs, asset exposure, reports, and detection gaps into reviewable threat hunts
> in AdversaryGraph. Platform behavior and public-source examples were reviewed
> on 25 July 2026.

AdversaryGraph is a self-hosted threat-intelligence and security-operations
workbench. It connects reports, ATT&CK and ATLAS knowledge, IOCs, CVEs, asset
context, governed AI/RAG assistance, threat hunting, evidence, detection
engineering, and controlled attack simulation in one reviewable workflow.
Analysts remain responsible for source validation, query execution, evidence
review, and operational decisions.

- [Explore the AdversaryGraph platform](https://1200km.com/adversarygraph/)
- [View the source code on GitHub](https://github.com/anpa1200/adversarygraph)
- [Read the complete documentation](https://1200km.com/adversarygraph-docs/)
- [Read the vendor-neutral threat-hunting methodology](threat-hunting-guide.md)

This guide begins where the vendor-neutral methodology ends. It follows the
current self-hosted interface from hypothesis and scope through query review,
external execution, findings, disposition, defensive handoff, and safe
validation.

AdversaryGraph is the system of record for the hunt. The current Threat Hunting
workspace does not execute a saved query against a SIEM, EDR, data lake, or
cloud control plane. The analyst copies the reviewed query into an approved
telemetry platform, runs it there, and records the run and evidence references
back in AdversaryGraph.

## Table of Contents

1. [Start here: the operator path](#1-start-here-the-operator-path)
2. [Before the first hunt](#2-before-the-first-hunt)
   - [Access and platform readiness](#21-access-and-platform-readiness)
   - [Know the boundary](#22-know-the-boundary)
3. [Create and plan the hunt](#3-create-and-plan-the-hunt)
   - [Stored report or research session to hypothesis](#31-turn-a-stored-report-or-research-session-into-a-hypothesis)
   - [Assistance across the hunt](#32-use-assistance-across-the-hunt-without-delegating-decisions)
   - [Cross-source RAG evidence](#33-use-cross-source-rag-evidence-to-scope-a-hunt)
   - [Query Library or IOC set](#34-start-from-the-query-library-or-an-ioc-set)
4. [Run the query and record findings](#4-run-the-query-and-record-findings)
5. [Review, decide, and hand off](#5-review-decide-and-hand-off)
6. [What AdversaryGraph preserves](#6-what-adversarygraph-preserves)
7. [Move through the AdversaryGraph ecosystem](#7-move-through-the-adversarygraph-ecosystem)
8. [Ten worked AdversaryGraph use cases](#8-ten-worked-adversarygraph-use-cases)
9. [Real open-source example: Play ransomware backdoor hash](#9-real-open-source-example-play-ransomware-backdoor-hash)
10. [Apply the twenty methodology playbooks in AdversaryGraph](#10-apply-the-twenty-methodology-playbooks-in-adversarygraph)

## 1. Start here: the operator path

Open **Hunt & Validate → Threat Hunting**. The landing page contains the active
hunt queue, status and priority filters, ATT&CK filtering, built-in templates,
and these primary actions:

- **Create threat hunt** starts an empty draft.
- **Browse query library** opens searchable Sigma, YARA-L, YARA, KQL, SPL, EQL,
  Lucene, SQL, osquery, and generic starting content.
- **Open hunting guide** opens the in-platform help route.
- Selecting a hunt opens its four-stage workspace and immutable query history.

For a first hunt, use this shortest safe path:

| Step | In AdversaryGraph | Required analyst decision |
|---|---|---|
| 1 | Select **Create threat hunt** or a reviewed template | What behavior is worth testing, and why now? |
| 2 | Complete **Plan and scope** | Which assets, identities, tenants, time range, exclusions, owner, priority, and TLP are authorized? |
| 3 | Complete **Query and telemetry** | Which data sources and fields are fit for purpose, and which query language matches the destination? |
| 4 | Save the draft and obtain peer review | Is the query safe, bounded, syntactically valid, and supported by the available telemetry? |
| 5 | Select **Copy query** and run it in the approved external platform | Which identity, backend, indexes, limits, and effective time range were actually used? |
| 6 | Return to **Findings** | Which result clusters support, refute, or fail to resolve the hypothesis? |
| 7 | Open **Outcome and handoff** | What is the narrowest defensible disposition, limitation, and next owner? |
| 8 | Complete and optionally archive | Is the record reviewable, reproducible, and linked to any incident, detection, evidence, or validation work? |

The lifecycle is enforced rather than inferred:

```text
draft -> planned -> running -> review -> completed -> archived
   \         \          \          \
    +------> cancelled or archived where the current transition permits
```

Use `draft` while the plan is incomplete, `planned` only after readiness and
authorization, `running` only while the external search is being performed,
and `review` while evidence and disposition are awaiting final review.
Completed, cancelled, and archived hunts are retained as read-only history.

## 2. Before the first hunt

### 2.1 Access and platform readiness

Before creating a production hunt:

1. Open the platform self-test and confirm that the database and required
   services are healthy. A degraded optional feed does not automatically
   invalidate a hunt, but it must not be represented as current evidence.
2. Confirm that the signed-in role can open Threat Hunting and run analysis.
   Export, feed administration, attack simulation, and platform configuration
   may require separate permissions.
3. Confirm that ATT&CK data, IOC/CVE feeds, report sources, Query Library
   indexes, and the RAG corpus needed for the use case are current enough for
   the question.
4. Verify time synchronization, retention, parser health, expected asset or
   identity coverage, and required fields in the destination telemetry system.
5. Select the handling marking before including sensitive context. A hunt or
   finding may be raised to a more restrictive TLP value but is not downgraded
   through the ordinary workspace.

### 2.2 Know the boundary

Treat AdversaryGraph as the hunt-management and evidence ledger unless a
separately configured and documented connector explicitly says otherwise.
Saving a query is not an execution record. For every external run, record:

- destination product, tenant, index or dataset;
- external job, search, case, or event reference;
- query-version number or checksum;
- effective start and end time, including time zone;
- asset or identity population and measured coverage;
- row, event, or cluster count;
- truncation, timeout, parser, permission, or shard errors; and
- the location and handling requirements of the authoritative raw evidence.

Keep these distinctions visible throughout the hunt:

- an ATT&CK mapping is an analyst hypothesis, not proof of local activity;
- a template or AI-generated query is a draft, not a production analytic;
- an IOC is a pivot, not proof of compromise;
- a RAG citation proves that a stored source contains the cited context, not
  that the behavior occurred locally;
- `no_matches` applies only to the data, population, and interval actually
  searched; and
- RetroHunt searches AdversaryGraph intelligence holdings, not enterprise
  telemetry.

## 3. Create and plan the hunt

The **Plan and scope** tab answers “what are we testing?” and “where are we
allowed to test it?” Complete it before optimizing a query.

1. Choose the entry point:
   - **Create threat hunt** for an analyst-authored question;
   - **Start from a template** for one of the built-in behavioral starting
     points;
   - **Create hunt from query** in Query Library;
   - **Create threat hunt** from a Navigator technique;
   - a reviewed Threat Radar or report/research workflow; or
   - a manually reviewed lead from IOC, CVE, asset, RAG, incident, or detection
     coverage work.
2. Write a precise **Hunt title**. Prefer “Encoded PowerShell from Office
   processes on managed finance endpoints” to “PowerShell hunt.”
3. Write the **Hypothesis** in falsifiable form:

   ```text
   If [actor or condition] causes [behavior] on [population] during [period],
   then [named telemetry] should contain [observable relationship];
   [counter-evidence or benign condition] would weaken the hypothesis.
   ```

4. Use **Description** for the trigger, risk, and business reason. Use **Scope**
   for named systems, identities, environments, tenants, inclusions,
   exclusions, and the authorized timebox.
5. Assign an **Owner**, set **Priority** from local impact and urgency, and set
   the correct **TLP** handling value.
6. Review **Creation source** and **Source reference**. These fields are
   server-assigned and read-only. Analyst-entered context belongs in the
   description, assumptions, or a clearly labeled `context:*` tag.
7. Add only supported **ATT&CK techniques** and tactics. A valid ID format does
   not make the mapping correct; open Navigator or the ATT&CK Group Library to
   verify the behavior and current relationship.
8. Add concise **Tags** for the environment, business unit, data class,
   campaign, review cadence, or other operational grouping.
9. Open **Query and telemetry** and list the data sources, minimum fields,
   time boundary, expected evidence, false-positive considerations, and
   assumptions.
10. Keep the record at `draft` until the readiness panel is satisfied and a
    reviewer confirms scope, data fitness, query safety, and authorization.
    Save as `planned` only when the external run is approved.

AdversaryGraph requires scope, telemetry sources, expected evidence, and
false-positive notes before a hunt can enter a ready state. This prevents a
query from being treated as a plan when nobody has defined what the result
would mean.

### 3.1 Turn a stored report or research session into a hypothesis

The governed assistant starts from a completed report or research session with
source text already stored in AdversaryGraph. It does not accept a new URL,
fetch another source, or search enterprise telemetry as part of generation.

1. Open the stored report or research session. Confirm that analysis is
   completed and that its source text, publisher, source URL, and ATT&CK domain
   are the intended source.
2. Confirm the source report's persisted handling marking before generation.
   New and legacy reports default conservatively to `TLP:AMBER+STRICT`. A user
   with `manage_intel` may classify the stored report through the linked-report
   edit API; every later hypothesis request reads that server-side value. A
   request may raise the effective marking, but it cannot lower the stored one.
3. Confirm that the source uses the Enterprise ATT&CK domain. Governed Threat
   Hunting AI does not currently generate hunts from Mobile, ICS, or ATLAS
   report domains.
4. Select the `hypothesis` assistant task. The service sends a bounded portion
   of the stored source to the selected approved provider and returns a
   suggestion containing a falsifiable hypothesis, candidate Enterprise ATT&CK
   techniques, expected evidence, counter-evidence, assumptions, telemetry
   requirements, and benign alternatives when the source supports them.
5. Review every citation against the stored report. A citation proves only that
   the report contains the referenced text; it does not prove that the behavior
   occurred in the local environment.
6. Resolve any dropped-citation or truncation warning. The server removes a
   proposed citation that cannot be matched to an exact stored-source excerpt.
   If the stored source changes during generation, the service rejects the
   result as a stale-context conflict; retry against the current source.
   Regenerate after any later material report edit rather than relying on an
   older source snapshot.
7. Edit the suggestion into organization-specific language, define the actual
   scope and owner, and save it through the normal hunt form. The resulting hunt
   remains a `draft`; AI generation does not authorize or start it.

The backend writes an append-only AI-assistance record with the optional hunt
and stored-session IDs, task and stage, `suggested` lifecycle, provider/model,
prompt version, effective TLP, sanitized source references, citation metadata,
the recorded remote-processing acknowledgment state, and bounded
server-validated citation excerpts of at most 300 characters
each, input and output checksums, validated structured suggestion, warnings, and
generation actor/time. It does not store the full raw report, raw prompt, raw
provider response, credentials, or provider exception. The original stored
report remains the source of record.

### 3.2 Use assistance across the hunt without delegating decisions

The same governed boundary applies to every assistant task:

| Task | The assistant may draft | The analyst must decide and save |
|---|---|---|
| `hypothesis` | Falsifiable behavior statement, rationale, candidate Enterprise ATT&CK IDs, supporting and refuting evidence to seek | Whether the source justifies a hunt, final wording, priority, owner, and local scope |
| `plan` | Telemetry sources, required fields, data-quality checks, pivot sequence, expected evidence, benign alternatives, and stop conditions | Authorized systems, identities, time range, exclusions, readiness, and approval to run |
| `query` | Implementation-independent logic or a translation for a declared query language, plus assumptions and validation warnings | Destination schema and syntax, cost controls, peer review, query-version save, and external execution |
| `findings` | A draft organization of analyst-selected finding summaries, contradictions, evidence gaps, and follow-up questions | Evidence references, verdict, confidence, severity, finding status, escalation, and whether events are related |
| `outcome` | A draft result summary, limitations, telemetry gaps, and possible defensive follow-up | Disposition, completion, incident handoff, detection publication, archive, and every operational decision |

Generation never changes the hunt, creates or reviews a finding, appends a
query version, chooses a disposition, or advances lifecycle status. An analyst
must review, edit, and save through the ordinary governed workflow. In
particular, generated finding or outcome prose is not evidence and cannot
replace an event reference, reviewed finding, or external query-run record.

In the UI, **Apply safe fields** or **Apply safe suggestions** copies only
permitted scalar values into blank draft fields and merges permitted list
values into the unsaved hunt form. Query assistance is intentionally different:
select **Generate query**, choose **Target query language** (including YARA-L
2.0 for Google SecOps UDM), generate the suggestion, inspect the proposed
text and assumptions, then choose **Use … query draft** or **Replace query with
… draft**. That explicit action copies both query text and language into the
unsaved editor. It does not save the hunt, execute the query, or mark the
assistance record accepted. Changing the query-language selector directly also
changes only the recorded type; it does not translate existing text.
**Open editable draft** opens the ordinary unsaved finding form; it does not
create a finding. Review every copied value, then use the normal Save action.
Query, findings, and outcome assistance require a saved hunt so the server can
enforce canonical context. An unsaved plan may use the configured local
provider, or an operator-enabled remote provider when the draft has an explicit
`TLP:CLEAR`, `TLP:GREEN`, or `TLP:AMBER` marking and the analyst acknowledges
that specific remote-processing request. Unsaved `TLP:AMBER+STRICT` and
`TLP:RED` plans remain local-only.

Stage-specific application stays narrow. The explicit query Use/Replace action
may replace only the unsaved query text and language, fill blank
evidence/assumption fields, and merge telemetry sources and required fields.
The backend binds the requested target language into the prompt and removes
query text when the provider labels it as a different language. A
findings-stage hunt patch is ignored. An opened AI finding draft is
forced to status `new`, verdict `inconclusive`, the hunt TLP, evidence type
`analysis`, and blank evidence reference, event time, observables, and query
version; the analyst must add canonical evidence. Outcome assistance may fill
only a blank result summary or assumptions field.

Each suggestion is a snapshot. The server rechecks a stored report or canonical
hunt after the provider returns and rejects the result with a conflict if that
context changed during generation. A later edit also makes an earlier
suggestion stale, but does not rewrite the append-only assistance record;
regenerate or compare it manually with the current context. A coverage or
truncation warning identifies report text, query text, query versions, finding
summaries, or finding notes that were shortened or omitted from the bounded
request. The assistant cannot make claims about content or records it did not
receive.

For a saved hunt, the current bounds are 12,000 characters of the canonical
query; the newest five query versions with up to 6,000 query characters and
4,000 backend-assumption characters each; and the newest 50 active findings
with up to 3,000 summary characters and 2,000 note characters each. The
response and append-only record carry deterministic warnings when one of these
limits affects a request.

### 3.3 Use cross-source RAG evidence to scope a hunt

The **AI RAG assistant** in Navigator and the stage-specific **Threat Hunting AI
assistant** have different evidence boundaries:

| Assistant | Grounding boundary | Useful hunting output | What it never does |
|---|---|---|---|
| Navigator AI RAG assistant | Allowlisted chunks from the unified IOC, CVE, ATT&CK/ATLAS, actor, campaign, report, Knowledge, Threat Radar, canonical hunt, Evidence Graph, and sanitized asset corpus; optional saved business profile | Cross-source evidence search, cited synthesis, and an expiring ATT&CK/ATLAS proposal | It does not create a hunt, finding, query version, external query run, detection, incident, or response action |
| Threat Hunting AI assistant | One completed stored report for hypothesis generation, or the bounded canonical context of one saved hunt for later stages | Draft hypothesis, plan, query, finding organization, or outcome for that hunt stage | It does not search the unified corpus or enterprise telemetry, and it never saves or advances the hunt automatically |

Use RAG to find and compare leads; use the hunt assistant only after deciding
which reviewed lead justifies a specific hunt. Neither assistant searches the
SIEM, EDR, data lake, or cloud control plane.

Example: scope an Israel technology-company hunt from actor-linked IOCs and
supported TTPs.

1. In **ATT&CK Navigator → AI RAG assistant**, select a saved business profile
   containing the reviewed region, sector, technologies, and crown-jewel
   categories. The profile affects deterministic retrieval/reranking and is not
   itself evidence that an actor targets the organization.
2. Select **IOCs**, **Actors**, **TTPs**, and the report sources relevant to the
   question. Add **Assets** only when local inventory context is necessary; that
   makes the request legally sensitive and local-provider-only.
3. Use **Search evidence** first:

   ```text
   Find recent actor-linked IOCs relevant to this saved profile. Separate the
   stored actor/sector observation, the IOC relationship, and the business
   relevance inference. Show freshness and source limitations.
   ```

4. Open the returned source routes. Verify observation type/value, actor ID,
   IOC type/value, relationship evidence, confidence, source, TLP, and dates.
   Reject stale or unsupported links. A shared actor ID is a pivot, not local
   compromise evidence.
5. If a behavioral map is useful, use **Generate grounded answer**:

   ```text
   From only these cited actor, IOC, campaign, report, and CVE records, propose
   the Enterprise ATT&CK techniques that could guide a local hunt. Explain each
   mapping and create a Navigator proposal. Do not claim targeting, execution,
   detection, or compromise.
   ```

6. Review citations and technique rationales. Preview the proposal, review the
   Add/Replace diff, explicitly confirm it, and save a named layer separately
   only if the reviewed map should persist. Confirmation changes the browser's
   in-memory selection; it does not create a threat hunt.
7. Create a new hunt from the reviewed technique or through the normal Threat
   Hunting workflow. Write a falsifiable local hypothesis that names the actual
   assets, identities, time window, expected telemetry, counter-evidence, and
   authorization. Record the authoritative RAG source routes/IDs as research
   context and label the relevance step as an inference.
8. Use stage-specific Threat Hunting AI only if a draft plan or analytic would
   help. Recheck every proposed field against the reviewed RAG sources and local
   schema, then save through the ordinary hunt form. The RAG answer and
   Navigator proposal are not hunt evidence.
9. Execute the reviewed query in the authorized external telemetry platform and
   record its backend job ID, effective range, coverage, errors, result count,
   and evidence references in the hunt. Only those run records and reviewed
   events support a local disposition.
10. After the hunt changes, wait for the next RAG reconciliation or ask a
    `manage_feeds` user to queue one before expecting the updated canonical hunt
    to appear in cross-source retrieval.

This flow deliberately prevents an AI feedback loop. Assistance answers and raw
provider output are not indexed as source documents. If an analyst reviews
material and saves it into a canonical hunt, the next reconciliation can index
the allowlisted hunt fields as a legal-sensitive source. Query-version and
finding tables are not independently collected by the unified corpus, and an
unsaved draft is never searchable.

### 3.4 Start from the Query Library or an IOC set

Use **Hunt & Validate → Query Library** when you already know the behavior, rule,
format, ATT&CK technique, or observable to investigate.

To start from an existing rule:

1. Search by ordinary terms or typed filters such as `ttp:T1059.001`,
   `tag:persistence`, `lang:yaral`, `source:"SigmaHQ Rules"`, or
   `platform:Windows`.
2. Open the result and inspect its source URL, license context, parser or quality
   state, mapped techniques, required data, and rule body.
3. Select **Create hunt from query**. The platform transfers the query, language,
   description, tags, supported ATT&CK mappings, source context, and a hypothesis
   shell into a new hunt draft.
4. Replace generic scope and fields with local values. A community rule may be
   useful and still be wrong for the local schema, retention, baseline, or
   authorization boundary.
5. Save the hunt to create its first immutable query revision.

To build from observables:

1. Select **Build query from IOCs**.
2. Enter one observable per line or prefix it with a type such as
   `ip:203.0.113.10`. Supported automatic types include IPv4/IPv6, domain, URL,
   email, MD5, SHA-1, and SHA-256.
3. Choose the destination format and add only ATT&CK IDs supported by
   investigation evidence.
4. Build the deterministic local query, inspect escaping and field mappings,
   then copy it or select **Create hunt from query**.
5. Time-bound the observable, verify its provenance and confidence, and extend
   the hunt to behavior around the match. Do not make a match equal a verdict.

The Query Library can index reviewed built-in content and bounded community
content synchronized through Pipeline. Provenance-derived stable keys prevent a
normal feed refresh from creating a new duplicate for the same upstream rule.

## 4. Run the query and record findings

### Stage 2: Query and telemetry

Open **Query and telemetry** and treat the page as the reviewed analytic record:

1. Select **Query type** before writing or generating content. Supported values
   are generic, Sigma, KQL, SPL, EQL, Lucene, SQL, osquery, YARA, YARA-L 2.0
   for Google SecOps UDM, and other.
2. Enter or paste the analytic in **Hunt query**, or select **Generate query**,
   choose the target language in the assistant, and review the proposed text.
   Use **Use … query draft** or **Replace query with … draft** only when the
   language and assumptions are correct.
3. Complete **Telemetry sources** and **Required fields**. Include join keys,
   event and ingest timestamps, actor and target identity, process ancestry,
   object identifiers, and outcome fields needed to test the hypothesis.
4. Set the actual **Start** and **End** boundary. Record time zone, retention,
   late-arrival behavior, and known gaps in **Assumptions and limitations**.
5. Define **Expected evidence** and **False-positive considerations** before
   looking at the result. This reduces post-hoc reinterpretation.
6. Save the hunt. Material query or assumption changes append a query version
   with version number, checksum, timestamp, language, and attribution; they do
   not erase earlier logic.
7. Have a second analyst or platform owner validate syntax, field mappings,
   exclusions, cost, cardinality, time range, and safety in the destination
   product.
8. Change the hunt to `running` only when the external execution actually
   starts. Select **Copy query**, paste it into the approved platform, and run it
   with a read-only identity and bounded scope.
9. Record the external job reference, effective parameters, population,
   coverage, result count, warnings, and errors in the result summary or linked
   evidence system.

Changing **Query type** does not translate existing text. AI-generated and
community queries remain unvalidated until the destination platform accepts the
syntax and a human reviews the data model and behavior.

### Stage 3: Findings

Return to AdversaryGraph, open **Findings**, and create one finding for each
material evidence cluster—not one finding per raw row.

For every finding:

- use a precise title and concise summary;
- keep the initial status `new` until another analyst reviews it;
- select `supports`, `refutes`, `inconclusive`, or `benign` independently of
  the final hunt disposition;
- set severity from impact and confidence from evidence quality; do not use one
  as a substitute for the other;
- select an evidence type and add a case-safe **Evidence reference**;
- add the event time with an explicit time zone where known;
- add only relevant observables and evidence-supported ATT&CK techniques;
- preserve the producing query-version link; and
- record alternative explanations, validation steps, and limitations in notes.

Use **AI assist findings** to organize analyst-selected summaries or expose
contradictions, not to manufacture evidence. **Open editable draft** creates
only an unsaved form. Add the authoritative evidence reference and review all
fields before selecting **Save finding**.

Move findings through `new`, `reviewed`, `escalated`, and `closed`. Set the hunt
to `review` when execution has ended and the evidence set is ready for the final
decision. If the query failed or the data was unfit, preserve that fact rather
than creating a clean-looking negative result.

## 5. Review, decide, and hand off

### Stage 4: Outcome and handoff

Open **Outcome and handoff** and write a result summary that another analyst can
review without relying on memory or chat history. Include:

- the hypothesis and searched population;
- actual backend, data sources, effective interval, and coverage;
- producing query version and external run reference;
- supporting, refuting, benign, and unresolved findings;
- missing assets, failed sensors, late data, parser errors, or result limits;
- the analyst decision and confidence; and
- follow-up owner, destination object ID, and rerun condition where applicable.

Select the narrowest supported disposition:

| Disposition | Use it when |
|---|---|
| `no_matches` | No matching evidence appeared in the fit-for-purpose data actually searched |
| `benign` | Reviewed matches have a supported benign explanation |
| `benign_policy_relevant` | Activity is benign in intent but violates or changes policy/risk |
| `suspicious` | Reviewed evidence supports escalation but does not justify a confirmed-malicious claim |
| `confirmed_malicious` | Authoritative reviewed evidence supports the malicious conclusion |
| `inconclusive` | Evidence cannot resolve the hypothesis |
| `telemetry_gap` | Missing, incomplete, delayed, or untrustworthy data prevents a defensible answer |
| `query_failure` | The analytic or external execution failed |

`undetermined` is the working default, not a completion outcome. Completion of
`suspicious` or `confirmed_malicious` work requires reviewed supporting
evidence, and unresolved `new` findings must be reviewed or archived.

Use the handoff controls deliberately:

1. **Open Operations** for investigation, response, remediation, or detection
   tracking.
2. **Open Evidence Graph** when the source, claim, behavior, ATT&CK mapping,
   telemetry, query, finding, validation, and decision need a durable reasoning
   chain.
3. **Open Attack Simulation** only with `run_attack_simulation` permission and
   an authorized, isolated, compatible allowlisted scenario.
4. Open Pipeline separately when the result should become governed detection
   content.
5. Record every new destination object ID or simulation `run-<UUID>` in the
   result summary, finding notes, or an analyst context tag. Opening a module
   does not automatically create or synchronize an object.
6. Select `completed` only after peer review and ownership of follow-up work.
   Select `archived` later when the retained record is no longer operationally
   active.

## 6. What AdversaryGraph preserves

The following object boundaries make a hunt reviewable:

| Object | Purpose |
|---|---|
| Threat Hunt | Hypothesis, scope, owner, lifecycle, priority, and disposition |
| Technique relationship | ATT&CK object/version, tactic context, and mapping rationale |
| Telemetry requirement | Source/channel/component, fields, coverage, retention, quality, and gap state |
| Query version | Immutable abstract/native/Sigma content, checksum, mapping, reviewer, and tests |
| Hunt run | Resolved parameters, connector, effective range, execution metadata, limits, and result state |
| Evidence | Source reference, integrity, time, handling, and normalized excerpt |
| Finding | Evidence cluster, observables, interpretation, confidence, severity, status, and analyst |
| Review | Reviewer, decision, challenges, approval, and timestamp |
| Schedule | Frequency, lookback, late-data policy, owner, analytic version, and retirement rule |
| Connector | Backend metadata, secret reference, allowlist, permissions, limits, and health—not raw credentials |

## 7. Move through the AdversaryGraph ecosystem

Threat Hunting is most useful when each module has a clear role:

| Module | Use before or during the hunt | Carry into the hunt | Do not infer |
|---|---|---|---|
| **Reports / Research** | Preserve a source and reviewed extraction | Source reference, citations, supported actor/behavior leads, TLP | The report describes local activity |
| **Unified Intelligence RAG** | Search allowlisted IOC, CVE, ATT&CK/ATLAS, actor, campaign, report, hunt, Evidence Graph, and sanitized asset context | Reviewed source routes, cited facts, and explicitly labeled relevance inferences | The generated answer is evidence or has searched enterprise telemetry |
| **Threat Radar** | Prioritize external signals against monitored business context | Signal reference, affected product/asset assumption, exploitation behavior to test | External relevance means local compromise |
| **ATT&CK Group Library** | Verify group identity, aliases, campaigns, and supported techniques | Reviewed group and technique identifiers with evidence links | Actor attribution from technique overlap alone |
| **Navigator** | Inspect techniques, Detection Strategies, data requirements, and related behavior | Reviewed ATT&CK selection and a scoped hunt draft | Selecting or coloring a cell proves coverage |
| **IOC Library / IOC Investigation** | Review provenance, freshness, relationships, and enrichment | Time-bound observable and behavior-focused pivots | An IOC match is malicious without context |
| **CVE Library** | Identify prerequisites, affected assets, exploitation context, and likely post-exploitation behavior | Affected product/version scope and observable behaviors | A CVE ID in logs proves exploitation |
| **Asset Surface / company space** | Identify exposed assets, owner, criticality, services, and discovered surfaces | Authorized asset population, owner, exposure, and limitations | Passive OSINT or scanner output is complete |
| **Query Library** | Find reviewed and community analytics or build a local query from IOCs | Source-backed rule, language, tags, mappings, and query draft | Imported content is production-ready |
| **RetroHunt Signals** | Search historical platform intelligence and relationships | Relevant stored reports, indicators, mappings, and dates | RetroHunt searched the SIEM or EDR |
| **Evidence Graph** | Preserve reasoning across sources, claims, mappings, queries, findings, and decisions | Durable graph object ID | Opening the module created or synchronized a graph |
| **Operations / Pipeline** | Manage incident, remediation, or detection engineering after review | Hunt ID, exact query version, finding references, validation needs | A handoff button deployed a rule |
| **Attack Simulation** | Validate a compatible analytic and telemetry path in an isolated lab | Scenario, run ID, observations, failed stage, and limitations | One lab pass proves universal production coverage |
| **Investigation Report** | Produce the reviewed human handoff | Necessary findings, references, decisions, and limits | Raw secrets or unnecessary personal data should be copied into the report |

The handoff principle is simple: carry identifiers and reviewed evidence
references between modules, preserve provenance, and record the inference made
at each step. Do not turn navigation between pages into a claim of automatic
data synchronization.

## 8. Ten worked AdversaryGraph use cases

These examples show how an analyst uses the current Threat Hunting workspace,
not a proposed future connector. Names, object identifiers, event references,
counts, and time ranges are illustrative. In every example, AdversaryGraph
preserves the hypothesis, plan, query revisions, evidence references, findings,
review, and outcome. The analyst runs the copied query in an authorized external
telemetry platform and records enough provenance to make the result reviewable.

| Use case | AdversaryGraph entry or capability | Demonstrated outcome |
|---|---|---|
| Threat Radar signal | Implemented case-to-hunt API/workflow | Reviewed `suspicious` identity hunt with a manual Operations reference |
| Navigator technique | T1059.001 deep link and context tags | Evidence-led PowerShell escalation |
| Discover selection | Multi-technique draft | Correlated Linux intrusion sequence |
| Built-in template | Scheduled-task starting plan | Tuned query and reviewed finding |
| Query peer review | Append-only query history | Reproducible version-to-finding relationship |
| External EDR result | Findings and `evidence_ref` ledger | `confirmed_malicious` LSASS outcome without raw-log duplication |
| Incomplete telemetry | Readiness, assumptions, and disposition | Honest `telemetry_gap` result and remediation reference |
| Defensive handoff | Operations and Evidence Graph links | Manually recorded destination identifiers |
| Restricted evidence | TLP raising, JSON export, and archive | Portable, read-only operational history |
| Detection improvement | Operations, separate Pipeline work, and compatible simulation | Traceable hunt-to-detection validation chain |

### 8.1 Turn a Threat Radar signal into a locally scoped hunt

**Situation.** Threat Radar contains a reviewed case describing a campaign that
uses valid accounts and adds a second authentication method. The intelligence is
relevant, but it does not establish that the organization is affected.

**Platform steps.**

1. Invoke the implemented Threat Radar create-hunt API/workflow for the case.
   AdversaryGraph creates a `queued` hunt and assigns trusted
   `source_type=threat_radar` provenance plus the source case UUID in
   `source_ref`; the analyst does not edit those fields. The current Threat
   Radar page does not render a create-hunt button, so operators using only the
   UI begin from the queued record after an authorized integration invokes the
   workflow.
2. Open the hunt and rewrite the intelligence claim as a local hypothesis: “If
   the campaign used a workforce identity in tenant `corp-prod`, a successful
   sign-in from a previously unseen device should be followed within 30 minutes
   by authentication-method or privilege changes.”
3. Set priority from local exposure, add T1078 and T1098, and scope the hunt to
   the production tenant, workforce identities, and the 14 days covered by
   complete identity and cloud-audit retention. Exclude documented break-glass
   tests and record the relevant change-ticket prefix.
4. Add identity-provider sign-ins, MFA events, cloud audit logs, and device
   inventory as telemetry. Record the required user, source, device, result,
   target, action, event-time, and ingest-time fields.
5. Store a generic correlation analytic, its expected evidence, travel/VPN and
   help-desk alternatives, and the assumption that device identifiers are
   stable. Move the hunt from `queued` to `planned` only after this readiness
   information is present.
6. Copy the query into the approved identity analytics platform. When execution
   starts, set the hunt to `running`; record the external job ID, query version,
   effective UTC interval, tenant, result count, and any throttling in the result
   summary.
7. For each material identity sequence, create a finding with the external event
   or case reference, observables, T1078/T1098 mapping, confidence, severity, and
   the query-version link. Review the findings before setting the hunt to
   `review` and selecting the final disposition.

**Example outcome.** Two sequences are explained by approved device replacement
and close as `benign`; one newly registered method lacks a ticket and produces a
reviewed finding with verdict `supports`. The hunt is completed as `suspicious`,
and the analyst opens Operations for incident handling and records the resulting
case ID in the result summary or an analyst context tag. The Radar signal remains
provenance, not proof of the local finding.

### 8.2 Start with one ATT&CK technique in Navigator

**Situation.** A coverage review in Navigator identifies T1059.001 PowerShell as
important for a Windows administration tier, but the team wants to test the
behavioral evidence rather than hunt on the technique label alone.

**Platform steps.**

1. In the Navigator technique panel, choose **Create threat hunt**. The new-hunt
   route preselects T1059.001 and records analyst launch context in tags such as
   `context:navigator` and `context-ref:T1059.001`; these tags are context, not
   server-assigned provenance.
2. State a falsifiable hypothesis covering encoded arguments, runtime decoding,
   unusual parent processes, and linked file or network behavior. Add T1027 only
   if the planned evidence can distinguish actual obfuscation.
3. Limit scope to managed Windows endpoints in the administration tier for the
   last seven days. Add process creation, EDR ancestry, and PowerShell Script
   Block Logging; record hosts without script logging as an explicit limitation.
4. Select KQL, SPL, EQL, YARA-L 2.0 (Google SecOps UDM), or another language matching the destination. Replace
   illustrative field names with the organization’s schema, document approved
   deployment systems as alternatives, and save the hunt as `draft` while it is
   peer reviewed.
5. After the scope, telemetry, expected evidence, and false-positive notes pass
   readiness, save as `planned`. Copy the query to the approved platform, begin
   the authorized search, and move to `running`.
6. Record related execution chains as findings rather than copying every hit.
   Preserve case-safe external event references and note whether decoded content
   is analyst-derived. Move to `review` for the final decision.

**Example outcome.** The query returns 84 encoded commands. Clustering shows 82
from a signed deployment agent and two from a spreadsheet process on one finance
host. A reviewed finding links the rare process chain and outbound connection;
the hunt completes as `suspicious`. Navigator supplied the starting technique,
while endpoint evidence supplied the conclusion.

### 8.3 Build a multi-technique hunt from Discover

**Situation.** During research in Discover, an analyst selects T1105 Ingress Tool
Transfer, T1059.004 Unix Shell, and T1082 System Information Discovery. The goal
is to test whether the sequence occurred on internet-facing Linux systems.

**Platform steps.**

1. Select the three TTPs in Discover and create a threat hunt. Verify that all
   intended technique IDs appear in the draft and that the launch context tag is
   present.
2. Do not turn the selection into three disconnected keyword searches. Write one
   sequence hypothesis: an exposed service process downloads a file, a shell
   executes it, and host-discovery commands follow within a bounded interval.
3. Scope the hunt to the current internet-facing Linux inventory and the period
   for which process, file, DNS, and egress telemetry overlap. Record excluded
   ephemeral workloads and late-ingest behavior.
4. Add parent/child entity IDs, command line, executable and file hashes, user,
   container or host identity, destination, event time, and ingest time as
   required fields. Explain how package managers, bootstrap scripts, and health
   checks will be distinguished.
5. Save a first query version that correlates the sequence by host or workload.
   Execute it externally and record the backend job reference, result count, and
   time zone. If peer review changes the time window or allowlist, save the
   modified query; AdversaryGraph creates another append-only revision.
6. The UI links each new finding to the latest query revision. Create it while
   the producing revision is latest, or use the findings API with an explicit
   `query_version_id` for an older run. Document whether all three behaviors,
   only a partial sequence, or counter-evidence were observed.

**Example outcome.** One chain is an approved image bootstrap and closes
`benign`; a second begins under a vulnerable web-service account, downloads from
a first-seen domain, and runs reconnaissance. The reviewed evidence supports a
`confirmed_malicious` disposition and an Operations handoff. The original
Discover selection remains visible as reproducible analyst context.

### 8.4 Adapt a built-in template instead of treating it as finished content

**Situation.** The team wants to hunt for scheduled-task persistence. The
AdversaryGraph dashboard offers the **Unexpected scheduled-task persistence**
template with T1053.005, starting telemetry requirements, expected evidence, and
false-positive guidance.

**Platform steps.**

1. Select the template from the dashboard or the new-hunt workspace. Confirm the
   `template:scheduled-task-persistence` tag and review every populated field.
2. Replace the generic scope with named Windows device groups, owner, UTC range,
   retention boundary, and exclusions. Add the organization’s Task Scheduler,
   process, registry, and EDR sources.
3. Translate `task.name`, `task.action`, creator, host, hash, and command fields
   to the actual schema. Add a local baseline for software distribution,
   patching, inventory, and approved administrator task creation.
4. Change the generic query to the destination language. Constrain task creation
   and modification to the covered interval, enrich action paths and creators,
   and keep rare or hidden tasks for review rather than declaring them malicious.
5. Save as `draft`, obtain platform-owner review of the syntax and exclusions,
   then move to `planned`. Copy and execute query version 1 externally.
6. If the first run is dominated by an approved maintenance product, add a
   time-bounded, owner-backed exclusion and save query version 2. Do not overwrite
   or disguise the first revision.
7. Create findings from the materially distinct task clusters, attach external
   event references, and record which query version generated each finding.

**Example outcome.** Version 1 produces 1,430 rows; version 2 reduces these to
four clusters without deleting the audit trail. Three have current change
records. One launches an unsigned binary from a user-writable directory and is
reviewed as supporting evidence. The hunt completes `suspicious`, while the
template remains accurately described as a starting point.

### 8.5 Preserve query peer review with append-only revisions

**Situation.** A DNS-beaconing hunt is technically ready, but a second analyst
finds that the original query calculates intervals using ingest time rather than
event time and lacks an asset-class partition.

**Platform steps.**

1. Create the hunt from the periodic DNS/TLS template and tailor its scope,
   telemetry, and schema mappings. Save the initial analytic as query version 1.
2. During peer review, record the identified assumptions and limitations. Edit
   the stored query to use event time, calculate jitter per source/destination,
   partition workstations from servers, and require a minimum observation count.
3. Save the hunt. AdversaryGraph appends query version 2 with its checksum,
   timestamp, language, analyst attribution, and assumptions; version 1 remains
   available in query history.
4. Run version 2 in the authorized DNS or network platform. Record the external
   job ID, lookback, source indexes, effective time range, row limit, and errors.
5. If a preflight finding must link to version 1, create it through the findings
   API with that `query_version_id`; the current UI automatically links a new
   finding to the latest revision. Create findings from the reviewed run while
   version 2 is latest so later readers do not infer that one analytic generated
   all evidence.
6. In the result summary, explain the material effect of the change rather than
   merely stating “query updated.”

**Example outcome.** Version 1 overstates periodicity because delayed events
arrive in batches. Version 2 removes those clusters and identifies one persistent
low-jitter relationship from a workstation to rare infrastructure. The analyst
can reproduce which logic supported the `suspicious` finding without relying on
an editable query box or chat history.

### 8.6 Convert external results into reviewed findings

**Situation.** An LSASS-access query has been run in the enterprise EDR. The
external job returns process-access events, diagnostic software, and two dump
artifacts. The team needs a compact evidence record without copying sensitive raw
telemetry into AdversaryGraph.

**Platform steps.**

1. Set the planned hunt to `running` when the EDR job actually starts. In the
   result summary, record a case-safe job reference, the tenant, UTC interval,
   query revision, host population, sensor coverage, result count, and any failed
   shards or inaccessible endpoints.
2. Cluster results by host, actor process, signer, access pattern, dump path, and
   follow-on authentication. Do not create one finding per raw row.
3. For each material cluster, add a finding with title, severity, confidence,
   status `new`, verdict, event time, observables, T1003.001 when supported,
   linked query version, evidence reference, TLP marking, and concise notes.
4. Use `supports`, `refutes`, `inconclusive`, or `benign` as the finding verdict;
   keep the hunt disposition separate until the population has been reviewed.
5. A second analyst verifies the EDR evidence, corrects the finding record if
   needed, and changes its status to `reviewed`, `escalated`, or `closed` as
   appropriate. Archive superseded or duplicate findings through the finding
   controls so they remain in the exported audit history.
6. Move the hunt to `review`. Before completion, resolve or archive every `new`
   finding and write a result summary covering both supporting and
   counter-evidence.

**Example outcome.** A signed diagnostic tool with a current change record is
closed `benign`. An unsigned process and dump artifact on a domain controller are
reviewed with verdict `supports`, and the external EDR case URI is retained in
`evidence_ref`. The hunt completes `confirmed_malicious`; AdversaryGraph records
the decision trail but does not claim custody of the original EDR events.

### 8.7 Record a telemetry gap without manufacturing a clean result

**Situation.** A web-shell hunt is approved for 42 internet-facing servers, but
11 lack process telemetry and eight have web logs retained for only two of the
requested seven days.

**Platform steps.**

1. Create the hunt from the web-shell template and list all 42 systems in scope.
   State the hypothesis around web-service child processes, executable content in
   served directories, suspicious requests, and outbound connections.
2. Add web, process, file-integrity, authentication, and network sources with
   their required fields. Record the expected asset count, retention, sensor
   health, and ingestion delay in assumptions or scope.
3. Run coverage preflights in the relevant external systems before the main
   analytic. Record the job references and measured coverage in the result
   summary.
4. Execute the behavioral query only across covered assets and intervals. If no
   matches occur, describe that bounded result exactly; do not generalize it to
   the entire fleet or seven-day period.
5. Create findings only for material evidence clusters. Represent absent
   telemetry in the hunt outcome and in an externally referenced Operations
   remediation item, not as fabricated zero-valued events.
6. Move to `review`, select `telemetry_gap`, name owners for endpoint-sensor and
   web-log remediation, and include a rerun condition. No supporting finding is
   required for this disposition, but the result summary is required.

**Example outcome.** The covered subset has no matches, yet only 31 of 42 servers
have adequate process evidence and complete web-log overlap is lower still. The
hunt completes `telemetry_gap`, not `no_matches`. The analyst opens Operations,
creates remediation work, and records its ID plus the planned rerun date in the
summary.

### 8.8 Complete a suspicious hunt and preserve the defensive handoff

**Situation.** A valid-account hunt produces an unusual successful sign-in,
privilege change, and access to a sensitive cloud resource. The evidence is
strong enough for response but not yet sufficient to claim confirmed malicious
activity.

**Platform steps.**

1. Create one finding for the correlated sequence with verdict `supports`, then
   add the identity, source network, device ID, target resource, event time,
   external evidence reference, T1078 mapping, severity, confidence, and query
   version.
2. Have an analyst verify the finding and change its status from `new` to
   `reviewed` or `escalated`. Completion with `suspicious` is blocked until a
   reviewed supporting finding exists.
3. Move the hunt from `running` to `review`. Write a summary containing searched
   scope, effective interval, data fitness, analytic revision, evidence for and
   against the hypothesis, limitations, and the requested response action.
4. Select `suspicious` and complete the hunt only after all other new findings
   have been reviewed or archived.
5. In **Outcome and handoff**, open Operations. Create the investigation or
   detection object there, then return and record its object ID in the result
   summary, an analyst context tag, or the editable finding notes.
6. If the reasoning chain needs durable representation, open Evidence Graph and
   create it explicitly. Record that new object’s ID as well; opening the link
   does not automatically synchronize objects.

**Example outcome.** The hunt is completed `suspicious`, and the summary
references Operations case `IR-2841` and Evidence Graph object
`EG-91c2`. Reviewers can follow the handoff without the guide falsely claiming
automatic incident creation or bidirectional synchronization.

### 8.9 Raise handling restrictions, export, and archive

**Situation.** A hunt begins with ordinary internal operational data at
`TLP:GREEN`, then a finding references sensitive identity and credential-access
evidence that requires `TLP:AMBER+STRICT` handling.

**Platform steps.**

1. Raise the hunt marking to `TLP:AMBER+STRICT` before adding the restricted
   reference. AdversaryGraph propagates the stricter marking to existing
   findings; it does not permit a later downgrade through the normal update
   path. This preserves label integrity; it is not recipient-level access
   control, so enforce authorization in the surrounding deployment.
2. Keep secrets, raw credentials, tokens, unnecessary personal data, and
   unrestricted screenshots out of query text, notes, and findings. Use a
   controlled case or evidence reference instead.
3. Complete the hunt through the normal review gate. Use **Export JSON** to
   produce the portable record containing the hunt, archived and active
   findings, and all query versions.
4. Read the export boundary statement: the package proves what AdversaryGraph
   preserved, not that it executed the external query. Transfer and store the
   export according to its TLP marking and the organization’s retention policy.
5. When active work and follow-up ownership are complete, archive the hunt. The
   record becomes read-only operational history; export and destination links
   remain available.

**Example outcome.** A reviewer receives a portable historical package with
append-only query versions 1–3, their checksums and attribution, two active
findings, one archived duplicate, and the final decision. The package contains
case-safe references rather than restricted raw events, and its higher TLP
marking makes the handling expectation explicit.

### 8.10 Turn a hunt result into detection and safe validation work

**Situation.** A Unix download-and-execute hunt repeatedly identifies a rare
sequence that is valuable enough for continuous detection. The team wants to
validate it without implying that a past hunt result proves future coverage.

**Platform steps.**

1. Finish the hunt review with the supporting findings linked to the exact query
   revision. In the result summary, state the stable behavioral features, known
   benign patterns, data dependencies, missed variants, and recommended
   detection severity.
2. In **Outcome and handoff**, open Operations for investigation or detection
   work and record the new object ID back in the hunt. If the organization uses
   Pipeline for governed detection engineering, navigate to Pipeline separately,
   create the candidate there, and record its ID; Pipeline is not one of the
   Threat Hunting handoff links, and the hunt does not deploy content.
3. Translate the hunt analytic into reviewed Sigma or a destination-native
   detection. Add field mappings, lookback, grouping, threshold, suppression
   owner and expiry, test fixtures, and rollback instructions in the destination
   workflow.
4. Open Attack Simulation only for an authorized isolated lab. Select a
   compatible predefined, allowlisted scenario when one is available and verify
   source, collection, transport, parsing, indexing, query, and alert behavior
   end to end. If no compatible scenario exists, document the proposed
   validation instead of implying that an arbitrary command can be executed.
5. Open Evidence Graph when the team needs a durable chain connecting the CTI or
   original hypothesis, ATT&CK behaviors, telemetry requirement, query revision,
   reviewed finding, detection candidate, lab validation, and decision. Record
   each resulting object ID manually in the hunt.
6. If validation fails, preserve whether the defect is in telemetry, parsing,
   analytic logic, or alert routing. Revise and retest; a successful lab run is
   evidence for that test path, not proof of universal production coverage.

**Example outcome.** The hunt completes `confirmed_malicious`, Operations tracks
the response, and Pipeline tracks detection candidate `DET-417`. A compatible
Attack Simulation scenario returns a run ID in the form `run-<UUID>`; if no
compatible scenario is available, the summary records validation as proposed.
A parser defect found during the first compatible test is corrected before the
second passes. The hunt summary stores the available references and limitation,
providing a defensible chain from hypothesis to maintained defensive work.

## 9. Real open-source example: Play ransomware backdoor hash

This example uses a real public indicator from a primary government source. It
is safe to reproduce as text for defensive matching; **do not download or
execute the associated file**.

### 9.1 Verify and classify the source

The joint CISA, FBI, and Australian Signals Directorate advisory
[#StopRansomware: Play Ransomware (AA23-352A)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)
was last revised on 4 June 2025. Its updated IOC table says the indicators were
obtained from FBI investigations as of January 2025. The table identifies this
SHA-256 value as an `SVCHost.dll Backdoor` associated with Play ransomware
actors:

```text
47B7B2DD88959CD7224A5542AE8D5BCE928BFC986BF0D0321532A7515C244A1E
```

The advisory was checked for this guide on 25 July 2026. Record the source facts
separately from analyst interpretation:

| Field | Value to preserve |
|---|---|
| Publisher | CISA, FBI, and ASD's ACSC |
| Advisory | AA23-352A, #StopRansomware: Play Ransomware |
| Source revision | 4 June 2025 |
| Source observation boundary | FBI investigation IOCs as of January 2025 |
| Indicator type | SHA-256 |
| Source description | `SVCHost.dll Backdoor` |
| Handling | Public advisory / TLP:CLEAR |
| Local observation | Unknown until the enterprise hunt runs |

This is a historical, source-reported malicious indicator, not a guarantee of
current prevalence. The advisory also warns that Play ransomware binaries are
recompiled for individual attacks, producing unique hashes. Therefore, an exact
hash hunt is a high-confidence retrospective check for one known artifact, but
it is not sufficient coverage for Play ransomware.

### 9.2 Store the source and IOC in AdversaryGraph

1. Open **Reports / Research** and store the advisory title, publisher, source
   URL, revision date, source text or approved excerpt, and `TLP:CLEAR`.
2. Complete report analysis and review the extracted entities. Keep the
   advisory's ATT&CK version in source metadata; revalidate each technique
   against the platform's current ATT&CK data before using it in a hunt.
3. Open **IOC Library** or the report-to-IOC workflow and add the full SHA-256
   value. Preserve the advisory URL as provenance. Do not invent first-seen,
   last-seen, confidence, or victim data that the advisory does not provide.
4. If approved enrichment providers are configured, query the hash by value.
   Do not upload a private binary or customer artifact to a public service.
   Record provider timestamps and disagreements rather than replacing the
   primary source.
5. Search for an existing normalized SHA-256 record before saving. If the same
   value already exists, add the new source relationship or observation instead
   of creating a duplicate indicator.

### 9.3 Create the hunt from Query Library

Open **Hunt & Validate → Query Library → Build query from IOCs** and enter:

```text
sha256:47B7B2DD88959CD7224A5542AE8D5BCE928BFC986BF0D0321532A7515C244A1E
```

Choose the format used by the destination telemetry platform. For this example,
select **KQL**, build the deterministic query, inspect the field mappings, and
select **Create hunt from query**.

Complete **Plan and scope** with reviewed local values:

| Hunt field | Example content |
|---|---|
| Title | Play-associated SVCHost.dll backdoor retrospective |
| Hypothesis | If the CISA-reported backdoor reached covered Windows endpoints during the retained period, file or process telemetry will contain the published SHA-256 and may show related execution, service, discovery, transfer, defense-evasion, or lateral-movement activity on the same device and timeline. |
| Description | Source-backed retrospective check derived from CISA AA23-352A; exact hash matching is followed by behavior review and does not independently establish Play attribution. |
| Scope | Managed Windows workstations and servers with EDR coverage; previous 90 days or the maximum common retention period; exclude lab and malware-research systems but report them separately if matched. |
| Owner | Named threat-hunting analyst and peer reviewer |
| Priority | Set from local exposure and asset criticality; do not derive it from the malware family name alone |
| TLP | `TLP:AMBER` for the local hunt even though the public source is TLP:CLEAR |
| Tags | `source:cisa-aa23-352a`, `ioc:sha256`, `play-ransomware`, `retrospective`, `windows` |

Do not automatically attach every technique in the advisory to this single
hash. Add a technique only when the source or local evidence supports the
relationship. Candidate behaviors from the advisory that may guide follow-up
include PowerShell (`T1059.001`), remote file copy (`T1570`), impairing defenses
(`T1562.001`), clearing Windows event logs (`T1070.001`), and data encryption
for impact (`T1486`). Technique overlap alone must not be used to attribute a
local event to Play.

### 9.4 Define telemetry and interpretation criteria

In **Query and telemetry**, record:

- **Telemetry sources:** EDR file and process events, antivirus detections,
  Windows service creation, Windows Security and Sysmon events, network
  connections, identity events, and file inventory where available.
- **Required fields:** event and ingest timestamps, device and tenant IDs,
  hostname, file name and path, SHA-256, process and initiating-process hashes,
  process command line, parent process, signer, account, service name, remote
  host, destination address, action, and sensor health.
- **Expected evidence:** an exact hash match in file, process, quarantine, or
  security-product telemetry, followed by a reviewable device timeline.
- **Counter-evidence:** the only copy is in an isolated malware-research
  repository; the event is an antivirus quarantine with no execution; or the
  source record is demonstrably misclassified.
- **False-positive considerations:** cryptographic collision is not a practical
  explanation, but security-product caches, controlled research collections,
  detonation systems, and restored forensic images can contain known-malicious
  files without indicating active compromise.
- **Limitations:** missing SHA-256 collection, short retention, offline devices,
  sensor failures, compressed or memory-only artifacts, renamed files, and
  unseen recompiled variants.

The generated Query Library draft must be adapted to the actual backend. A
Microsoft Defender XDR Advanced Hunting starting point could be:

```kusto
let play_backdoor_sha256 =
    "47B7B2DD88959CD7224A5542AE8D5BCE928BFC986BF0D0321532A7515C244A1E";
union
(
    DeviceFileEvents
    | where SHA256 =~ play_backdoor_sha256
    | project Timestamp, DeviceId, DeviceName,
              EvidenceType = "file",
              FileName, FolderPath,
              MatchedSHA256 = SHA256,
              AccountName = InitiatingProcessAccountName,
              ProcessCommandLine = InitiatingProcessCommandLine,
              ReportId
),
(
    DeviceProcessEvents
    | where SHA256 =~ play_backdoor_sha256
        or InitiatingProcessSHA256 =~ play_backdoor_sha256
    | project Timestamp, DeviceId, DeviceName,
              EvidenceType = "process",
              FileName, FolderPath,
              MatchedSHA256 = iff(
                  SHA256 =~ play_backdoor_sha256,
                  SHA256,
                  InitiatingProcessSHA256
              ),
              AccountName,
              ProcessCommandLine,
              ReportId
)
| order by Timestamp asc
```

This query is a starting point, not evidence that it was executed. Confirm table
availability, permissions, retention, SHA-256 population, field semantics, row
limits, and syntax in the destination tenant. Save the reviewed text in
AdversaryGraph to create query version 1.

### 9.5 Execute and pivot safely

1. Run a coverage preflight: measure how many in-scope devices reported file and
   process events with populated SHA-256 values during the requested period.
2. Set the hunt to `planned` after peer review and to `running` only when the
   external search starts.
3. Select **Copy query**, run it with an approved read-only hunting identity,
   and record the external job ID, tenant, interval, population, coverage,
   result count, and any timeout or truncation.
4. If there is an exact match, preserve the authoritative external event
   reference and isolate response actions from the hunt record. Follow the
   organization's incident-response process; do not use the hunting query to
   execute containment.
5. Build a device timeline around the event. Review file creation, process
   ancestry, module load, service creation, account activity, remote execution,
   network connections, defense changes, log clearing, archive creation, and
   encryption behavior.
6. Search for the related behavior across the environment even if the exact
   hash does not recur. Label those results behavioral leads. They are not hash
   matches and are not automatically attributable to Play.
7. If the exact query returns no rows, do not stop until the coverage preflight
   is reviewed. A zero-row search with poor hash population or missing devices
   is a telemetry gap, not a clean result.

### 9.6 Record findings and choose the outcome

Use **Findings → Add finding** for each material cluster:

| Observed result | Finding treatment | Possible hunt disposition |
|---|---|---|
| Exact hash executed on a production endpoint, with an authoritative event reference and corroborating activity | `supports`; high or critical severity based on asset and impact; independently reviewed and escalated | `suspicious` or `confirmed_malicious` under the organization's evidence standard |
| Exact hash found only in antivirus quarantine with no execution and complete surrounding telemetry | Record the quarantine and absence of execution; verdict depends on delivery and control evidence | `benign_policy_relevant`, `suspicious`, or `inconclusive`—not automatically `benign` |
| Exact hash exists only in an authorized isolated malware-analysis collection | `benign` for that controlled context, with repository authorization and path recorded | `benign` |
| No match with complete, fit-for-purpose coverage | No fabricated finding is needed; preserve run and coverage evidence in the summary | `no_matches`, bounded to the searched period and population |
| No match, but SHA-256 is absent on many assets or retention is incomplete | Record the measured data limitation and remediation owner | `telemetry_gap` |
| Related Play-like behavior without the published hash | Record behavior as a separate finding with supported techniques and alternative explanations | `inconclusive` or `suspicious`; do not claim Play attribution from overlap |

For a supporting match, include:

- the producing query-version ID;
- external event or case reference;
- event time and device identity;
- exact SHA-256;
- file path, signer, process ancestry, account, and relevant network context;
- evidence-supported ATT&CK techniques;
- analyst confidence and its justification; and
- alternative explanations that were tested.

Move the hunt to `review`, have a second analyst verify the external evidence,
resolve every `new` finding, and write the result summary. The summary must say
that CISA supplied the source association while local telemetry supplied—or did
not supply—the enterprise observation.

### 9.7 Hand off and validate without using live malware

If the result is suspicious or malicious:

1. Select **Open Operations**, create the investigation or incident record, and
   copy its object ID back into the hunt.
2. Select **Open Evidence Graph** to connect AA23-352A, the IOC, the query
   revision, the external run, reviewed findings, ATT&CK mappings, and the
   decision.
3. Open Pipeline separately if the exact match or a behavior analytic should
   become maintained detection content.
4. Validate the exact-hash rule using synthetic telemetry or an approved inert
   fixture with a different test hash. A cryptographic hash cannot be replaced
   while still claiming to test this exact indicator.
5. Use **Open Attack Simulation** only for an authorized allowlisted scenario
   that safely validates related telemetry and behavior. Never retrieve or
   execute the public malicious sample merely to make the rule fire.
6. Record the detection ID, simulation run ID, observed pipeline stages,
   failures, and coverage limitations in the hunt before completion.

This example produces a real, reviewable hunt from a real public IOC while
preserving the distinction among source reporting, local observation,
behavioral inference, actor attribution, and final incident determination.

## 10. Apply the twenty methodology playbooks in AdversaryGraph

The companion
[Twenty worked hunt playbooks](threat-hunting-guide.md#16-twenty-worked-hunt-playbooks)
provide the full vendor-neutral hypothesis, telemetry, analytic, procedure,
decision, and safe-validation logic. The notes below show how to preserve each
playbook in the AdversaryGraph workspace. External identifiers, counts, scopes,
and outcomes are illustrative and must be replaced with the operator's real,
case-safe evidence.

### 10.1 Encoded or obfuscated PowerShell execution
**AdversaryGraph implementation.** Start from **Suspicious encoded PowerShell
execution**, scope the draft to 620 managed Windows endpoints and a seven-day
UTC interval, and document deployment-agent and administrator activity as benign
alternatives. Translate the stored generic analytic to the approved EDR’s KQL,
save the revision, move `planned` to `running`, and execute the copied query in
that EDR. If 84 hits reduce to one unusual Office-to-PowerShell chain, add one
finding with the external case reference, process and host observables,
T1059.001/T1027, verdict `supports`, and the automatically linked latest query
version. After review, complete as `suspicious` and manually record the
Operations case ID.

### 10.2 Access to LSASS memory or credential-dump artifacts
**AdversaryGraph implementation.** Select **Credential access against LSASS**, limit
scope to domain controllers with verified process-access coverage, and store the
tenant-specific EQL translation plus diagnostic-tool assumptions. Copy and run
it in the EDR; record job `EDR-98411`, the effective interval, 38 covered hosts,
and two unreachable sensors in the result summary. Cluster signed security-tool
events separately from an unsigned process and dump-file sequence. Record the
latter as a high-severity finding with the case-safe EDR reference, host/hash
observables, T1003.001, high confidence, and verdict `supports`. Once the finding
is `reviewed` or `escalated`, a verified intrusion can support
`confirmed_malicious`; the template alone cannot.

### 10.3 Periodic DNS or TLS command-channel behavior
**AdversaryGraph implementation.** Use **Periodic DNS or encrypted-channel beaconing**,
scope it to workstations with complete DNS and EDR overlap, and save an SPL
revision that measures per-host interval jitter using event time. Execute the
copied query in the network platform and record its search SID, time range,
indexes, row limit, and late-data caveat. Suppose monitoring agents explain 57
clusters but one workstation repeatedly contacts a rare domain from an unsigned
process. Create a single reviewed finding with domain, IP, host, and process
observables; map T1071.004 only if DNS carried the behavior. Complete
`suspicious`, or use `no_matches` only when the bounded search completed with
fit-for-purpose data and zero evidence.

### 10.4 Valid-account abuse in cloud or identity systems
**AdversaryGraph implementation.** Open **Cloud or identity-provider valid-account
abuse**, define the production tenant, privileged groups, VPN ranges, emergency
accounts, and a 72-hour interval, then tailor the template to immutable identity
and session fields. Run the copied KQL in the identity platform and preserve the
external job ID. For a new-device sign-in followed by an unapproved role change,
add one finding with the user, session, device, source network, target role,
T1078 and T1098, and a case-safe audit reference. Set verdict `supports` and move
the finding out of `new`. Complete `suspicious` if compromise remains unproven;
open Operations and manually record the response object ID in the hunt.

### 10.5 Unexpected scheduled-task persistence
**AdversaryGraph implementation.** Start from **Unexpected scheduled-task
persistence**, add the managed-server groups and maintenance window, and replace
the generic fields with the organization’s Task Scheduler and EDR schema. After
external execution, a task named `InventoryRefresh` may be confirmed by its
owner and change ticket yet run a script from a user-writable temporary path.
Create a reviewed finding with verdict `benign`, T1053.005, the task/host/path
observables, and the ticket reference. Select `benign_policy_relevant`, explain
the authorized purpose and separate control weakness, then open Operations for
remediation. Record that item’s ID manually; AdversaryGraph does not create the
ticket from the handoff link.

### 10.6 Web-shell behavior on an internet-facing server
**AdversaryGraph implementation.** Choose **Web-shell behavior on an internet-facing
server**, list the 42 exposed servers, and require web, process, file-integrity,
and egress evidence. Coverage preflights in the external systems may show that
11 servers lack process telemetry and eight retain only two of the requested
seven days of web logs. Record those job references and execute the analytic
only across the covered subset. Even if that subset returns no web-service child
shells, complete the reviewed hunt as `telemetry_gap`, not `no_matches`. State
the precise covered assets and intervals, open Operations for sensor and
retention remediation, and manually record the remediation ID and rerun
condition.

### 10.7 Remote-service lateral movement
**AdversaryGraph implementation.** From Navigator, create a manual draft for the
relevant T1021 sub-technique and retain `context:navigator` as analyst context,
not trusted provenance. Scope the hunt to a server administration zone, named
jump hosts, and four hours around an alert. Store an SPL sequence correlating
source authentication, remote-service network activity, target logon, and child
processes; execute it in approved identity and endpoint tools and record both job
IDs. A connection from a workstation followed by a service-account logon and
rare command shell becomes one `supports` finding with source, target, account,
session, and process observables. Review it before selecting `suspicious` and
opening Operations.

### 10.8 Cloud account manipulation and added privileges
**AdversaryGraph implementation.** Create a manual T1098 hunt for one cloud tenant,
privileged identities, and the audit-retention window. Record approved
role-management workflows and emergency access as alternatives, then store a
KQL correlation for role membership, credential addition, policy change, and
subsequent resource use. Execute it in the cloud audit platform and cite the
external job and evidence package. If an inactive service principal receives a
new credential and administrator role before accessing secrets, create a
critical `supports` finding with immutable principal, actor, credential, role,
and session observables. After incident verification and finding review, complete
`confirmed_malicious`; use Evidence Graph only by creating the reasoning object
there and recording its ID.

### 10.9 Ingress tool transfer followed by execution
**AdversaryGraph implementation.** Use Discover to select T1105 plus the supported
execution technique and create a manual draft. Bound it to internet-facing Linux
hosts, verify process/file/DNS/egress overlap, and store an EQL sequence linking
download utility, destination, file hash, and execution by host. After the
external search, record the job reference and add one finding for a web-service
child process that retrieves an executable from a first-seen domain and launches
it. The finding should carry URL, domain, host, path, hash, and process
observables, verdict `supports`, and the automatically linked query revision.
Review it, choose `suspicious` or `confirmed_malicious` only as evidence permits,
and preserve the incident ID manually.

### 10.10 Burst of host, account, and network discovery
**AdversaryGraph implementation.** Create a manual hunt for T1082, T1087, and T1018,
with a ten-minute grouping window and scope limited to managed endpoints around
a known initial-access alert. Store the destination-native sequence and copy it
to the EDR. Record the job ID, host count, interval, and sensor gaps. Broad
inventory activity from a signed management agent can become a reviewed
`benign` finding when ownership and schedule are verified. A rare browser child
that runs multiple discovery commands on one executive endpoint becomes a
separate `supports` finding. Do not merge the clusters: close the first and use
the second to support a `suspicious` hunt outcome and Operations handoff.

### 10.11 Security-tool disablement or configuration impairment
**AdversaryGraph implementation.** Create a `P1 High` manual hunt for T1685, naming the
affected endpoint group and heartbeat-loss interval. Add security control-plane
audit, service/process activity, policy changes, identity events, network
reachability, and change records. Execute the copied correlation in external
systems and preserve each job reference. If missing heartbeats are confirmed
but neither a deliberate control change nor a platform outage can be established,
create a reviewed finding with verdict `inconclusive`, affected assets, time
window, and health-event references. Complete the hunt `inconclusive` and state
what evidence is absent. Do not report ATT&CK behavior as observed merely because
the sensor stopped reporting.

### 10.12 Recovery inhibition and ransomware-impact sequence
**AdversaryGraph implementation.** Create a `P0 Emergency` hunt with T1490 and T1486,
scope it to the backup tenant and critical systems, and store a sequence linking
recovery changes to high-rate file impact. Start `running` when authorized
external searches begin, then preserve their job IDs and raw-evidence package
references. A privileged snapshot deletion followed by mass rewrites becomes a
critical `supports` finding with actor, session, host, storage object, and process
observables. Escalate through Operations immediately; administrative hunt
completion must not delay response. After reviewers verify malicious recovery
inhibition and impact, move to `review`, complete `confirmed_malicious`, and
manually record the incident and Evidence Graph object IDs.

### 10.13 Archive creation and data staging
**AdversaryGraph implementation.** Create a manual T1560.001 hunt for high-value file
servers and endpoint groups, recording approved backup, build, and support
archives as alternatives. Store a query that correlates archive-tool execution,
source-file access, output path, size, account, and subsequent transfer, then run
the copied revision in endpoint and storage platforms. An approved release build
with a current pipeline record can be captured as a reviewed `benign` finding.
An unscheduled multi-gigabyte archive under a hidden user directory, followed by
network transfer, should be a separate `supports` finding with paths, hash,
account, host, and destination. Review it before completing `suspicious` and
recording the Operations case ID.

### 10.14 Exfiltration to personal or rare cloud storage
**AdversaryGraph implementation.** Create a manual T1567.002 hunt, scope it to sanctioned
egress controls and sensitive-data repositories, and document approved business
tenants and backup flows. Store an SPL or KQL correlation using immutable user,
device, application, destination tenant, bytes, object label, and event time.
Run it in the approved proxy/CASB/DLP platform and record the external search
identifier. A large upload to a rare personal tenant following archive staging
becomes one high-severity `supports` finding with user, device, tenant, domain,
object reference, and volume observables. After review, complete `suspicious` or
`confirmed_malicious` only with sufficient intent evidence; keep sensitive file
contents in their governed repository.

### 10.15 Suspicious OAuth application consent or token use
**AdversaryGraph implementation.** Create a manual OAuth hunt for the production tenant
and a 30-day interval, mapping T1098 first and adding T1528 or T1550.001 only
when token evidence supports it. Require consent, directory, service-principal,
credential, sign-in, and resource-access audit, then execute the copied analytic
externally. If only seven days of consent history exist, record the successful
job and uncovered 23 days and complete `telemetry_gap`; do not call the result
clean. If a risky consent and credential addition lead to unauthorized access,
create and review a `supports` finding before selecting `suspicious` or
`confirmed_malicious`. Open Operations and manually record the identity-response
object ID.

### 10.16 Unexpected Windows service creation or modification
**AdversaryGraph implementation.** From Navigator, create a T1543.003 draft and add
T1569.002 only if service execution is part of the hypothesis. Scope it to
Windows servers, translate the analytic to the actual service-control, registry,
process, file, and network schemas, and preserve authorized installer and
management-agent baselines. Execute the copied query externally and cluster by
service name, binary path, creator, signer, host, and change record. An approved
service whose binary resides in a user-writable path can be a reviewed `benign`
finding followed by hunt disposition `benign_policy_relevant`. An unknown service
launching outbound traffic should be a separate `supports` finding that may
justify `suspicious` and an Operations handoff.

### 10.17 Multi-factor authentication request generation and fatigue
**AdversaryGraph implementation.** Create a manual T1621 hunt for workforce identities,
exclude provider tests, and define a short correlation window spanning failed
sign-ins, MFA requests, user responses, successful authentication, device, and
resource access. Store a KQL revision and execute the copied query in the
identity platform; record its job ID and tenant. For 19 denied pushes followed
by one approval from a new device and mailbox-rule creation, add a high-severity
`supports` finding with immutable identity, session, device, source, and target
observables. Review or escalate it, complete `suspicious` unless incident evidence
supports a stronger conclusion, and manually record the Operations case ID.
Repeated requests alone are not proof of maliciousness.

### 10.18 Credentials accessed from web-browser stores
**AdversaryGraph implementation.** Create a manual T1555.003 hunt scoped to endpoints
with verified file/process telemetry. Store an EQL sequence for access to browser
credential or cookie databases by a non-browser process followed by archive,
network, or authentication activity. Execute it in the EDR and record the search
reference, exclusions, and uncovered hosts. An approved backup agent with stable
history may be a reviewed `benign` finding; an unsigned user process copying the
database and contacting rare infrastructure becomes a `supports` finding with
host, user, process, path, hash, and destination observables. Once incident
review verifies credential theft or use, complete `confirmed_malicious` and
retain raw artifacts outside AdversaryGraph.

### 10.19 Unexpected container-administration command
**AdversaryGraph implementation.** Create a manual T1609 hunt for production clusters,
privileged namespaces, orchestrator identities, and a 24-hour interval. Require
Kubernetes audit, identity, admission, workload, and network data and store a
query that enriches `exec`, `attach`, or equivalent actions with actor, source,
pod, namespace, container, command, decision, and ticket. Execute it in the
approved audit platform. A support engineer’s ticketed diagnostic command can
produce a reviewed `benign` finding or `benign_policy_relevant` outcome if the
target violated policy. A rare identity executing in a privileged pod and then
accessing secrets becomes a reviewed `supports` finding and may justify
`suspicious` plus an Operations handoff.

### 10.20 Unix shell download-and-execute chain
**AdversaryGraph implementation.** Use Discover to create a manual hunt with T1059.004
and T1105, then scope it to internet-facing Linux assets and the overlap of
process, file, DNS, and egress retention. Store an EQL sequence for a shell or
service process downloading a file and executing it, save assumptions, and run
the copied revision in the approved telemetry platform. For a web-service account
that retrieves an unknown file, changes permissions, executes it, and performs
discovery, add one `supports` finding with host, account, URL, domain, path, hash,
and process observables; put the external job reference in `evidence_ref` or the
result summary. Review it and choose the evidence-supported final disposition.
Use Attack Simulation only for a separate compatible, allowlisted lab scenario,
then manually record the returned `run-<UUID>` identifier.
