# Operation Desert Hydra in AdversaryGraph: From Source Research to Reviewed Detection Validation

**A practical, evidence-first guide for adapting the MuddyWater research-to-detection workflow around AdversaryGraph without turning AI suggestions, ATT&CK mappings, or synthetic telemetry into unsupported claims.**

Operation Desert Hydra began with a demanding question: can public reporting on MuddyWater be converted into a defensible chain from source research to detection validation?

The original project answered that question with a source register, procedure records, an OpenCTI graph, detection pseudologic, a Windows/Elastic lab, screenshots, and a coverage matrix. It also exposed the parts that did not work cleanly: source counts changed as the dataset evolved, some simulations were only surrogates for the intended behavior, one DLL fixture was not a loadable PE, and network topology prevented a Telegram-specific validation.

This guide adapts that workflow around **AdversaryGraph**. The objective is not to recreate the OpenCTI and Kibana screens pixel for pixel. It is to preserve the more important chain:

```text
source -> accepted claim -> behavior -> reviewed ATT&CK mapping
  -> required telemetry -> detection candidate -> reviewed rule
  -> validation scenario -> SIEM result -> analyst decision
```

AdversaryGraph can coordinate and link the reviewed intelligence, Evidence Graph, Navigator layer, hunt and detection records, controlled simulation references, gaps, and final report. External systems still own open-web research, bulk source acquisition and deduplication, execution of queries in a production SIEM, durable storage of some validation evidence, and actor-specific behavior that has no safe built-in fixture. Those handoffs are called out rather than hidden.

> **Scope and safety:** Use only public or explicitly authorized source material. Do not upload restricted reports to a remote AI provider without policy approval. Run Attack Simulation only against registered lab fixtures. AdversaryGraph does not execute malware, exploit arbitrary targets, or run arbitrary commands. Source-shaped synthetic events can validate parsing and rule logic, but they do not prove that a rule detects real MuddyWater activity. Begin every validation record as `not_proven` and change it only after reviewing captured evidence.

## Table of contents

1. [What this guide recreates](#what-this-guide-recreates)
2. [Prerequisites and acceptance rules](#prerequisites-and-acceptance-rules)
3. [Data mapping into AdversaryGraph](#data-mapping-into-adversarygraph)
4. [Phase 1: source gathering and the Review Gate](#phase-1-source-gathering-and-the-review-gate)
5. [Phase 2: build the procedure set](#phase-2-build-the-procedure-set)
6. [Phase 3: build the reviewed knowledge graph](#phase-3-build-the-reviewed-knowledge-graph)
7. [Phase 4: rebuild the detection atlas](#phase-4-rebuild-the-detection-atlas)
8. [Phase 5: validate all eleven detection records](#phase-5-validate-all-eleven-detection-records)
9. [Phase 6: calculate bounded coverage without overstating it](#phase-6-calculate-bounded-coverage-without-overstating-it)
10. [Final evidence pack and acceptance checklist](#final-evidence-pack-and-acceptance-checklist)
11. [Limitations](#limitations)
12. [Conclusion](#conclusion)
13. [References](#references)
14. [Follow My Work](#follow-my-work)

### Compact 31-step index

| Phase | Steps |
|---|---|
| Source gathering and Review Gate | [1](#step-1--run-two-independent-discovery-passes), [2](#step-2--preserve-the-first-raw-result), [3](#step-3--preserve-the-second-result-separately), [4](#step-4--compare-and-deduplicate-the-source-candidates), [5](#step-5--acquire-the-source-material), [6](#step-6--rate-reliability-and-information-credibility), [7](#step-7--review-approve-and-promote-each-source-revision), [8](#step-8--extract-source-bound-atomic-claims), [9](#step-9--derive-procedure-candidates) |
| Procedure set and knowledge graph | [10](#step-10--start-and-verify-adversarygraph), [11](#step-11--verify-current-attck-data), [12](#step-12--bring-the-promoted-source-set-into-the-platform), [13](#step-13--verify-muddywater-identity-and-aliases), [14](#step-14--build-the-reasoning-graph), [15](#step-15--build-and-verify-the-attck-layer), [16](#step-16--verify-malware-and-tool-context), [17](#step-17--verify-the-report-collection), [18](#step-18--reconcile-changed-sources-and-mappings), [19](#step-19--build-the-case-dashboard) |
| Detection atlas | [20](#step-20--create-and-review-eleven-detection-records) |
| Validation | [21](#step-21--validate-email-to-endpoint-correlation), [22](#step-22--validate-web-service-child-process-behavior), [23](#step-23--validate-encoded-and-obfuscated-powershell), [24](#step-24--validate-dll-side-loading-telemetry), [25](#step-25--validate-run-key-and-startup-persistence), [26](#step-26--validate-the-scheduled-task-rule-and-the-43-minute-lead), [27](#step-27--validate-rmm-abuse-against-a-real-baseline), [28](#step-28--validate-web-service-c2-without-claiming-telegram-proof), [29](#step-29--validate-dns-tunneling-or-preserve-the-gap), [30](#step-30--validate-the-wmi-discovery-survey), [31](#step-31--validate-lsass-and-credential-store-coverage) |

## What this guide recreates

The original Operation Desert Hydra workflow had six phases and 31 numbered steps:

| Original phase | Original implementation | AdversaryGraph implementation |
|---|---|---|
| Source gathering | Two external research models, acquisition scripts, source register, manual scoring | External discovery and acquisition, followed by separate Reports / Research records and the deterministic Review Gate |
| Procedure dataset | YAML claims and procedures | Accepted source-bound claims, Evidence Graph behavior paths, and reviewed Navigator mappings |
| Knowledge graph | OpenCTI objects, relationships, reports, ATT&CK connector, dashboard | ATT&CK Group Library, Reports / Research, Navigator, Evidence Graph, Statistics, and optional RAG projection |
| Detection atlas | Eleven YAML detection records with pseudologic | Eleven Operations records, Evidence Graph detection paths, Query Library starting points, and versioned hunts |
| Validation lab | Ansible, Windows/Sysmon, Winlogbeat, Elastic, Kibana | Approved Attack Simulation fixtures, source-shaped telemetry, optional SIEM forwarding, external rule execution, and manual verdict submission whose evidence is persisted in a versioned hunt, Investigation, Evidence Graph, or approved external case system |
| Coverage matrix | Custom score and screenshots | Navigator layer, Evidence Graph gaps, explicit validation dimensions, Statistics, and a final Investigation report |

This is an **adaptation**, not a claim that AdversaryGraph natively replaces every component:

- AdversaryGraph does not conduct independent open-web research or automatically deduplicate a 71-source register.
- It does not import `sources.yaml`, `procedures.yaml`, or `detections.yaml` as a complete native case model.
- It does not execute a stored hunt query in your SIEM.
- SIEM delivery confirms transport, not that a detection fired.
- Its safe simulations do not run MuddyWater malware or reproduce every actor-specific detail.

The platform is strongest where the original workflow needed the most discipline: source-bound review, immutable promotion, traceable reasoning, explicit gaps, and separation between a candidate, a rule, a delivered event, a rule match, and an analyst decision.

### Correct the historical baseline before starting

The narrative and the current Desert Hydra repository are not identical snapshots. The baseline below was audited against the pinned [`data/`](https://github.com/anpa1200/operation-desert-hydra/tree/da779256605e541a601118b31c5081a431b15d28/data) and [`docs/source-gathering/`](https://github.com/anpa1200/operation-desert-hydra/tree/da779256605e541a601118b31c5081a431b15d28/docs/source-gathering) trees. Record these differences in the case instead of silently choosing the more convenient number:

| Item | Current source audit | How to use it here |
|---|---|---|
| Candidate register | 71 listed candidates | Discovery baseline only; your rerun may differ |
| Retained raw-source directories | 65 in the reviewed checkout | Do not claim all 71 still have local folders |
| `data/sources.yaml` | 20 records: 19 `promote`, one `promote_with_caution` | All remain candidates until your own Review Gate promotion |
| `data/claims.yaml` | 51 atomic claims | Re-extract and bind each accepted claim to your stored source revision |
| `data/procedures.yaml` | 10 procedures and 21 candidate techniques | Use as the concordance, not automatic authority |
| Historical validation summary | Corrected project summary is 14 PASS, 1 PARTIAL, 1 FAIL across 16 checks | Cite only as prior project evidence; reset the AdversaryGraph run to `not_proven` |
| `data/validation-results.yaml` | Empty | Build a new durable validation ledger |
| Claimed exported detection directories | Not present beyond the detection README in the reviewed checkout | Recreate and version the actual local rules you test |

An Ansible `failed=0` line proves that the playbook completed; it does not prove that every detection predicate matched. Likewise, a screenshot proves only the query and event visible in that screenshot.

## Prerequisites and acceptance rules

### Platform preflight

This walkthrough was checked against the AdversaryGraph integration checkout `7a3fc2e4cd8a730f63d6ec7b7d871947c9e91867` and the Operation Desert Hydra source checkout `da779256605e541a601118b31c5081a431b15d28`. The AdversaryGraph revision was one reviewed commit beyond the public v7.0.0 merge baseline when this draft was written. Recheck routes, permissions, catalog entries, and source counts against the public revision used for publication or deployment.

Use the reviewed deployment guide for your environment. For a local Compose deployment, the minimum acceptance sequence is:

```bash
docker compose up -d --build
docker compose ps
./scripts/selftest.sh
curl -sS http://localhost:3000/api/ready
```

Do not start the case while the database migration, API, worker, ATT&CK data, or required attack-lab target is unhealthy. RAG is optional for the core workflow. Exact and full-text retrieval remain useful when semantic embeddings are disabled, but the index must be built and current before RAG results are treated as available.

### Routes and permissions

| Work | Route | Typical permission |
|---|---|---|
| Source intake and report collection | `/reports-research` | view with relevant read/module access; URL intake and unparsed text/file storage use `manage_intel`; every uploaded file also requires `upload_files`; file-based AI parsing uses `run_analysis` plus `upload_files` |
| Linked report and Review Gate | `/analyze/<session-id>/report` | view with the relevant read/module access; `review_reports` for start, preflight, gates, claims, and submit; `promote_reports` for request changes, reject, approve, promote, and revoke |
| MuddyWater reference profile | `/apt` | `read` |
| ATT&CK selection and layer | `/navigator` | `read`; save/delete named layers use `manage_intel`; JSON/PDF exports use `export_data` |
| Reasoning chain and gaps | `/evidence-graph` | module access uses `run_analysis`; graph mutation/materialization uses `manage_intel`; export uses `export_data` |
| Detection and investigation work queue | `/operations` | module/read access uses `run_analysis`; investigation, intake, and tracked-actor mutations use `manage_intel`; detection-candidate writes use `manage_detections` |
| Detection-content sources | `/query-library` | `run_analysis` for search/read/IOC drafting; community index sync uses `manage_feeds` |
| Versioned hunt | `/threat-hunting` | `run_analysis` for hunt CRUD; hunt export uses `export_data` |
| Controlled validation | `/attack-simulation` | `run_attack_simulation`; SIEM forwarding uses `forward_siem` |
| Final report and export | `/report` | module access uses `run_analysis`; save uses `manage_intel`; export uses `export_data` |
| Dataset metrics | `/statistics` | `run_analysis` |
| Source and ATT&CK freshness | `/feeds` | `manage_feeds` |

### Four-eyes review is a hard prerequisite

Enable authentication and provision two distinct human identities before attempting the promoted-report workflow. One identity needs `review_reports` to prepare and submit the revision; a different identity needs `promote_reports` to approve and promote it.

With `AUTH_ENABLED=false`, requests without a valid session or trusted-proxy identity fall back to the same `local:local` review actor. That fallback actor cannot approve its own submission, so the ordinary unauthenticated local workflow cannot complete promotion. Use two named authenticated or trusted identities; do not rely on the fallback or describe an unapproved local draft as promoted intelligence.

Follow [Authentication and Users](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/authentication-and-users.md) to enable named access safely. Do not expose an auth-disabled instance to an untrusted network.

### Evidence labels

Carry the original evidence vocabulary into the case notes:

- **Observed** — directly present in telemetry, a sample, a screenshot, or a primary incident artefact.
- **Reported** — explicitly stated by a source but not directly reproduced in your evidence.
- **Assessed** — an analytical judgment made by the publisher.
- **Inferred** — your conclusion from multiple cited facts.
- **Gap** — unknown, unsupported, unavailable, or not tested.

These labels do not override the Review Gate. A report-derived claim is eligible downstream only when accepted in an active current promotion. Text claims require exact stored-source binding; metadata claims may bind to stored acquisition metadata.

### Reset the historical results

Do not preload the original `14 PASS / 1 PARTIAL / 1 FAIL` summary as the result of this run. Those figures belong to the original Elastic lab and include known surrogate-test limitations. In this AdversaryGraph case:

1. Every scenario starts as `not_proven`.
2. A transported event is not automatically a parser success.
3. A parser success is not a rule match.
4. A positive match without a benign control is incomplete.
5. A synthetic or canary match must say exactly what it validated.
6. Actor detection is never inferred from generic technique coverage.

## Data mapping into AdversaryGraph

Use the original repository as a source package, not as pre-approved truth:

```bash
git clone https://github.com/anpa1200/operation-desert-hydra.git
cd operation-desert-hydra
git checkout da779256605e541a601118b31c5081a431b15d28
```

The main reusable artefacts are `docs/source-gathering/`, `data/sources.yaml`, `data/claims.yaml`, `data/procedures.yaml`, `data/detections.yaml`, and `data/validation-results.yaml`.

Map them into the platform as follows:

| Desert Hydra artefact | AdversaryGraph representation |
|---|---|
| Source record | Reports / Research item with title, URL or file, date, publisher, TLP, and stored source text |
| Atomic claim | Review Gate claim bound to an exact source excerpt |
| Procedure record | Evidence Graph `Behavior` connected to accepted claims and reviewed ATT&CK nodes |
| ATT&CK candidate | Navigator selection plus a reviewed Evidence Graph mapping |
| Required telemetry | Evidence Graph `Required Telemetry` node and hunt data requirement |
| Detection idea | `Detection Candidate` node plus an Operations backlog item |
| Detection pseudologic | Versioned hunt query or `Detection Rule` node with provenance and local adaptation notes |
| Benign validation plan | `Validation Scenario` linked to an approved Attack Simulation fixture |
| SIEM observation | `SIEM Result` with delivery, parser, query, positive-control, and negative-control evidence kept separate |
| Coverage score | `Analyst Decision`, Navigator layer, and explicit gap dimensions |

The current Desert Hydra repository has evolved beyond the numbers repeated in the original article. At the version reviewed for this guide, `data/sources.yaml` contains 20 source records: 19 marked for promotion and one marked `promote_with_caution`. The article's repeated “8 promoted” statement describes an earlier state. Treat all repository records as **candidates** in your deployment and let your own Review Gate determine the accepted count.

## Phase 1: source gathering and the Review Gate

### Step 1 — Run two independent discovery passes

**Where:** External approved research tools, then `/reports-research`.

Run the following **AdversaryGraph-adapted version** of the [original Desert Hydra research workflow](https://1200km.com/operation-desert-hydra/) independently with two providers. Use the adapted text verbatim for both runs so their outputs are comparable. AdversaryGraph is not a web-research crawler, so do not describe this as a native platform action. Require candidate URLs, dates, publishers, direct-download status, actor claims, procedure relevance, evidence labels, and explicit gaps.

Use the same bounded prompt for both passes:

```text
You are a senior CTI source-discovery analyst. Build a candidate source register
for a defensive MuddyWater / Seedworm / Mango Sandstorm / TA450 research case.
The output will be reviewed in AdversaryGraph; it must not be treated as evidence
or promoted automatically.

Prioritize primary government, standards-body, and original technical research.
Include comparison actors only as comparison and never merge clusters from shared
tools or ATT&CK overlap.

For every candidate return:
  id, title, publisher, canonical_url, direct_download_url, publication_date,
  access_date, source_type, actor_claims, procedure_relevance, key_entities,
  candidate_attack_ids, source_summary, acquisition_limitations.

Use only these evidence labels:
  Observed, Reported, Assessed, Inferred, Gap.

Rules:
  - Do not invent URLs, dates, quotes, page numbers, or ATT&CK IDs.
  - Write none_found when a direct download cannot be verified.
  - Do not upgrade a publisher statement into direct observation.
  - Do not use ATT&CK mapping or shared tooling as attribution proof.
  - Do not claim detection coverage or local targeting.
  - Mark inaccessible, partial, conflicting, or secondary evidence explicitly.

Return:
  1. executive source assessment;
  2. high-priority candidate register in YAML;
  3. extended register;
  4. direct-download table;
  5. actor alias and overlap cautions;
  6. procedure candidates with source IDs, label, ATT&CK candidate, required
     telemetry, detection opportunity, and validation feasibility;
  7. gaps and manual-review items.
```

Store each output as a separate Markdown file. Do not merge them yet and do not allow either model to create authoritative IOCs, ATT&CK mappings, or actor relationships.

**Evidence to save:** prompt checksum, provider/model, run time, raw output, and any provider warning.

**Stop if:** the model does not return source URLs, invents dates, omits limitations, or cannot separate MuddyWater from comparison actors.

### Step 2 — Preserve the first raw result

**Where:** `/reports-research` -> **Upload research file**.

Upload the first provider output with a title such as `Desert Hydra source discovery — provider A — raw`. Leave **Parse with AI** unchecked. This is a research artefact, not a threat report whose candidate mappings should enter review.

The original scenario planned a `deep-research-raw.md` artefact, but that file is not present in the reviewed source checkout. Creating this stored raw record closes that provenance gap for the new run; it does not retroactively prove the historical file existed.

**Evidence to save:** the stored raw file, provider metadata in the title or source note, and the platform record identifier.

**Stop if:** the uploaded text differs from the original output or contains secrets, private customer data, or material not permitted in this deployment.

### Step 3 — Preserve the second result separately

**Where:** `/reports-research`.

Upload the second provider output as a separate unparsed research record. Keeping the two runs independent makes disagreements, missing sources, and fabricated URLs visible.

**Evidence to save:** both record identifiers and a small comparison note listing sources unique to each run.

**Stop if:** one output has been overwritten, normalized into the other, or stripped of its original provenance.

### Step 4 — Compare and deduplicate the source candidates

**Where:** External worksheet or version-controlled Markdown; store the result in `/reports-research`.

AdversaryGraph does not have a native multi-source deduplication register. Reuse `docs/source-gathering/relevant-research-list.md` as the starting control sheet or build a new one. Normalize URLs, preserve canonical and direct-download links, retain provider provenance, and record the reason for each merge.

Upload the deduplicated register as unparsed research. The historical project produced 71 candidates; your current count may differ and should be recorded rather than forced to match 71.

**Evidence to save:** deduplication rules, before/after counts, canonical URL, duplicate members, and analyst initials.

**Stop if:** two reports are merged only because their titles or actor aliases look similar.

### Step 5 — Acquire the source material

**Where:** External acquisition process, then `/reports-research`.

The original project used:

```bash
python3 tools/fetch_research_sources.py
```

The script records the source number, title, requested URL, curl result and effective URL, HTTP status, response headers, raw and extracted-text paths, size, and extraction error. It does not itself record a fetch timestamp or create `fallback-reader.txt`; preserve any separately acquired reader fallback with its own provenance. Review those artefacts before upload. For each source you intend to assess, use **Upload from URL** or upload the authorized PDF, DOCX, TXT, or Markdown file.

Use **Parse with AI** only when the source handling policy permits it. A failed fetch, reader-mode fallback, corrupted PDF, or partial article must remain visible in the source record.

**Evidence to save:** canonical URL, acquisition timestamp, content hash, HTTP result, extraction status, and the exact stored text used for review.

**Stop if:** only a search snippet or secondary summary is available for a procedure claim.

### Step 6 — Rate reliability and information credibility

**Where:** Linked report notes and `/analyze/<session-id>/report`.

Apply the original two-axis Admiralty-style rubric in an analyst note: source reliability `A` through `F` and information credibility `1` through `6`. The current UI does not provide a dedicated Admiralty register, so preserve the score and rationale in the source-bound review record or a linked case artefact.

Then run the deterministic **Review Gate preflight**. It evaluates source provenance, publication date, procedure relevance, procedure-level claims, and actor basis. A high publisher rating does not automatically accept every claim in the report.

**Evidence to save:** score, rationale, source limitation, preflight output, and unresolved gate items.

**Stop if:** the rating is based only on publisher reputation or the source merely mentions MuddyWater without describing behavior.

### Step 7 — Review, approve, and promote each source revision

**Where:** `/analyze/<session-id>/report` -> **Deterministic report Review Gate**.

For every candidate report:

1. Start the review.
2. Run preflight.
3. Resolve all five gates with evidence and rationale.
4. Accept, reject, or request evidence for every claim.
5. Submit the revision.
6. Have an independent reviewer approve it.
7. Promote only the current fingerprinted revision.

`canonical_intelligence` is the mandatory promotion target. Add `rag`, `hunting`, or `exports` only when those downstream uses are intended and permitted.

**Evidence to save:** review history, gate decisions, accepted/rejected claims, approval identity, promotion manifest, and active revision fingerprint.

**Stop if:** the revision changed after review, an excerpt no longer matches stored offsets, the actor basis is tooling overlap alone, or a required gate remains unresolved.

### Step 8 — Extract source-bound atomic claims

**Where:** Review Gate claims inside the linked report.

Convert prose into narrow claims. A useful claim contains one behavior, one actor or campaign context, one exact excerpt, one source reference, and one evidence label. Avoid broad statements such as “MuddyWater uses PowerShell.” Prefer a claim such as “The cited report describes encoded PowerShell execution in the documented campaign,” bound to the exact supporting paragraph.

The current Desert Hydra repository contains 51 claim records. That number is a useful comparison point, not a quota.

**Evidence to save:** accepted claim ID, exact excerpt, source location, label, reviewer rationale, and rejected alternatives.

**Stop if:** the evidence only appears in an AI summary, an ATT&CK page without campaign context, or a paragraph unrelated to the proposed behavior.

### Step 9 — Derive procedure candidates

**Where:** Review Gate, `/navigator`, and `/evidence-graph`.

Group accepted claims into behavior-specific procedure candidates. For each candidate, record:

- supporting accepted claims from one or more sources;
- Observed, Reported, Assessed, Inferred, or Gap status;
- candidate ATT&CK IDs and mapping rationale;
- required telemetry and required fields;
- a detection idea and false-positive classes;
- a safe validation plan;
- known limits and contradictory evidence.

AdversaryGraph does not have a native `procedures.yaml` editor. Preserve the YAML as a controlled companion artefact, then represent each reviewed procedure in the Evidence Graph as `Claim -> Behavior -> ATT&CK Technique` with separate telemetry and detection nodes.

**Evidence to save:** procedure identifier, supporting claim IDs, mapping decision, required telemetry, validation feasibility, and reviewer.

**Stop if:** a procedure is only an ATT&CK category with no actor-specific behavior or source-bound claim.

## Phase 2: build the procedure set

Phase 2 is the analyst review and normalization of the ten procedure candidates produced by Step 9; it is not an omitted additional numbered step. Re-review every record in your deployment and do not accept it merely because it exists in Git.

| Procedure | Reviewed behavior | Candidate ATT&CK | Minimum telemetry question |
|---|---|---|---|
| `proc_mw_0001` | Spearphishing delivery by attachment, link, or compromised account | `T1566.001`, `T1566.002`, `T1534` | Can email delivery be correlated with recipient endpoint execution? |
| `proc_mw_0002` | Public-facing exploitation followed by staging or execution | `T1190` | Can web/WAF evidence be joined to service-parent endpoint activity? |
| `proc_mw_0003` | Encoded or obfuscated PowerShell | `T1059.001`, `T1027` | Are process command lines and PowerShell 4104 available? |
| `proc_mw_0004` | DLL side-loading | `T1574.002` | Is Sysmon ImageLoad or equivalent signing/path telemetry collected? |
| `proc_mw_0005` | Run-key and startup-folder persistence | `T1547.001` | Are registry and file-creation events available with actor and path fields? |
| `proc_mw_0006` | BugSleep scheduled task with a reported 43-minute interval | `T1053.005` | Does task telemetry preserve interval, action, creator, and path? |
| `proc_mw_0007` | Abuse of legitimate RMM software | `T1219` | Is there an authoritative baseline of approved tools, paths, users, and windows? |
| `proc_mw_0008` | Web-service C2 and DNS tunneling | `T1071.001`, `T1572`, `T1102` | Are process-aware proxy/network records and full DNS QNAMEs available? |
| `proc_mw_0009` | WMI-based host, network, user, and security-tool survey | `T1047`, `T1082`, `T1016`, `T1033`, `T1518.001` | Can the separate discovery events be correlated as one survey? |
| `proc_mw_0010` | LSASS and credential-store access | `T1003.001`, `T1003.004`, `T1003.005` | Is process-access telemetry available, and can legitimate security tools be excluded? |

For each row, open the technique in Navigator and verify the current Enterprise ATT&CK version, technique status, data requirements, and source references. ATT&CK describes a behavior class; it does not prove that MuddyWater performed the source claim and it does not prove local coverage.

Create the initial Evidence Graph path only after the claim and mapping are reviewed:

```text
accepted report excerpt
  -> accepted claim
  -> procedure-specific behavior
  -> reviewed ATT&CK technique
  -> required telemetry
```

If two sources disagree, preserve both paths. Do not delete the weaker or rejected path merely to make the graph look clean.

## Phase 3: build the reviewed knowledge graph

### Step 10 — Start and verify AdversaryGraph

**Where:** deployment shell, `/discover`, and `/troubleshooting`.

Start the reviewed platform build, confirm the migration job completed, verify long-running services are healthy, and run Self-test. Record the AdversaryGraph version, database migration head, ATT&CK version, case start time, and enabled AI/RAG/simulation capabilities.

This replaces the original OpenCTI stack-start step. Do not start a second OpenCTI instance merely to make this workflow look identical; AdversaryGraph's Evidence Graph is the authoritative reasoning workspace for this guide.

**Evidence to save:** `docker compose ps`, Self-test result, `/api/ready` result, platform version, and any degraded optional capability.

**Stop if:** the schema head is wrong, the worker is unavailable, ATT&CK data is missing, or the selected lab target is unhealthy.

### Step 11 — Verify current ATT&CK data

**Where:** `/feeds`, `/navigator`, and `/apt`.

Confirm the ATT&CK feed completed successfully. Open Enterprise Navigator and verify representative IDs such as `T1059.001`, `T1219`, and `T1003.001`. Then open the ATT&CK Group Library, search `G0069` and `MuddyWater`, and review aliases rather than creating a second actor from a vendor name.

**Evidence to save:** ATT&CK domain/version, last successful feed time, G0069 profile, and alias review note.

**Stop if:** the catalog is stale, a candidate ID is deprecated or wrong-domain, or aliases are being treated as independent groups without source support.

### Step 12 — Bring the promoted source set into the platform

**Where:** `/reports-research` and each linked Review Gate.

There is no supported one-click import for Desert Hydra's `sources.yaml`. Add every selected source by URL or file, preserve its metadata, review its claims, and promote its current revision individually. This deliberate boundary prevents a YAML flag from becoming platform authority.

If the repository already contains a source file, compare its hash and acquisition metadata with the authoritative public source before upload. Record inaccessible or partial sources as gaps rather than filling them from a secondary summary.

**Evidence to save:** one promoted manifest per accepted report and a source ledger linking the Desert Hydra source ID to the AdversaryGraph report/session identifiers.

**Stop if:** the report cannot be matched to its canonical source or promotion is based on repository status alone.

### Step 13 — Verify MuddyWater identity and aliases

**Where:** `/apt`.

Open the G0069 profile and review the actor name, aliases, source links, software, and techniques. Compare MuddyWater, Seedworm, Mango Sandstorm, TA450, Static Kitten, TEMP.Zagros, Mercury, and DEV-1084 only where source context supports the alias or cluster relationship.

Record a separate Evidence Graph claim for attribution or sponsorship only when a promoted source supports it. Shared PowerShell, RMM, or malware tooling is not identity proof.

**Evidence to save:** actor identifier, aliases accepted for search, aliases requiring qualification, and source citations.

**Stop if:** a comparison actor or vendor cluster is merged into G0069 solely because techniques overlap.

### Step 14 — Build the reasoning graph

**Where:** `/evidence-graph`.

For each promoted procedure, build the chain:

```text
Evidence -> Claim -> Behavior -> ATT&CK Technique -> Required Telemetry
  -> Detection Candidate -> Detection Rule -> Validation Scenario
  -> SIEM Result -> Analyst Decision
```

Create evidence nodes before analytical nodes. Keep ordinary AI graph suggestions in `draft` until reviewed. The from-report materializer is the narrow exception: it projects already accepted Review Gate claims as `analyst_reviewed` while retaining `ai_generated` provenance. Its API, `POST /api/evidence-graph/from-report/{report_id}`, accepts a UUID that resolves unambiguously to either the analysis session or its linked report-intake record, then requires a current promotion allowing `canonical_intelligence`. Do not pass a title, source ID, or arbitrary string.

Do not use `POST /api/evidence-graph/from-simulation/{run_id}` as proof that a simulation ran. The current endpoint creates a draft validation scenario and an unsent SIEM-result placeholder from the supplied string; it does not authenticate that string against a persisted run. Create or update the result nodes from the real run, delivery, parser, rule, control, and analyst evidence instead.

**Evidence to save:** graph path for every procedure, review status of every node/edge, and unresolved gaps.

**Stop if:** a graph path starts with an AI summary, an unpromoted report, or a technique node with no accepted claim.

### Step 15 — Build and verify the ATT&CK layer

**Where:** `/navigator`.

Select Enterprise ATT&CK and add the 21 candidate technique IDs from the procedure set. Inspect each technique's details, telemetry, detections, and source references. Use a clear name such as `Operation Desert Hydra — reviewed procedure candidates — <date>` and save or export the layer with the displayed ATT&CK version.

Use different colors or comments for:

- reviewed mapping with accepted source evidence;
- mapping needing more evidence;
- telemetry available;
- telemetry partial or absent;
- validation not yet run;
- validation complete for a clearly stated scope.

**Evidence to save:** Navigator JSON, domain/version, selected ID list, color legend, and analyst timestamp.

**Stop if:** a layer color is being interpreted as proof of detection coverage.

### Step 16 — Verify malware and tool context

**Where:** `/apt`, `/reports-research`, and `/evidence-graph`.

Review source-backed references to POWERSTATS, PowGoop, Small Sieve, Canopy, Mori, BugSleep, AnchorRAT, SyncroRAT, DarkBit, and abused RMM or credential tools. Distinguish malware from legitimate software used by an adversary.

AdversaryGraph does not need a custom object for every name to preserve the reasoning. Add a malware/tool node only when the source and identity are clear; otherwise keep the name inside the accepted claim and mark normalization as a gap.

**Evidence to save:** normalized name, object type, aliases, supporting report, and relationship rationale.

**Stop if:** a legitimate RMM product is labelled malware or a similarly named sample is merged without evidence.

### Step 17 — Verify the report collection

**Where:** `/reports-research` -> **Promoted intelligence only**.

Filter to promoted reports and reconcile the result against your source ledger. Record loaded, promoted, blocked, stale, and excluded counts separately. The denominator is your current candidate set, not a historical screenshot.

Open a sample from each source tier and confirm its stored text, source URL, review history, accepted claims, and active promotion fingerprint.

**Evidence to save:** timestamped report inventory and discrepancies.

**Stop if:** a visible candidate tag is counted as authoritative without an accepted claim and active promotion.

### Step 18 — Reconcile changed sources and mappings

**Where:** linked Review Gate, `/navigator`, and `/evidence-graph`.

The original OpenCTI workflow reran its importer after connector sync. In AdversaryGraph, reconciliation means rechecking authority after source or catalog change:

1. Reparse only when necessary; this changes the analysis fingerprint and withdraws the old promotion.
2. Start a fresh review revision.
3. Reapprove and repromote accepted claims.
4. Recheck Navigator IDs against the current catalog.
5. Update or reject graph paths whose source authority is stale.
6. Rebuild RAG only after the new revision is promoted for the `rag` target.

**Evidence to save:** previous and current revision identifiers, reason for change, mapping diff, and downstream invalidation result.

**Stop if:** stale graph, hunt, RAG, or export content remains presented as current authority.

### Step 19 — Build the case dashboard

**Where:** `/evidence-graph`, `/statistics`, `/navigator`, and `/operations`.

AdversaryGraph does not reproduce the original eight-widget OpenCTI dashboard. Build an equivalent review surface from:

- Evidence Graph Overview for node, edge, readiness, validation, and gap counts;
- Navigator for the 21-technique layer;
- Statistics for instance-wide or domain-wide source, technique, and telemetry distributions; use it only as background context unless the deployment is dedicated to this case;
- Operations for detection backlog state and ownership;
- Reports / Research for promoted-source counts.

Record the filter, denominator, ATT&CK version, and timestamp beside every metric. Export an Evidence Pack at meaningful milestones.

**Evidence to save:** graph export, layer, timestamped metrics, work queue, and dashboard screenshots if required by your evidence policy.

**Stop if:** frequency is being reported as risk, a graph readiness score is being called detection coverage, or historical and current revisions are mixed.

## Phase 4: rebuild the detection atlas

### Step 20 — Create and review eleven detection records

**Where:** `/operations`, `/evidence-graph`, `/query-library`, and `/threat-hunting`.

Create one detection backlog item and one graph path for each original record:

1. `det_mw_0001` — email delivery correlated with recipient process spawn.
2. `det_mw_0002` — public web service spawning an interpreter or shell.
3. `det_mw_0003` — encoded PowerShell and script obfuscation.
4. `det_mw_0004` — DLL side-loading from an unexpected path.
5. `det_mw_0005` — Run-key or startup-folder persistence.
6. `det_mw_0006` — suspicious scheduled task, including the reported 43-minute lead.
7. `det_mw_0007` — RMM execution outside the approved baseline.
8. `det_mw_0008a` — non-browser process using a web service for C2.
9. `det_mw_0008b` — DNS tunneling volume, label length, or entropy behavior.
10. `det_mw_0009` — WMI-based security-product and system survey.
11. `det_mw_0010` — LSASS access or credential-dumping artefacts.

Every record should include:

- exact accepted claim IDs and source excerpts;
- procedure-specific behavior and candidate ATT&CK IDs;
- required products, log sources, fields, and retention;
- SIEM-agnostic pseudologic;
- local query language and version;
- false-positive classes and exclusions;
- expected positive and benign-control evidence;
- a safe validation scenario;
- owner, reviewer, priority, and due date;
- initial result `not_proven`.

Search Query Library with filters such as `ttp:T1059.001 lang:sigma`, but treat community content as a starting point. Verify source, license, parser status, product, field names, time window, and exclusions. Create a hunt to preserve each locally adapted query version and checksum.

Do not rely on an edited Pipeline rule preview as the durable copy of the final analytic. Initial generated detection versions are stored, but later UI edits and revalidation state are not a substitute for a versioned hunt or an externally version-controlled rule. Operations tracks the work item; it does not currently provide a complete rule/telemetry/source-reference editor.

Reperform the original analyst checks: Boolean precedence, event guards, access masks, path allowlists, parent-child direction, case normalization, time-window semantics, and missing telemetry. Do not copy the original score into the new record.

**Evidence to save:** eleven reviewed records, eleven graph detection paths, local query versions, code-review notes, and explicit validation scope.

**Stop if:** a generated rule is marked validated because it parses, or a rule is deployed without confirming local fields and controls.

## Phase 5: validate all eleven detection records

### One protocol for every validation

For Steps 21–31, use the same controlled sequence:

1. Open `/attack-simulation` and select the documented technique or fixture.
2. Confirm the target is a registered lab fixture.
3. Add a ticket, purpose, operator, and maintenance window.
4. Generate and review the dry-run plan.
5. Run only the predefined scenario.
6. Inspect target-side or source-shaped events.
7. If permitted, forward selected events to a test SIEM.
8. Confirm transport, parsing, required fields, positive match, and benign control separately.
9. Submit the manual status as `passed`, `failed`, `partial`, or `not_proven`, with scope.
10. Persist the actual evidence in a versioned hunt, Investigation record, Evidence Graph nodes, and/or your approved external case system.

The current `/api/simulation/manual-result` response echoes the submitted evidence and gaps, while its durable audit event stores only the target and status. The UI response is therefore not a durable evidence repository. Export or record the evidence before leaving the workflow, and never reconstruct a result later from the audit status alone.

The phrase “passed” must complete a sentence: *passed what, against which event shape, query version, target, parser, and control?*

Use the verdicts consistently:

- **`passed`** — the full stated, bounded scope was demonstrated and the benign control did not alert.
- **`failed`** — a valid test completed, but the rule missed, a required delivery/parser condition failed, or the benign control alerted.
- **`partial`** — only a specifically named subset or rule leg was demonstrated.
- **`not_proven`** — the test was not run, or the fixture, telemetry, or retained evidence was insufficient to decide.

The current simulation catalog has a fixture for 16 of the 21 procedure technique IDs: `T1566.001`, `T1190`, `T1059.001`, `T1027`, `T1574.002`, `T1547.001`, `T1053.005`, `T1219`, `T1071.001`, `T1102`, `T1047`, `T1082`, `T1016`, `T1033`, `T1518.001`, and `T1003.001`. It has no matching fixture for `T1566.002`, `T1534`, `T1572`, `T1003.004`, or `T1003.005`. Even a matching ID means only that a generic technique fixture exists; it does not mean the actor-specific procedure is reproduced.

### Step 21 — Validate email-to-endpoint correlation

**Use:** `sim-t1566-001-atomic-email-attachment-delivery` and `sim-t1203-atomic-office-spawned-script-host`.

The first fixture supplies email-gateway-shaped delivery data. The second supplies an Office-parent process event. Validate both schemas and your individual rule legs. Then test the five-minute join in an authorized lab or SIEM fixture that preserves a common recipient/host/time correlation key.

**Pass only if:** one coherent test chain produces the intended delivery and endpoint events, both parse correctly, the correlation rule fires inside the expected window, and a benign delivery/control does not fire.

**Otherwise record:** `failed` when a valid full-chain test misses or its control alerts; `partial` when only named individual legs are demonstrated; `not_proven` when the full correlation fixture or evidence is absent. The original project did not actually validate the email-gateway leg, so do not inherit its PASS label.

### Step 22 — Validate web-service child-process behavior

**Use:** `sim-t1190-web-exposure` and `sim-t1059-web-command-canary` as web/WAF parser fixtures.

These fixtures validate public-web and command-injection-shaped telemetry. They do not by themselves prove an endpoint event where `w3wp.exe`, `java.exe`, a VPN service, or another documented service parent launches a shell.

**Pass only if:** an approved multi-tier lab produces both the web request and the required endpoint parent-child event, the rule matches that relationship, and an administrative benign control does not match.

**Otherwise record:** `failed` when a valid full multi-tier test misses or its control alerts; `partial` when only the web/WAF or endpoint leg is demonstrated; `not_proven` when the required endpoint correlation fixture or evidence is absent.

### Step 23 — Validate encoded and obfuscated PowerShell

**Use:** `sim-t1059-powershell-encoded-command` and `sim-t1027-atomic-encoded-powershell-scriptblock`.

Validate the process-command-line rule against encoded-command forms and the script-block rule against PowerShell 4104-shaped data. Include mixed case, abbreviated flags, whitespace variation, and a benign encoded administrative script where policy permits.

**Pass only if:** the exact local query version matches the intended encoded or obfuscated fields, preserves the source event, and the negative control stays below the alert threshold.

**Otherwise record:** `failed` when a valid full-scope test misses or its control alerts; `partial` when only one named rule leg is demonstrated; `not_proven` when the required fixture or evidence is absent.

**Scope note:** a canary or atomic event proves parser/rule behavior for that event shape; it does not prove resistance to AMSI bypass, alternate encoders, or real MuddyWater tooling.

### Step 24 — Validate DLL side-loading telemetry

**Use:** `sim-t1574-002-atomic-dll-side-loading`.

This fixture emits a single Sysmon Event ID 7-shaped ImageLoad event. It contains the loader process name (`signed-app.exe`), DLL path, and DLL signature state (`Unsigned`), but no separate loader-signature field. Validate those available fields and path logic; do not infer that the loader was signed from its filename. Add a benign control for an approved signed application loading its expected library.

**Pass only if:** your stated scope is schema and rule validation. Full behavior validation requires an authorized endpoint fixture with a valid benign PE DLL and actual ImageLoad capture.

**Otherwise record:** `failed` when a valid stated-scope test misses or its control alerts; `partial` when only schema/rule behavior is demonstrated but real ImageLoad execution is still required; `not_proven` when neither scope has adequate evidence. The original four-byte `MZ` stub was not a loadable DLL; AdversaryGraph must not turn a corrected event fixture into a claim that real side-loading executed.

### Step 25 — Validate Run-key and startup persistence

**Use:** `sim-t1547-run-key-persistence`.

Validate the Run-key path, value, process, user context, and suspicious target path. Test a known-good software installer as the benign control. The built-in fixture does not create a real registry value and does not cover every startup-folder WSF condition.

**Pass only if:** the recorded scope is the Run-key rule leg and the source-shaped event reaches the expected parser and query.

**Otherwise record:** `failed` when the Run-key scope is validly tested but misses or its control alerts; `partial` when the Run-key leg passes but startup-folder coverage remains open; `not_proven` when the test or evidence is insufficient.

### Step 26 — Validate the scheduled-task rule and the 43-minute lead

**Use:** `sim-t1053-scheduled-task`.

Validate generic scheduled-task creation fields: task name, action, creator, path, and schedule. Then separately test whether your telemetry preserves a repetition interval equivalent to `PT43M` or `/MO 43`.

**Pass only if:** the generic task rule and, when claimed, the 43-minute-specific branch are both supported by captured fields and controls.

**Otherwise record:** `failed` when a valid generic-task test misses or its control alerts; `partial` when generic task creation passes but the interval branch remains open; `not_proven` when the required evidence is absent. Keep the actor-specific interval separately `not_proven` until demonstrated. The 43-minute value is a single-source BugSleep lead, not an attribution fingerprint.

### Step 27 — Validate RMM abuse against a real baseline

**Use:** `sim-t1219-atomic-remote-access-software-started`.

The atomic fixture emits a remote-access-software process event. Validate path, signer, parent, user, destination, and inventory fields. Before judging the result, build an authoritative list of approved RMM products, install paths, service accounts, deployment systems, maintenance windows, and relay domains.

**Pass only if:** the local rule distinguishes the fixture from an approved baseline control and the fields needed for the distinction are present.

**Otherwise record:** `failed` when a valid baseline-aware test misses or alerts on its approved control; `partial` when only a named field or binary/path leg is demonstrated; `not_proven` when the baseline, fixture, or retained evidence is insufficient. A binary-name match is not a defensible RMM-abuse detection.

### Step 28 — Validate web-service C2 without claiming Telegram proof

**Use:** `sim-t1071-web-beacon` and `sim-t1102-atomic-web-service-c2-user-agent`.

Validate proxy/network parsing, process identity where available, periodicity, host/category fields, and a browser control. The fixtures use safe lab data and do not contact Telegram.

**Pass the generic scope only if:** the HTTP/web-service C2-shaped telemetry parses, the rule matches the intended non-browser or beacon behavior, and the browser control remains quiet. Otherwise classify that generic scope as `failed`, `partial`, or `not_proven` using the protocol above.

**Telegram outcome:** keep the Telegram-specific `api.telegram.org` branch `not_proven` unless a separately approved exact fixture demonstrates it. Do not solve the gap by enabling arbitrary internet egress from the simulator.

### Step 29 — Validate DNS tunneling or preserve the gap

**Use:** `sim-t1071-controlled-beacon` for planning and any approved DNS source fixture available in your lab.

The current native catalog does not provide an actor-specific `T1572` DNS-tunneling execution. Define the required resolver fields: full QNAME, parent domain, source host, process or sensor context, timestamp, response, label length, volume, and entropy features.

**Pass only if:** an approved DNS fixture produces controlled positive and benign samples, the resolver preserves the required fields, and the local detection matches the intended volume/length/entropy behavior.

**Otherwise record:** `failed` when a valid approved DNS test misses or its control alerts; `partial` when only named resolver fields or a narrower detector leg is demonstrated; `not_proven` when the DNS fixture or evidence is absent. Create a telemetry-fixture backlog item for the missing scope. A generic DNS or HTTP beacon is not proof of tunneling coverage.

### Step 30 — Validate the WMI discovery survey

**Use:**

- `sim-t1047-atomic-wmic-process-call-create`;
- `sim-t1518-001-atomic-security-software-discovery`;
- `sim-t1082-system-discovery`;
- `sim-t1016-network-config-discovery`;
- `sim-t1033-user-discovery`.

Validate each telemetry leg, including the `SecurityCenter2` namespace where present. Then test whether your SIEM can correlate the legs into one bounded survey without mistaking ordinary inventory tooling for actor activity.

**Pass only if:** each claimed field exists, the query version is recorded, the sequence/correlation logic works, and approved management software is represented in the control set.

**Otherwise record:** `failed` when a valid full-survey test misses or its control alerts; `partial` when only named individual legs are demonstrated; `not_proven` when the correlation fixture or evidence is absent. Five independent atomic events do not automatically prove one coherent procedure.

### Step 31 — Validate LSASS and credential-store coverage

**Use:** `sim-t1003-lsass-mimikatz-canary`.

Validate process, command line, target process, dump path, and any process-access fields your telemetry provides. Check the exact access-mask logic against the local sensor documentation and test legitimate EDR, backup, and security software as controls.

**Pass only if:** `T1003.001` rule behavior is demonstrated for the named event shape and controls. The built-in fixture does not access LSASS memory or credentials.

**Otherwise record:** `failed` when a valid `T1003.001` test misses or its control alerts; `partial` when only a named subset of the stated `T1003.001` scope is demonstrated; `not_proven` when its fixture or evidence is insufficient. Keep `T1003.004` and `T1003.005` `not_proven` unless separate LSA Secrets and cached-domain-credential telemetry is captured. Do not inherit the original combined PASS, whose validator accepted broader LSASS Event ID 10 data than the documented rule masks.

## Phase 6: calculate bounded coverage without overstating it

The original coverage matrix reduced each technique to a score. In AdversaryGraph, preserve the dimensions that produced the score.

For every one of the 21 candidate techniques, record:

| Dimension | Allowed value |
|---|---|
| Promoted source authority | yes / no / stale / revoked |
| Procedure claim accepted | yes / no / needs evidence |
| ATT&CK mapping reviewed | accepted / rejected / candidate |
| Required telemetry available | full / partial / absent / unknown |
| Query locally adapted | yes / no |
| Fixture scope | real lab / source-shaped synthetic / plan only / none |
| Event delivered | yes / no / not attempted |
| Required fields parsed | full / partial / no |
| Positive rule match | yes / no / not attempted |
| Benign control | passed / failed / not attempted |
| Analyst decision | passed / failed / partial / not_proven |

Use Navigator to display the reviewed technique set and Evidence Graph Gap View to identify missing telemetry, candidates, rules, scenarios, SIEM results, and decisions. The graph's deterministic readiness score is a workflow indicator, not scientific truth and not proof that MuddyWater would be detected.

Navigator coverage and maturity assessments are browser-local state, not a governed server-side coverage record. Export the versioned layer and keep the dimension table in the Investigation or another approved durable system; do not treat one browser's colored cells as the case authority.

Define the denominator as the unique ATT&CK technique candidates in the current promoted procedure set. Count a technique as **evidence-complete** only when it has current promoted authority, an accepted procedure claim, a reviewed mapping, full required telemetry, a versioned local query, delivered and parsed evidence, a positive match, a passing benign control, and an analyst decision of `passed`. Report `passed`, `failed`, `partial`, and `not_proven` counts separately; do not fold partial credit into a single percentage without publishing the weighting formula.

Recalculate that denominator from your current promoted procedures. Do not publish the original `17/21` effective-coverage figure unless your own evidence independently supports the same 17 techniques and the same threshold.

### Recheck the six capability gates

1. **PowerShell Script Block Logging** — required for content-level PowerShell and WMI survey logic.
2. **Sysmon Event ID 10 or equivalent ProcessAccess** — required for tool-independent LSASS access.
3. **Sysmon Event ID 7 or equivalent ImageLoad** — required for DLL side-loading.
4. **Full DNS QNAME telemetry** — required for DNS-tunneling logic.
5. **Process-aware proxy/network flow** — required for RMM and web-service C2 context.
6. **Email gateway metadata plus endpoint correlation** — required for the complete delivery chain.

Turn every failed gate into an Operations backlog item with an owner, data source, acceptance test, and link to the originating Evidence Graph gap. Absence of telemetry is not evidence of absence.

## Final evidence pack and acceptance checklist

Build the final case in `/report` and include links rather than unnecessary copies of sensitive raw data. Export the Evidence Graph Evidence Pack and Navigator layer. Attach hunt exports, simulation run identifiers, SIEM query versions, parser evidence, rule-match evidence, control results, and screenshots only where your retention policy permits.

The current Evidence Pack export is graph-wide, includes rejected paths, and is bounded to the graph query limit rather than scoped to one Desert Hydra operation. Review it for unrelated or sensitive records, retain a case-specific node/edge manifest, and do not call the ZIP a complete or exclusive case export without verifying its contents.

The reproduction is complete when all of these are true:

- [ ] Each retained source has acquisition provenance and an explicit review outcome.
- [ ] Every authoritative report-derived claim is accepted in an active current promotion; text claims have exact stored-source binding and metadata claims have stored acquisition metadata.
- [ ] Rejected, stale, excluded, and contradictory evidence remains visible.
- [ ] All ten procedure candidates have source claims, mapping rationale, telemetry, and limitations.
- [ ] The Navigator layer records its domain, ATT&CK version, denominator, and legend.
- [ ] All eleven detection records have local query versions, false positives, controls, and owners.
- [ ] Every validation separates fixture type, delivery, parsing, match, control, and decision.
- [ ] Unsupported actor-specific behavior is recorded as a gap, not replaced by a generic simulation.
- [ ] Coverage is recomputed from current evidence rather than copied from the original article.
- [ ] The final report separates fact, publisher assessment, analyst inference, and local validation.
- [ ] Exports contain no credentials, malware binaries, restricted source text, or unauthorized customer data.
- [ ] A second analyst can follow the links from final decision back to source and reproduce the logic.

Recommended final package:

```text
operation-desert-hydra-adversarygraph/
  source-ledger.md
  promoted-report-manifest.csv
  procedure-review.md
  navigator-layer.json
  detection-register.md
  hunt-query-manifest.csv
  validation-ledger.md
  evidence-pack.zip
  final-report.md
  limitations-and-open-gaps.md
```

The filenames are an export-package convention for this case, not a native bulk-import schema.

## Limitations

This workflow has deliberate boundaries:

- Open-web discovery, source acquisition, and cross-provider deduplication remain external analyst activities.
- The platform has no native bulk procedure or detection-atlas importer for the Desert Hydra YAML files.
- Review Gate promotion establishes reviewed source authority; it does not establish that the report is correct about every external fact.
- ATT&CK mapping is a reviewed analytical classification, not attribution evidence.
- Evidence Graph connectivity and readiness scoring do not make a claim true or a control effective.
- Query Library content is a starting point. AdversaryGraph stores and reviews hunts but does not execute them in your SIEM.
- SIEM forwarding proves only the delivery result exposed by the adapter. Parser success and rule firing require separate evidence.
- Atomic and AI-generated simulation events validate event shape, transport, field mapping, and rule logic within their stated scope. They do not reproduce malware execution or prove detection of real MuddyWater operations.
- The built-in catalog does not fully reproduce the 43-minute BugSleep interval, Telegram-specific C2, DNS tunneling, complete WMI survey correlation, startup-folder behavior, or every credential-store technique.
- Public reporting, ATT&CK content, tool aliases, and software behavior change over time. Pin versions and repeat review.
- A positive lab result still requires production baselining, tuning, monitoring, privacy review, and change control.

## Conclusion

The most valuable part of Operation Desert Hydra was never a particular OpenCTI graph or Kibana screenshot. It was the refusal to skip the chain between a public sentence and a defensive claim.

AdversaryGraph turns that discipline into a repeatable workspace. Reports remain candidates until a current revision is approved and promoted. Text claims remain bound to exact excerpts; metadata claims remain bound to stored acquisition metadata. ATT&CK mappings remain analytical decisions. Detection rules remain drafts until adapted. Simulations state whether they are real fixtures, canaries, or synthetic events. Delivery, parsing, matching, controls, and analyst decisions remain separate facts. Gaps stay visible.

That makes the new workflow stricter than a simple port. It also makes it easier to defend. A reviewer can start with any coverage cell and move backward through the validation result, rule version, telemetry requirement, ATT&CK mapping, behavior, claim, and source.

The goal is not to prove that a platform “detects MuddyWater.” The goal is to produce a current, bounded, reproducible record of what the evidence supports, what the local controls demonstrated, and what still needs work.

## References

- [Operation Desert Hydra — original article](https://1200km.com/operation-desert-hydra/)
- [Operation Desert Hydra — source repository](https://github.com/anpa1200/operation-desert-hydra)
- [MITRE ATT&CK — MuddyWater (G0069)](https://attack.mitre.org/groups/G0069/)
- [CISA AA22-055A — Iranian Government-Sponsored Actors Conduct Cyber Operations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a)
- [AdversaryGraph repository](https://github.com/anpa1200/adversarygraph)
- [AdversaryGraph documentation and Report Review Gate](https://1200km.com/adversarygraph-docs/)
- [Authentication and Users](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/authentication-and-users.md)
- [Module Reference and Casebook](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/module-reference.md)
- [Evidence-to-Detection Graph](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/evidence-to-detection-graph.md)
- [Threat Hunting Query Library](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/query-library.md)
- [Threat Hunting Guide](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/threat-hunting-guide.md)
- [Attack Simulation](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/attack-simulation.md)
- [Attack Simulation SIEM Forwarding Security](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/attack-simulation-siem-forwarding-security.md)
- [Unified Intelligence RAG and MCP](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/unified-rag-and-mcp.md)
- [Validation and Limitations](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/validation-and-limitations.md)
- [Taxonomy and Label Convention](https://github.com/anpa1200/adversarygraph/blob/2a9a7bedf6115dbcfbf1e90a70e08f50d76e8c73/docs/taxonomy-and-label-convention.md)

## Follow My Work

I publish practical cybersecurity research, CTI workflows, detection engineering notes, malware-analysis projects, AI-security research, open-source tools, labs, and technical guides.

- [Website — 1200km.com](https://1200km.com/)
- [Medium — @1200km](https://medium.com/@1200km)
- [LinkedIn — Andrey Pautov](https://www.linkedin.com/in/andrey-pautov/)
- [GitHub — tools and labs](https://github.com/anpa1200)
- [Contact — 1200km@gmail.com](mailto:1200km@gmail.com)
