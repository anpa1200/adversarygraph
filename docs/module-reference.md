# AdversaryGraph Module Reference and Casebook

This is the detailed operational reference for the modules exposed by the
current AdversaryGraph source tree. It is derived from the backend module
catalog, frontend routes, API tags, and in-application help definitions.

The checked-out source declares version `6.5.0`. Until its tag workflow
successfully publishes and verifies immutable artifacts, `v6.0.0` remains the
latest published historical tag. Verify the checked-out tag or commit and the
corresponding release evidence before using this document as acceptance
evidence.

The examples and case studies below are reproducible workflows or clearly
labelled illustrative scenarios. They are not customer testimonials, adoption
claims, or proof that a suggested mapping, attribution, vulnerability, or
detection is correct. Analysts must validate evidence and deployment-specific
results.

## Contents

1. [How to use this reference](#how-to-use-this-reference)
2. [Module and access index](#module-and-access-index)
3. [Workspace](#workspace)
4. [Intelligence](#intelligence)
5. [Analyze and Investigate](#analyze-and-investigate)
6. [Hunt and Validate](#hunt-and-validate)
7. [Operations](#operations)
8. [Platform](#platform)
9. [Learn and Support](#learn-and-support)
10. [Cross-module case studies](#cross-module-case-studies)
11. [Evidence and safety rules](#evidence-and-safety-rules)

## How to use this reference

Every module entry contains:

- **Purpose** — the question the module is designed to answer.
- **Inputs and prerequisites** — data, configuration, and access needed.
- **Workflow** — a repeatable analyst procedure.
- **Outputs and handoff** — records produced and where they should go next.
- **Worked example** — a small example that can be reproduced with public or
  synthetic data.
- **Case study** — a realistic scenario, decision path, and acceptance check.
- **Limits** — what the output does not prove or what the module does not do.

Module visibility and action authority are separate controls. A user needs the
module in an enabled access group. Mutating or sensitive actions additionally
require permissions such as `run_analysis`, `manage_intel`,
`run_attack_simulation`, `manage_feeds`, `view_audit`, or `manage_users`. The
API enforces the same boundary as the frontend. See
[Authentication and User Management](authentication-and-users.md).

External enrichment is conditional. A provider appearing in the interface does
not mean it is ready: credentials, operator policy, network reachability, model
access, and a successful module-level readiness check may all be required.

## Module and access index

| Category | Module | Route | Module key | Typical action grant |
|---|---|---|---|---|
| Workspace | Discover | `/discover` | `discover` | `read` |
| Intelligence | Threat Radar | `/threat-radar` | `threat_radar` | `run_analysis` |
| Intelligence | Reports / Research | `/reports-research` | `reports_research` | `read`; mutations may require `manage_intel` |
| Intelligence | ATT&CK Group Library | `/apt` | `apt_library` | `read` |
| Intelligence | Sector Intelligence | `/sector-intel` | `sector_intel` | `read`; saved intelligence may require `manage_intel` |
| Intelligence | Knowledge Library | `/knowledge` | `knowledge` | `read` |
| Intelligence | IOC Library | `/ioc-library` | `ioc_library` | `read`; imports may require `manage_intel` |
| Intelligence | CVE Library | `/cve` | `cve_library` | `read` |
| Intelligence | RetroHunt Signals | `/retrohunt` | `retrohunt` | `read`; collection work may require `run_analysis` |
| Analyze & Investigate | AI Analysis | `/analyze` | `ai_analysis` | `run_analysis` |
| Analyze & Investigate | Navigator | `/navigator` | `navigator` | `read`; saved layers may require additional authority |
| Analyze & Investigate | Compare | `/compare` | `compare` | `read` |
| Analyze & Investigate | IOC Investigation | `/ioc-investigation` | `ioc_investigation` | `run_analysis` |
| Analyze & Investigate | Malware Analysis | `/malware-analysis` | `malware_analysis` | `run_analysis`, `upload_files` |
| Analyze & Investigate | VirusTotal Lookup | `/virustotal` | `virustotal` | `run_analysis` |
| Analyze & Investigate | Asset Surface | `/asset-surface` | `asset_surface` | `run_analysis`, optionally `upload_files` |
| Analyze & Investigate | EMB3D | `/emb3d` | `emb3d` | `run_analysis` |
| Analyze & Investigate | Evidence Graph | `/evidence-graph` | `evidence_graph` | `run_analysis` |
| Hunt & Validate | Threat Hunting | `/threat-hunting` | `threat_hunting` | `run_analysis` |
| Hunt & Validate | Query Library | `/query-library` | `query_library` | `run_analysis`; curation may require `manage_detections` |
| Hunt & Validate | Attack Simulation | `/attack-simulation` | `attack_simulation` | `run_attack_simulation`; forwarding requires `forward_siem` |
| Hunt & Validate | Investigation | `/report` | `investigation` | `run_analysis`; export may require `export_data` |
| Operations | Operations | `/operations` | `operations` | `run_analysis` |
| Operations | Pipeline | `/pipeline` | `pipeline` | `run_analysis`; source administration may require `manage_intel` |
| Operations | Statistics | `/statistics` | `statistics` | `run_analysis` |
| Platform | Feeds Management | `/feeds` | `feeds` | `manage_feeds` |
| Platform | Observability | `/observability` | `observability` | `view_audit` |
| Platform | Administration | `/admin` | `admin` | `manage_users`, `manage_auth`, or `view_audit` |
| Learn & Support | DFIR Examples | `/examples` | `examples` | `read` |
| Learn & Support | Help / Local Guide | `/help` | `help` | `read` |
| Learn & Support | Troubleshooting | `/troubleshooting` | `troubleshooting` | `read`; some remediations require an operator |

The table describes normal UI entry requirements, not a substitute for the
authoritative endpoint-level OpenAPI contract. Review
[the generated API reference](api-reference.md) for exact routes and schemas.

## Workspace

<!-- module:discover -->
### Discover

**Purpose.** Discover is the start surface for deciding which workflow matches
the evidence in hand. It presents launchers, local intelligence counters,
provider inventory, feed status, saved-work context, and health signals.

**Inputs and prerequisites.**

- A healthy frontend and API.
- Synced reference data for useful actor, ATT&CK, IOC, and CVE counters.
- No LLM key is required merely to browse or launch a deterministic workflow.

**Workflow.**

1. Review health, data counters, enabled integrations, and startup ingestion.
2. Identify the starting artefact: report, IOC, actor, CVE, asset, malware
   sample, hunt hypothesis, or detection-validation requirement.
3. Use the matching launcher instead of forcing every artefact through AI
   Analysis.
4. If the relevant library is empty or stale, inspect Feeds Management.
5. If an API action fails, open Self-test, Observability, or Troubleshooting.

**Outputs and handoff.** Discover does not create an investigation by itself.
Its output is a deliberate transition into the correct module with a visible
readiness signal.

**Worked example.** An analyst receives `example.invalid` in an alert. From
Discover, open IOC Investigation, preserve the source alert reference, run
configured pivots, and only then decide whether to create a report or hunt.

**Illustrative case study.** A new deployment shows zero CVEs and a degraded
IOC source. Instead of interpreting the empty dashboard as “no exposure,” the
operator opens Feeds Management, confirms the last-sync timestamps, repairs the
source, and reruns Self-test. Acceptance is a successful sync plus changed
library counts—not merely a green frontend.

**Limits.** Dashboard counters indicate records in this deployment. They do
not measure global threat activity, product adoption, or environment safety.

## Intelligence

<!-- module:threat_radar -->
### Threat Radar

**Purpose.** Threat Radar converts external and internal threat signals into
business-relevant exposure records, action queues, and monitored company assets.
It connects CVE, KEV, exploit, supplier, package, breach, telemetry, and
research claims to products, components, dependencies, owners, and workflows.

**Inputs and prerequisites.**

- A sanitized threat signal or an enabled collection source.
- A company space and, for exposure work, an asset or product inventory.
- `run_analysis`; sensitive source handling must follow the stored TLP.

**Workflow.**

1. Create or import a signal and preserve its canonical source.
2. Map the claim to a product, component, dependency, version, asset, and owner.
3. Review exposure, exploitability, confidence, blast radius, and the explained
   0–100 prioritization score.
4. Create the appropriate PSIRT, hunt, IR, legal, detection, or reporting
   handoff rather than treating every signal as an incident.
5. Track actions, evidence, and status in the case graph.

**Outputs and handoff.** Scored signals, company spaces, asset registry
records, cases, watchlists, queues, flash notes, Hunt Packs, and handoffs into
Threat Hunting or other operational modules.

**Worked example.** Import a public CISA KEV record for a product represented in
a synthetic inventory. Confirm the affected version and exposure manually,
then create a hunt only when the deployment has the required telemetry.

**Illustrative case study.** A high-severity CVE appears in an internet-facing
VPN product. The initial score is high, but the owner confirms the affected
version is not deployed. The analyst records the product/version evidence and
reduces the operational priority rather than suppressing the source record.
Acceptance is an auditable decision with asset evidence, not the original
severity alone.

**Limits.** Threat Radar does not prove that an asset is vulnerable, reachable,
exploited, or compromised. Restricted sources must remain sanitized; do not
store credentials, stolen data, exploit payloads, or illegal access material.

<!-- module:reports_research -->
### Reports / Research

**Purpose.** Reports / Research is the durable library for source reports,
analysis sessions, handling markings, extracted entities, and analyst-reviewed
results.

**Inputs and prerequisites.**

- Public or authorized report text, PDF, or DOCX.
- A defensible TLP and source URL or internal evidence reference.
- `upload_files` for file intake; provider-backed extraction additionally
  requires a ready and permitted AI provider.

**Workflow.**

1. Record title, publisher, date, source, and handling marking.
2. Store or upload the source in an environment appropriate for its sensitivity.
3. Run deterministic parsing and, if approved, AI-assisted extraction.
4. Review every candidate IOC, actor, technique, and claim against the source.
5. Save the reviewed session and link it to hunts, evidence, or reports.

**Outputs and handoff.** Stored research sessions, source excerpts, reviewed
ATT&CK candidates, observables, citations, summaries, and links into AI
Analysis, Threat Hunting, Navigator, or Evidence Graph.

**Worked example.** Use
[`docs/demo-dataset/public-report-excerpt.md`](demo-dataset/public-report-excerpt.md),
record it as public source material, run analysis, and compare the reviewed
mappings with
[`expected-mappings.json`](demo-dataset/expected-mappings.json).

**Illustrative case study.** A vendor report mentions PowerShell only in a
defensive recommendation. The model proposes `T1059.001`, but no adversary
behavior excerpt supports it. The analyst rejects the mapping and records the
reason. Acceptance is evidence fidelity, not the number of extracted TTPs.

**Limits.** A stored report is not proof that its claims apply to the local
environment. AI summaries and mappings remain suggestions until reviewed.

<!-- module:apt_library -->
### ATT&CK Group Library

**Purpose.** The group library joins ATT&CK group profiles, aliases,
techniques, reports, campaigns, IOCs, and CVE correlations into a research
starting point.

**Inputs and prerequisites.**

- Current ATT&CK reference data and any configured local report/IOC sources.
- No AI provider is required for deterministic browsing.

**Workflow.**

1. Search by group name or alias.
2. Confirm the ATT&CK group ID and source provenance.
3. Review mapped techniques, campaigns, reports, IOCs, and vulnerabilities.
4. Load the technique set into Navigator or Compare.
5. Record which relationships are source-backed and which are analytical leads.

**Outputs and handoff.** Actor profile, alias set, technique layer, evidence
links, comparison input, and tracking candidates.

**Worked example.** Search for MuddyWater by name and known aliases, open its
ATT&CK profile, load the technique set, and use Compare to distinguish shared
commodity behaviors from less-common overlap.

**Illustrative case study.** A report uses an alias that maps to two clusters.
The analyst compares identifiers, dates, source references, and technique
evidence rather than merging them by name. Acceptance is a documented identity
decision with citations.

**Limits.** Actor-to-technique and IOC overlap are investigation leads, not
attribution proof. ATT&CK is a knowledge base, not a live activity feed.

<!-- module:sector_intel -->
### Sector Intelligence

**Purpose.** Sector Intelligence ranks actors and behaviors against sector,
region, technology, and time-window context.

**Inputs and prerequisites.**

- A defined sector and optional region/technology profile.
- Current actor, campaign, and sector-source data.

**Workflow.**

1. Select sector, geography, technologies, and activity window.
2. Review the factors that contribute to each relevance result.
3. Open source reports and actor records behind the score.
4. Move validated techniques into Navigator or Compare.
5. Export a prioritized review list with assumptions.

**Outputs and handoff.** Sector overview, ranked actors, candidate TTPs,
evidence routes, and reusable Sector Packs.

**Worked example.** Build a profile for an Israel-based technology company
using cloud identity, Linux production, and public APIs. Review the top actors
and techniques, but retain only items supported by current source material.

**Illustrative case study.** A group ranks highly due to historic regional
activity but has no recent reporting against the company’s technology stack.
The analyst keeps it as background context and prioritizes a lower-ranked group
with recent, technology-specific evidence. Acceptance is an explainable
priority list, not blind use of the score.

**Limits.** Relevance does not prove targeting. A sector or region match alone
is insufficient for blocking, attribution, or incident declaration.

<!-- module:knowledge -->
### Knowledge Library

**Purpose.** Knowledge Library provides local, searchable reference material
for research, strategy, reports, and reusable analyst context.

**Inputs and prerequisites.**

- Indexed local knowledge content and appropriate source permissions.
- Corpus reconciliation for RAG-backed cross-module retrieval.

**Workflow.**

1. Search by exact identifier, title, keyword, actor, product, or technique.
2. Open the local item and verify its canonical source and date.
3. Distinguish maintained guidance from historical or illustrative material.
4. Cite the relevant excerpt in analysis or Evidence Graph.
5. Refresh or archive stale content through the governed source workflow.

**Outputs and handoff.** Source-backed references, citations, local strategy
material, and retrieval candidates.

**Worked example.** Search for `T1059.001`, open the matching research item,
and link the exact excerpt that explains PowerShell telemetry requirements to a
hunt plan.

**Illustrative case study.** Two documents give conflicting remediation
advice. The analyst compares dates and authoritative sources, marks the older
item as historical context, and cites the current guidance. Acceptance is
traceable source selection.

**Limits.** Search ranking is not evidence confidence. Local content can be
stale, incomplete, or illustrative.

<!-- module:ioc_library -->
### IOC Library

**Purpose.** IOC Library is the normalized observable repository for domains,
IPs, URLs, hashes, email artefacts, malware-family context, source provenance,
freshness, confidence, and entity links.

**Inputs and prerequisites.**

- Synced IOC feeds, report extraction, manual import, or pipeline intake.
- Source attribution and timestamp fields for operational use.

**Workflow.**

1. Search by exact value, type, tag, family, actor, TTP, source, or freshness.
2. Open the IOC detail and compare all source observations.
3. Review normalization, deduplication, first/last seen, confidence, and TLP.
4. Pivot into IOC Investigation for current enrichment.
5. Export or create evidence only after validating source and time context.

**Outputs and handoff.** Deduplicated IOC records, observations, tags, source
links, actor/TTP/CVE/report relationships, and pivot actions.

**Worked example.** Import the same domain in uppercase and lowercase from two
synthetic sources. Confirm one normalized indicator with separate source
observations rather than duplicate operational records.

**Illustrative case study.** A domain appears in a year-old malware report and
a recent benign passive-DNS observation. The analyst does not add it directly
to a blocklist; they inspect history, current resolution, and source
confidence, then classify it as a review lead. Acceptance is a time-bounded
decision with both observations preserved.

**Limits.** IOC presence does not prove maliciousness, active use, targeting,
or compromise. Deduplication prevents redundant records; it does not reconcile
contradictory source claims automatically.

<!-- module:cve_library -->
### CVE Library

**Purpose.** CVE Library combines vulnerability records with CVSS, EPSS where
available, CISA KEV, CWE, affected-product context, and reviewed links to
actors, IOCs, and ATT&CK techniques.

**Inputs and prerequisites.**

- Synchronized NVD/CVE and configured enrichment sources.
- Asset or product evidence for deployment-specific prioritization.

**Workflow.**

1. Search by CVE ID, vendor, product, severity, KEV, CWE, or relationship.
2. Review source timestamps and scoring-vector details.
3. Distinguish affected-product claims from confirmed local exposure.
4. Inspect source-backed actor/IOC/TTP correlations.
5. Hand relevant CVEs to Threat Radar or Asset Surface for contextual review.

**Outputs and handoff.** CVE records, scoring context, KEV/weakness labels,
relationships, and vulnerability review candidates.

**Worked example.** Select a KEV-listed CVE, compare its CVSS vector and source
date, then check a synthetic inventory for the affected product and version.

**Illustrative case study.** A critical CVE has high severity but affects an
unused optional component; a high-severity CVE is confirmed on an
internet-facing asset. The second receives operational priority. Acceptance is
documented asset/version/exposure evidence.

**Limits.** CVSS and KEV are inputs, not complete risk decisions. The module
does not prove patch state, reachability, exploit success, or compromise.

<!-- module:retrohunt -->
### RetroHunt Signals

**Purpose.** RetroHunt searches historical local reports, indicators,
techniques, tags, and evidence for recurrence and previously unseen overlap.

**Inputs and prerequisites.**

- Historical records collected into the local RetroHunt store.
- Normalized tags and source timestamps.

**Workflow.**

1. Start with an IOC, actor, technique, family, product, or tag.
2. Search the historical collection and constrain the time range.
3. Review each match’s source, confidence, and relationship reason.
4. Group repeated observations without collapsing independent evidence.
5. Send credible recurrence into IOC Investigation, Threat Radar, or a hunt.

**Outputs and handoff.** Historical matches, tagged signals, recurrence
timelines, source counts, and investigation candidates.

**Worked example.** Search a synthetic domain across imported reports and IOC
observations. Confirm that independent appearances retain separate timestamps
and provenance.

**Illustrative case study.** A hostname resurfaces after six months. RetroHunt
finds an older report and actor overlap, but the current IP belongs to a shared
provider. The analyst creates a bounded DNS/proxy hunt rather than asserting
actor attribution. Acceptance is a hypothesis tied to current telemetry.

**Limits.** Historical overlap can be coincidental or stale. It is not proof of
the same operator, campaign, or intent.

## Analyze and Investigate

<!-- module:ai_analysis -->
### AI Analysis

**Purpose.** AI Analysis turns report text or uploaded documents into
structured, reviewable ATT&CK/ATLAS, IOC, actor, claim, summary, and gap
candidates.

**Inputs and prerequisites.**

- Source text or an authorized PDF/DOCX.
- A configured and module-ready provider for AI generation.
- Appropriate TLP handling and explicit acknowledgment for permitted remote
  processing.

**Workflow.**

1. Preserve the source metadata and handling marking.
2. Select a provider allowed by operator policy and source sensitivity.
3. Run analysis against the stored source.
4. Review candidate mappings against exact evidence excerpts.
5. Accept, reject, or edit results and preserve unresolved gaps.

**Outputs and handoff.** Reviewable TTP and IOC candidates, source citations,
summary, assumptions, confidence, and saved report session.

**Worked example.** Analyze the public demo report excerpt, reject mappings
without behavioral evidence, and compare accepted IDs with the expected mapping
file.

**Illustrative case study.** A model returns a valid technique ID but cites an
unrelated paragraph. The analyst rejects it despite plausible narrative. The
case passes when every accepted mapping has a supporting excerpt and human
decision.

**Limits.** AI output is not evidence. Provider availability shown in Self-test
does not replace the module’s policy, connectivity, and model-access check.

<!-- module:navigator -->
### Navigator

**Purpose.** Navigator is the ATT&CK/ATLAS matrix workspace for selecting,
reviewing, overlaying, and exporting techniques across supported domains.

**Inputs and prerequisites.**

- Current versioned ATT&CK/ATLAS data.
- An optional technique set from reports, actors, assets, RAG proposals,
  comparisons, or manual selection.

**Workflow.**

1. Select Enterprise, Mobile, ICS, or ATLAS before choosing techniques.
2. Search by ID/name and expand sub-techniques where relevant.
3. Open detail, detection, telemetry, and source references.
4. Apply reviewed overlays or explicit RAG proposal Add/Replace decisions.
5. Export or save a layer with its domain and version.

**Outputs and handoff.** Selected TTP set, coverage overlay, technique detail,
Navigator-compatible JSON layer, and inputs for Compare, Threat Hunting,
Attack Simulation, or Investigation.

**Worked example.** Select `T1059.001`, inspect its data requirements, add it to
a white layer, and export JSON. Verify the export retains the ATT&CK domain and
version.

**Illustrative case study.** A RAG assistant proposes eight TTPs for a business
profile. The analyst opens citations, rejects three unsupported items, previews
five, and explicitly adds them. Acceptance is the reviewed selection—not the
assistant proposal.

**Limits.** Selecting, previewing, or exporting a technique does not create a
detection, prove coverage, execute a hunt, or run a simulation.

<!-- module:compare -->
### Compare

**Purpose.** Compare measures overlap and gaps between a selected technique set
and groups, campaigns, reports, or another group.

**Inputs and prerequisites.**

- A selected Navigator/report/actor technique set.
- Current source profiles for the comparison population.

**Workflow.**

1. Confirm the selected domain and TTP set.
2. Choose Groups, Campaigns, Reports, or Group vs Group.
3. Run deterministic overlap analysis.
4. Inspect shared, exclusive, and missing techniques plus evidence.
5. Move distinctive leads into source review, Navigator, or a hunt.

**Outputs and handoff.** Similarity ranking, shared/exclusive TTPs, tactic
distribution, matrix diff, and detection-gap candidates.

**Worked example.** Compare a five-technique report layer with two ATT&CK
groups. Manually calculate intersection/union for one result to validate the
displayed overlap.

**Illustrative case study.** Two actors have the same high score because the
input contains common techniques. The analyst adds source, tooling, timing, and
infrastructure evidence before prioritizing either. Acceptance is a documented
lead, never “attribution by similarity.”

**Limits.** Similarity is not attribution, probability, or confidence that an
actor is present.

<!-- module:ioc_investigation -->
### IOC Investigation

**Purpose.** IOC Investigation performs a bounded pivot around one domain, IP,
URL, hash, or other supported observable.

**Inputs and prerequisites.**

- A normalized observable and its originating alert/report reference.
- Optional keys and connectivity for configured providers such as DNS,
  urlscan, VirusTotal, GreyNoise, Shodan, Censys, AbuseIPDB, or ThreatFox.

**Workflow.**

1. Enter the observable and confirm its type.
2. Select the permitted pivot depth and enrichment providers.
3. Run the investigation and preserve source-specific errors.
4. Review Tier 1/2/3 relationships, evidence, timestamps, and TTP/actor leads.
5. Save findings or produce a report with explicit assumptions and gaps.

**Outputs and handoff.** Enrichment results, relationship graph, pivot trail,
risk cues, TTP/actor leads, AI summary when enabled, and saved investigation.

**Worked example.** Use a reserved synthetic domain and a manual source record
to verify validation, empty-provider handling, and a saved report without
calling external services.

**Illustrative case study.** A domain resolves to a shared CDN IP and appears in
one threat feed. The analyst avoids expanding every co-hosted domain, limits
pivots, checks current resolution, and records the feed observation separately.
Acceptance is a scoped graph without guilt by shared infrastructure.

**Limits.** Provider errors and no-result responses are evidence gaps, not
benign verdicts. Relationship expansion can amplify weak or stale data.

<!-- module:malware_analysis -->
### Malware Analysis

**Purpose.** Malware Analysis manages an isolated case for safe static triage,
hash checks, strings, imports, unpacking, decompilation, optional runtime
evidence, and reviewed IOC/TTP candidates.

**Inputs and prerequisites.**

- An authorized sample or hash-only case.
- `upload_files` for sample intake.
- MalwareGraph service readiness and isolated disposable infrastructure for
  any dynamic execution.

**Workflow.**

1. Create a case and record acquisition source, handling, and hash.
2. Run hash/feed checks before opening or executing the sample.
3. Review static metadata, strings, imports, packer indicators, and leads.
4. Use Unpacker and Debugger for deeper static analysis.
5. Use Dynamic Analysis only in the explicitly isolated profile, then separate
   observed behavior from static inference.

**Outputs and handoff.** Sample case, hashes, static findings, strings, imports,
IOC/TTP candidates, pseudocode context, runtime evidence, and AI summaries.

**Worked example.** Use a harmless synthetic text fixture, confirm its hashes,
extract URL-like strings, and document why those strings are leads rather than
observed network activity.

**Illustrative case study.** Static strings suggest PowerShell and a domain, but
runtime evidence shows neither path executes. The analyst marks the strings as
unreached and accepts only observed behaviors. Acceptance is separation of
potential and executed behavior.

**Supporting workspaces.**

- **String Analyzer** (`/string-analyzer`) classifies strings, commands, URLs,
  paths, registry keys, and API leads.
- **Unpacker** (`/malware-unpacker`) reviews packing indicators and unpacking
  results; it does not guarantee a complete original binary.
- **Decompilation & Debug IDE** (`/malware-debug`) presents entry points,
  functions, recovered pseudocode, sections, imports, and analyst notes.
- **Dynamic Analysis** (`/dynamic-analysis`) reviews collected process, file,
  registry, network, DNS, memory, module, persistence, and decision evidence.

See [Malware Analysis Guide](malware-analysis-guide.md) and
[Malware Analysis Boundary](malware-analysis-boundary.md).

**Limits.** Static triage is not a sandbox verdict. Dynamic execution is
disabled by default and must never run on an analyst workstation or unapproved
network.

<!-- module:virustotal -->
### VirusTotal Lookup

**Purpose.** VirusTotal Lookup performs an on-demand lookup for a hash, domain,
IP, or URL and presents the provider response in AdversaryGraph context.

**Inputs and prerequisites.**

- A supported observable.
- A valid VirusTotal key, network connectivity, rate-limit capacity, and
  provider terms that permit the query.

**Workflow.**

1. Confirm the observable and its handling sensitivity.
2. Decide whether sending it to the external provider is permitted.
3. Run the lookup and record timestamp, provider response, and errors.
4. Review detections, relationships, and metadata.
5. Link relevant evidence to IOC Investigation or a report.

**Outputs and handoff.** Provider lookup record, detection summary, metadata,
relationships, and investigation leads.

**Worked example.** Use a known public benign test hash or domain allowed by
organizational policy, verify rate-limit/error handling, and save the response
timestamp.

**Illustrative case study.** One engine flags a newly registered domain while
most engines return no verdict. The analyst records the minority signal and
adds DNS/proxy checks instead of declaring malware. Acceptance is source-aware
triage.

**Limits.** A provider consensus is not proof, and an absent record is not a
clean verdict. Do not submit private URLs, hashes, or files without approval.

<!-- module:asset_surface -->
### Asset Surface

**Purpose.** Asset Surface normalizes CMDB, cloud, scanner, hostname/IP, and
manual inventory data into assets, exposures, risk priorities, and candidate
ATT&CK review paths.

**Inputs and prerequisites.**

- CSV, JSON, text, cloud inventory, CMDB export, or scanner output.
- Asset ownership and authorization for passive or active assessment.
- Optional Shodan/Censys-style keys and an approved scanner configuration.

**Workflow.**

1. Name the inventory and choose the target company space.
2. Paste or upload the inventory and review normalized assets.
3. Correct owner, environment, criticality, exposure, technology, host, IP,
   URL, and port fields.
4. Review passive intelligence and proposed related attack surfaces.
5. Run active scanning only against explicitly authorized targets; inspect
   findings, CVEs, TTP candidates, and evidence.
6. Add validated newly discovered IPs, hosts, or URLs to the same company
   inventory without duplicating existing normalized assets.

**Outputs and handoff.** Saved asset registry, asset detail pages, exposure
score, passive-source observations, scan jobs/results, CVE/TTP/IOC leads,
retrohunt matches, and Navigator layer.

**Worked example.** Import
[`asset-inventory-example.csv`](../asset-inventory-example.csv), open one asset,
review its normalized URLs/IPs, and run only the non-invasive workflow unless
the target is explicitly owned and authorized.

**Illustrative case study.** A web hostname resolves to an additional public IP
seen in passive data. The analyst verifies that it belongs to the organization,
adds it as a related surface with provenance, and schedules an approved bounded
scan. Acceptance is ownership evidence, normalized deduplication, and preserved
scan scope.

**Limits.** Inventory mapping and passive OSINT do not prove vulnerability.
Active scans can disrupt systems and must be authorized, scoped, rate-limited,
and logged. See [Asset Attack Surface Mapping](asset-attack-surface.md).

<!-- module:emb3d -->
### EMB3D

**Purpose.** EMB3D maps embedded-device properties and mitigations to the MITRE
EMB3D threat model.

**Inputs and prerequisites.**

- An embedded device, product, firmware, interface, deployment, or component
  description.
- Current EMB3D catalog data.

**Workflow.**

1. Record device purpose, deployment boundary, interfaces, update path,
   privilege model, hardware protections, and exposed services.
2. Match characteristics to EMB3D threat entries.
3. Review evidence, applicability, and mitigation status.
4. Record unknowns as validation gaps.
5. Export the assessment or link relevant behaviors into wider analysis.

**Outputs and handoff.** Device threat-model assessment, applicable threat
entries, mitigations, evidence notes, gaps, and export.

**Worked example.** Model a synthetic edge gateway with Ethernet, remote
firmware updates, a local debug port, and signed boot. Review both applicable
threats and existing mitigations.

**Illustrative case study.** A device exposes a maintenance interface in the lab
but production units have a physical enclosure control. The analyst records
different environment assumptions instead of applying one risk result to both.
Acceptance is environment-specific applicability.

**Limits.** Text matching is a threat-model aid, not a hardware penetration
test, firmware proof, or certification. See [EMB3D](emb3d.md).

<!-- module:evidence_graph -->
### Evidence Graph

**Purpose.** Evidence Graph preserves the reasoning chain from source evidence
to analyst decision:

```text
Evidence -> Claim -> Behavior -> ATT&CK Technique -> Required Telemetry
  -> Detection Candidate -> Detection Rule -> Validation Scenario
  -> SIEM Result -> Analyst Decision
```

**Inputs and prerequisites.**

- Evidence references from reports, IOCs, malware, assets, hunts, simulations,
  or SIEM validation.
- Analysts able to approve/reject draft nodes and relationships.

**Workflow.**

1. Create or open a graph context.
2. Add canonical evidence references before analytical claims.
3. Connect behavior to reviewed ATT&CK techniques.
4. Add telemetry, detection candidates, rules, and validation scenarios.
5. Record results and the final analyst decision without deleting failed paths.

**Outputs and handoff.** Typed nodes/edges, paths, coverage gaps, review states,
JSON/Markdown/CSV exports, and Evidence Packs.

**Worked example.** Add one report excerpt, a claim about encoded PowerShell,
`T1059.001`, required process/script-block telemetry, a draft rule, a lab
scenario, and an inconclusive result caused by missing telemetry.

**Illustrative case study.** A detection appears to pass, but the rule matched a
generic process event rather than the intended encoded-command field. The graph
keeps the failed validation edge, updates the telemetry requirement, and sends
the rule back for revision. Acceptance is traceable correction.

**Limits.** Graph connectivity does not make a claim true. AI-created nodes are
drafts until reviewed. See
[Evidence-to-Detection Graph](evidence-to-detection-graph.md).

## Hunt and Validate

<!-- module:threat_hunting -->
### Threat Hunting

**Purpose.** Threat Hunting manages falsifiable hypotheses, scope, ATT&CK
context, telemetry requirements, versioned queries, findings, outcomes, and
defensive handoffs.

**Inputs and prerequisites.**

- A report, signal, IOC, asset, detection gap, ATT&CK selection, or manual
  hypothesis.
- Access to an approved external SIEM/EDR/data lake when queries must be run.
- Optional ready AI provider for governed, stage-scoped suggestions.

**Workflow.**

1. Create a hypothesis with a bounded population, time range, behavior, and
   falsification condition.
2. Define ATT&CK IDs, telemetry sources, required fields, expected evidence,
   assumptions, and false positives.
3. Generate or select a query, review its language and field mapping, and save
   it as a version.
4. Copy the reviewed query to the approved telemetry platform.
5. Record evidence references and findings; do not paste sensitive raw data
   unnecessarily.
6. Set an explicit disposition and document telemetry gaps and handoffs.

**Outputs and handoff.** Versioned hunt, query revisions/checksums, AI
assistance audit records, findings, disposition, limitations, and export.

**Worked example.** Create “Suspicious encoded PowerShell execution,” map
`T1059.001` and `T1027`, choose KQL or SPL, define process/script-block fields,
and validate the generated query syntax in the destination platform.

**Illustrative case study.** The query returns no matches, but only 40% of
Windows endpoints provide script-block logs. The analyst records
`telemetry-gap`, not “environment clean,” and creates a collection improvement
handoff. Acceptance is an honest scoped conclusion.

**Limits.** AdversaryGraph records and reviews queries; it does not claim that a
stored query was executed in an external platform. AI cannot save a hunt,
create evidence, choose a verdict, or advance lifecycle state. See
[Threat Hunting Guide](threat-hunting-guide.md).

<!-- module:query_library -->
### Query Library

**Purpose.** Query Library provides searchable reviewed and community-sourced
detection content plus deterministic IOC-to-query drafting.

**Inputs and prerequisites.**

- Bundled or synchronized Sigma, YARA-L, YARA, KQL, SPL, EQL, Lucene, SQL,
  osquery, or generic query content.
- Source URL, license, parser status, tags, platform, and ATT&CK metadata.

**Workflow.**

1. Search ordinary text or use filters such as `ttp:T1059.001`,
   `lang:yaral`, `tag:persistence`, source, platform, or status.
2. Open the rule and verify provenance, license, parser status, and fields.
3. Adapt field names, product, index, time window, and exclusions.
4. Create a hunt draft or generate a query from reviewed IOCs.
5. Validate syntax and behavior in the destination platform.

**Outputs and handoff.** Query starting point, source metadata, ATT&CK links,
IOC-derived draft, and Threat Hunting handoff.

**Worked example.** Search `ttp:T1059.001 lang:sigma`, open a rule, map its
process fields to the local schema, and save the adapted query as a hunt
revision.

**Illustrative case study.** A community Sigma rule parses successfully but
assumes Sysmon fields absent from the environment. The analyst adapts it to EDR
fields, documents the source and changes, and validates both positive and
benign cases. Acceptance is local evidence, not parser success alone.

**Limits.** Community content may be stale, incomplete, or incompatible. A
generated or parsed query is not a validated detection. See
[Threat Hunting Query Library](query-library.md).

<!-- module:attack_simulation -->
### Attack Simulation

**Purpose.** Attack Simulation validates telemetry and detection behavior using
approved lab targets, source-shaped events, controlled scenarios, and optional
SIEM forwarding.

**Inputs and prerequisites.**

- Explicitly authorized lab targets.
- A selected technique/scenario and healthy attack-lab services.
- `run_attack_simulation`; `forward_siem` for destination delivery.

**Workflow.**

1. Select the ATT&CK technique or reviewed scenario.
2. Confirm the target is an approved fixture, never an arbitrary production
   endpoint.
3. Configure bounded parameters and a permitted SIEM destination.
4. Run the scenario; watch target-side logs or labelled source-shaped events.
5. Verify parser receipt, rule match, correlation, and expected non-match
   controls.
6. Save the result, limitations, and Evidence Graph relationship.

**Outputs and handoff.** Real fixture logs where supported, labelled synthetic
events where required, attack-chain graph, delivery history, rule-validation
result, and evidence.

**Worked example.** Run an approved web-lab scenario, observe NGINX/WAF-style
logs, forward them to a test collector, and verify a detection rule matches the
intended fields rather than only a generic status code.

**Illustrative case study.** Delivery succeeds but the SIEM rule does not fire.
The analyst confirms events arrived, identifies a parser field mismatch,
updates the rule, reruns the scenario, and records both attempts. Acceptance is
reproducible detection behavior with preserved failed evidence.

**Limits.** This is not a general exploit framework. Unsupported behavior must
be shown as a telemetry gap, not fabricated as “real logs.” See
[Attack Simulation](attack-simulation.md) and
[SIEM Forwarding Security](attack-simulation-siem-forwarding-security.md).

<!-- module:investigation -->
### Investigation

**Purpose.** Investigation assembles selected evidence, techniques, IOCs,
actors, findings, gaps, and decisions into a reviewable analyst handoff.

**Inputs and prerequisites.**

- Saved evidence or notes from upstream modules.
- `export_data` when producing downloadable artefacts.

**Workflow.**

1. Create or open the report workspace.
2. Add the question, scope, time range, owner, and handling marking.
3. Attach source references, accepted TTPs, IOC pivots, findings, and gaps.
4. Separate facts, analytical judgments, and unverified leads.
5. Record outcome, recommended actions, and reviewer.
6. Export the required analyst format.

**Outputs and handoff.** Analyst report, selected TTP layer, evidence
references, gaps, recommendations, and exports.

**Worked example.** Build a report from the encoded-PowerShell hunt with one
supporting process event, one rejected IOC lead, a telemetry gap, and a
recommended script-block logging action.

**Illustrative case study.** A Tier 1 escalation labels an IP “malicious,” but
the source evidence only shows scanning. The investigator revises the language
to “observed scanning source,” preserves the original alert, and documents the
confidence. Acceptance is precise claim/evidence alignment.

**Limits.** Export formatting does not validate the underlying analysis.
Sensitive evidence must remain in approved systems and be referenced rather
than copied when policy requires.

## Operations

<!-- module:operations -->
### Operations

**Purpose.** Operations manages durable investigation, intake, detection
backlog, tracked-actor, and analyst workflow objects.

**Inputs and prerequisites.**

- Reviewed records from intelligence, investigation, hunt, or validation work.
- Consistent owners, status values, tags, and due dates.

**Workflow.**

1. Create the appropriate operational object instead of an unstructured note.
2. Assign owner, priority, state, due date, and source links.
3. Attach evidence and upstream/downstream relationships.
4. Review status changes and blocked conditions.
5. Close with an outcome and retained audit history.

**Outputs and handoff.** Investigation records, intake items, tracked actors,
detection skeletons/backlog, and task context.

**Worked example.** Convert a confirmed telemetry gap for `T1059.001` into a
detection backlog item with owner, required data source, acceptance criteria,
and a link to the originating hunt.

**Illustrative case study.** Three reports create duplicate detection requests.
The manager links them to one backlog item, preserves each source, and records a
single validation plan. Acceptance is deduplicated work without lost evidence.

**Limits.** Operations is a local workflow manager, not a replacement for an
enterprise ticketing, SOAR, or case-management platform unless explicitly
integrated.

<!-- module:pipeline -->
### Pipeline

**Purpose.** Pipeline registers sources, normalizes incoming observables and
detection content, performs idempotent upserts, and creates structured
detection starting points.

**Inputs and prerequisites.**

- An authorized STIX/TAXII, MISP, CSV/JSON/TXT, sandbox, Sigma/YARA, or other
  supported source.
- Source type, URL/file, license, TLP, schedule, and credentials where needed.

**Workflow.**

1. Register the source and its handling/license metadata.
2. Test connectivity or parse an uploaded fixture.
3. Normalize and validate records before import.
4. Review duplicate/upsert behavior and rejected rows.
5. Link imported behavior to ATT&CK and generate detection skeletons only where
   evidence supports them.

**Outputs and handoff.** Source registrations, import jobs, normalized
observables, parser errors, audit records, and detection skeletons.

**Worked example.** Import a small synthetic STIX bundle twice. Confirm the
second run updates or reuses normalized objects instead of duplicating them.

**Illustrative case study.** A community feed changes field names and begins
rejecting half its rows. The operator pauses promotion, reviews parser errors,
updates the mapping, and reimports a fixture before production sync. Acceptance
is deterministic idempotent intake.

**Limits.** Successful parsing does not establish intelligence accuracy,
license compatibility, or detection quality.

<!-- module:statistics -->
### Statistics

**Purpose.** Statistics describes the local dataset across actors, reports,
sectors, TTPs, CVEs, IOCs, sources, tags, confidence, and telemetry fields.

**Inputs and prerequisites.**

- Sufficient normalized local records.
- Awareness that counts reflect this deployment and selected filters.

**Workflow.**

1. Choose the datasets to include.
2. Set row limits and filters.
3. Review totals, ranked tables, charts, and distributions.
4. Pivot from material rows into the authoritative module.
5. Record the filter and timestamp when using a metric in a report.

**Outputs and handoff.** Local coverage metrics, distributions, ranked
techniques/entities, source breakdowns, and pivot links.

**Worked example.** Compare the most frequent techniques in reviewed reports
with those represented in saved detection-validation records.

**Illustrative case study.** `T1059` dominates because one bulk-imported report
contains many sub-technique records. The analyst filters by source and unique
report before concluding there is a program gap. Acceptance is a metric with a
defined denominator.

**Limits.** Frequency is not risk, prevalence, attribution, or detection
coverage. Counts change with feed scope and local data quality.

## Platform

<!-- module:feeds -->
### Feeds Management

**Purpose.** Feeds Management configures, synchronizes, and diagnoses ATT&CK,
ATLAS, IOC, CVE, malware, report, OpenCTI, STIX/TAXII, MISP, and
detection-content sources.

**Inputs and prerequisites.**

- `manage_feeds`.
- Provider URLs, credentials, licenses, schedules, and network access.

**Workflow.**

1. Review enabled/configured state separately from live status.
2. Test or run one source sync.
3. Inspect last successful sync, record counts, errors, and degraded status.
4. Confirm imported records in the destination library.
5. Rerun Self-test and reconcile RAG when source data should be searchable.

**Outputs and handoff.** Source status, sync jobs, counts, timestamps, errors,
and normalized records in downstream libraries.

**Worked example.** Sync a permitted public IOC source, record its before/after
count, inspect duplicate normalization, and verify one record in IOC Library.

**Illustrative case study.** OTX is temporarily unavailable while existing
indicators remain in the database. The operator marks the source degraded,
preserves the last-success time, and avoids deleting data or claiming a current
sync. Acceptance is transparent freshness.

**Limits.** “Configured” does not mean reachable or current. A partial sync can
leave useful data while still requiring operator attention.

<!-- module:observability -->
### Observability

**Purpose.** Observability exposes operational health, redacted logs, request
traces, route metrics, readiness, audit signals, and Prometheus-compatible
metrics.

**Inputs and prerequisites.**

- `view_audit`.
- Writable log storage and configured metric collection where used.

**Workflow.**

1. Start with API and dependency health.
2. Filter recent failed/slow routes by status and correlation ID.
3. Review redacted log tails and trace summaries.
4. Correlate symptoms with container logs without exposing secrets.
5. Move to Troubleshooting for bounded remediation and recheck.

**Outputs and handoff.** Health status, request metrics, trace summaries,
redacted logs, runtime status, and audit evidence.

**Worked example.** Reproduce a failed IOC request, capture its route/status and
correlation context, then verify whether the cause is frontend/API connectivity
or a provider-specific error.

**Illustrative case study.** Users see “Network error” while the API is healthy.
Observability shows requests never reach the route; the operator identifies a
frontend proxy configuration issue, corrects it, and verifies a successful
trace. Acceptance is an end-to-end request, not just a healthy container.

**Limits.** Metrics and redacted logs are diagnostic evidence, not complete
forensics. Secrets and private source content must never be copied into support
reports.

<!-- module:admin -->
### Administration

**Purpose.** Administration manages named users, SOC groups, module/action
grants, passwords, MFA state, sessions, authentication settings, and auth audit
events.

**Inputs and prerequisites.**

- `manage_users`, `manage_auth`, or `view_audit` as appropriate.
- An enabled Platform Administrator recovery path.

**Workflow.**

1. Create a named user with a policy-compliant password.
2. Assign the smallest suitable SOC group and keep the legacy role at `viewer`
   unless a compatibility reason requires otherwise.
3. Confirm effective modules and permissions.
4. Test sign-in and expected access in a private browser session.
5. Review sessions/audit events; revoke or reset when required.
6. Maintain at least two independent administrative recovery accounts.

**Outputs and handoff.** Persistent users/groups, effective grants, sessions,
MFA/password state, revocations, and audit records.

**Worked example.** Create a Tier 1 analyst, verify IOC Investigation and
Reports are visible, verify Administration and Attack Simulation are denied,
then inspect the creation/login audit events.

**Illustrative case study.** A SOC manager requests feed administration. The
administrator rejects the broad grant and assigns the dedicated Feed Operators
group only to the operator responsible for synchronization. Acceptance is
least privilege plus API-level denial outside the group.

**Limits.** Module hiding is not the security boundary; backend enforcement is.
Native project-level auth is not multi-tenant isolation. See
[Authentication and User Management](authentication-and-users.md).

## Learn and Support

<!-- module:examples -->
### DFIR Examples

**Purpose.** DFIR Examples supplies public or synthetic material for training,
demonstration, regression checks, and workflow evaluation without private
evidence.

**Inputs and prerequisites.**

- Bundled examples and demo datasets.
- Clear labelling that results are examples.

**Workflow.**

1. Choose the example matching the target module.
2. Read its expected evidence and output before execution.
3. Run the workflow using the documented inputs.
4. Compare actual output with expected mappings and limitations.
5. Record deviations as bugs, data changes, or model variability.

**Outputs and handoff.** Reproducible sample sessions, reports, layers,
detection-gap CSV, and regression evidence.

**Worked example.** Run the public report excerpt through AI Analysis and
compare accepted mappings with the expected mapping file.

**Illustrative case study.** A model upgrade changes confidence values but
preserves supported technique IDs. The reviewer records model/version
variability separately from deterministic export correctness. Acceptance is
defined per test, not visual similarity alone.

**Limits.** Demo output is not customer evidence or production validation.

<!-- module:help -->
### Help / Local Guide

**Purpose.** Help provides the in-application local runbook and concise module
guidance, reachable from each page’s help control.

**Inputs and prerequisites.** A loaded frontend; no external provider is
required.

**Workflow.**

1. Confirm local start/update commands and service health.
2. Find the module card and review when-to-use, workflow, outputs, and tips.
3. Open the module directly.
4. Use this detailed casebook for extended examples.
5. Move to Troubleshooting when a health or action check fails.

**Outputs and handoff.** Operator commands, module orientation, and direct
routes into workspaces.

**Worked example.** An onboarding analyst reads the IOC Investigation card,
opens the module, runs the synthetic example, and reviews the result with a
senior analyst.

**Illustrative case study.** A new user tries to analyze a report in IOC
Investigation. Help redirects them to Reports / Research and AI Analysis,
preventing an incoherent workflow. Acceptance is correct module selection.

**Limits.** Help summarizes workflows; endpoint schemas and deployment controls
remain authoritative in the API, admin, security, and production guides.

<!-- module:troubleshooting -->
### Troubleshooting

**Purpose.** Troubleshooting provides bounded diagnostics for Docker, API,
database, Redis, storage, feeds, authentication, providers, and module errors.

**Inputs and prerequisites.**

- The exact symptom, timestamp, route, status, and relevant self-test result.
- Operator shell access for container-level remediation.

**Workflow.**

1. Preserve the error and correlation context.
2. Check container/API health before changing data.
3. Run the smallest relevant diagnostic.
4. Apply one reversible remediation.
5. Rerun the failed action and Self-test.
6. Escalate with redacted evidence if the failure remains.

**Outputs and handoff.** Diagnostic evidence, recovery commands, known-error
explanations, and a verified or escalated state.

**Worked example.** For a frontend `/system/selftest` network error, check API
health, frontend proxy target, container status, and browser request path before
rebuilding or deleting anything.

**Illustrative case study.** A feed shows disabled because an external URL is
unreachable. The operator confirms DNS/TLS/connectivity and provider status,
then either corrects the URL or leaves the source explicitly disabled. They do
not make Self-test green by suppressing the error. Acceptance is correct state
and an explained dependency.

**Limits.** Troubleshooting guidance cannot replace backups, change control,
provider support, or deployment-specific network knowledge. Never delete
volumes as a first response.

## Cross-module case studies

These cases show how modules combine. They are designed for public/synthetic
data unless the deployment owner has explicitly approved private data and
active testing.

### Case 1: Public report to reviewed detection candidate

**Question.** Which report behaviors deserve detection work?

1. Store a public excerpt in **Reports / Research** with source and TLP.
2. Use **AI Analysis** to propose ATT&CK mappings.
3. Reject candidates without direct behavioral evidence.
4. Review accepted techniques in **Navigator**.
5. Create a typed reasoning chain in **Evidence Graph**.
6. Search **Query Library** for a source-compatible starting point.
7. Create a **Threat Hunting** workspace and adapt the query.
8. Run the query in the approved external telemetry platform.
9. Record findings and build the **Investigation** handoff.

**Acceptance evidence.** Source excerpt, human mapping decision, query revision,
external execution reference, findings, gaps, and reviewer.

### Case 2: IOC alert to a bounded escalation

**Question.** Does a suspicious domain justify escalation?

1. Find the domain in **IOC Library** and review freshness/provenance.
2. Run permitted pivots in **IOC Investigation**.
3. Search **RetroHunt** for historical recurrence.
4. Review actor references in **ATT&CK Group Library** without asserting
   attribution.
5. Create a scoped DNS/proxy **Threat Hunt**.
6. Record the result in **Investigation** and **Operations**.

**Acceptance evidence.** Original alert reference, provider timestamps,
relationship reasons, query scope, findings, and explicit disposition.

### Case 3: Asset inventory to vulnerability assessment

**Question.** Which owned surface should be assessed first?

1. Import an authorized inventory into **Asset Surface**.
2. Correct owner, criticality, technology, exposure, and identifiers.
3. Review passive source observations and newly discovered related surfaces.
4. Check relevant vulnerabilities in **CVE Library**.
5. Add a scored signal and company asset context in **Threat Radar**.
6. Run a bounded active scan only with written authorization.
7. Move validated TTP candidates into **Navigator** and **Evidence Graph**.
8. Track remediation in **Operations**.

**Acceptance evidence.** Scope authorization, normalized asset identity, source
observations, scan configuration/result, version/exposure proof, and owner.

### Case 4: Malware sample to behavior-led hunt

**Question.** Which observed sample behaviors can be hunted?

1. Create a **Malware Analysis** case and preserve acquisition/hash data.
2. Run static triage and hash checks.
3. Review strings/unpacking/decompilation as leads.
4. If authorized, gather runtime evidence in isolated **Dynamic Analysis**.
5. Add only evidence-backed behavior to **Evidence Graph** and **Navigator**.
6. Search **Query Library** and create a **Threat Hunt**.
7. Report observed behavior separately from unexecuted strings or code paths.

**Acceptance evidence.** Hash, acquisition source, isolation boundary, observed
events, rejected leads, query scope, and findings.

### Case 5: Detection rule to simulation evidence

**Question.** Does the rule detect the intended behavior?

1. Select the technique in **Navigator**.
2. Link its required telemetry in **Evidence Graph**.
3. Adapt a rule from **Query Library**.
4. Configure an approved **Attack Simulation** fixture.
5. Capture target-side or explicitly labelled source-shaped telemetry.
6. Forward to a test SIEM and record delivery/parser status.
7. Record rule match/non-match and benign control results.
8. Update **Operations** and the final **Investigation** report.

**Acceptance evidence.** Rule revision, fixture authorization, event sample,
delivery receipt, parser fields, match result, control result, and reviewer.

### Case 6: Platform failure to verified recovery

**Question.** Why does a module action return a network error?

1. Preserve the visible error and failed route.
2. Use **Discover** health and Self-test to determine whether the API is ready.
3. Review route/trace/log evidence in **Observability**.
4. Follow the smallest matching **Troubleshooting** procedure.
5. Check **Feeds Management** or **Administration** only if the evidence points
   to source readiness or permissions.
6. Rerun the exact action and record success/failure.

**Acceptance evidence.** Before/after route result, container/API health,
correlation context, one documented change, and successful functional retest.

## Evidence and safety rules

- Keep source evidence, analyst judgment, and AI output visibly separate.
- Treat ATT&CK mappings, actor overlap, sector relevance, IOC relationships,
  CVE correlations, and RAG ranking as review leads.
- Do not infer targeting, exploitation, compromise, or attribution from one
  relationship or score.
- Preserve canonical source URLs, observation times, TLP, confidence, and
  rejected/failed paths.
- Do not send sensitive reports, observables, assets, or samples to remote
  providers without authorization and an applicable data-handling policy.
- Run active scans and simulations only against owned or explicitly authorized
  targets.
- Run malware only in isolated disposable environments.
- Record telemetry gaps and provider failures instead of converting absence of
  data into a benign conclusion.
- Validate queries and detections in the destination platform.
- Use [Validation and Limitations](validation-and-limitations.md),
  [Security Threat Model](security-threat-model.md), and
  [Production Readiness](production-readiness.md) as acceptance boundaries.
