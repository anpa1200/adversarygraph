# Changelog

## Unreleased

No changes are recorded after the v6.5.0 release boundary.

## v6.5.0 - 2026-07-25

- Fixed administrator user creation so browser/password-manager autofill is
  read from the submitted form, the action is no longer silently disabled, and
  username/password policy failures are shown as an accessible validation
  checklist before the API request.
- Expanded the README, quickstart, platform/user/admin/authentication guides,
  in-product Auth Guide, security/upgrade guidance, release notes, and OpenAPI
  description with the named-user workflow, least-privilege group guidance,
  verification steps, and user-creation troubleshooting.
- Added a detailed Module Reference and Casebook for all 31 governed
  workspaces, including prerequisites, repeatable workflows, outputs, worked
  examples, illustrative case studies, limitations, and six cross-module
  investigations. CI now fails if the backend module catalog and documented
  module coverage diverge.
- Updated the frontend lint toolchain to remove its high-severity transitive
  audit finding and pinned the Anomaly documentation site's `brace-expansion`
  resolution to a patched release. The Anomaly documentation image also uses a
  reviewed npm toolchain that does not bundle the vulnerable 5.0.7 copy. The
  pinned MalwareGraph UI build now applies an integrity-pinned PostCSS 8.5.18
  patch and fails on high dependency-audit findings before compilation. The
  remaining React Router v6 audit items are moderate, deployment-contextual
  limitations documented in the security and validation guides rather than
  hidden release exceptions.

- Added persistent SOC access groups with module-level RBAC. Built-in
  least-privilege profiles cover SOC Tier 1/2/3, SOC Manager, threat
  intelligence, threat hunting, detection engineering, incident response,
  vulnerability management, feed operations, audit/read-only access, and
  platform administration. User membership, sidebar visibility, frontend route
  boundaries, direct API access, grant ceilings, audit events, and
  last-user-manager continuity are enforced consistently.
- Added a searchable saved-asset registry and dedicated Threat Radar asset
  intelligence pages. Each asset exposes its normalized inventory, alerts,
  assessment history, CVEs, ATT&CK techniques, and IOCs through a server-side
  evidence-labelled correlation API. Exact identity matches, source-backed
  signal relationships, inventory candidates, and scan-derived candidates are
  kept distinct, and the authorized passive/Nmap/AI assessment workflow is
  available directly on the asset page.
- Added an authorized Asset Exposure Assessment workflow to Threat Radar.
  Analysts can select only IP addresses and HTTP(S) hosts recorded in the
  asset inventory, correlate them with configured passive OSINT sources,
  optionally run a bounded unprivileged Nmap service-discovery profile, review
  explicitly unconfirmed local CVE candidates, and request governed
  multi-provider AI analysis. Explicit authorization, attack-simulation
  permission, cloud-egress acknowledgement, private-target egress protection,
  persistent results, audit events, self-test readiness, and human-review
  warnings are enforced.
- Added a production Threat Hunting Query Library with more than thirty
  reviewed Sigma and YARA-L examples, normalized tags and ATT&CK links,
  provenance and parser state, server-side fielded search, typed autocomplete,
  facets, community-feed indexing, and direct handoff into canonical hunt
  drafts.
- Added deterministic IOC-to-query generation for Sigma, YARA-L, YARA, KQL,
  SPL, EQL, Lucene, SQL, osquery, and generic output. Values are typed and
  escaped locally, stored IOC ATT&CK mappings can be retained, and every result
  carries explicit destination-validation warnings.
- Added the official Google SecOps community YARA-L GitHub tree as a bounded
  default rule source alongside SigmaHQ and Yara-Rules. Successful rule-feed
  runs now refresh the normalized Query Library index while preserving
  upstream URLs, identifiers, license context, and validation metadata.
- Added a direct **Generate query** action to Threat Hunting and made YARA-L
  2.0 for Google SecOps UDM a first-class query target across the editor, AI
  request contract, prompt guardrails, and query-draft replacement workflow.
- Fixed Threat Hunting query assistance so the analyst selects an explicit
  target language, the AI generates from the saved hypothesis and telemetry
  context for that language, and a clearly labeled Use/Replace action copies
  both query text and type into the unsaved editor draft. Mislabeled provider
  output is rejected instead of being presented under the wrong query type.
- Self-hosted the Monaco query/code editor and its workers so the production
  content-security policy no longer leaves Threat Hunting query editing on an
  indefinite loading screen. Removed the unrelated Google Analytics bootstrap
  from the self-hosted application to preserve the no-external-script boundary.
- Fixed existing and fresh Atlas documentation volumes that could be initialized
  as root-owned by another container, leaving the non-root `atlas-builder` in a
  restart loop. A least-privilege one-shot initializer now reconciles ownership
  before the builder starts, and all Atlas volume mounts disable image copy-up.
- Enabled configured cloud providers for unsaved Threat Hunting plan drafts
  only when the draft has an explicit cloud-eligible TLP marking and the
  analyst authorizes that individual request. Restricted TLP markings remain
  local-only, later hunt stages still require saved canonical state, and every
  remote request now commits a redacted pre-egress audit event before any
  prompt leaves the deployment. Remote catalog entries now distinguish
  configured-and-permitted state from locally probed runtime readiness.
- Corrected the active MiniMax default to `MiniMax-M2.7` and aligned its
  OpenAI-compatible transport with the provider contract: bounded 2,048-token
  completions, separated reasoning output, a bounded timeout, and one retry.
- Fixed fresh source-checkout image handling: buildable AdversaryGraph services
  now stay on local build targets during `docker compose pull`, while the
  production overlay retains digest-pinned registry pulls. The next release
  workflow also fails closed unless all seven versioned GHCR images are
  anonymously readable and match the scanned image IDs before the GitHub
  release is published. Shared `latest` tags are no longer advanced; the
  release attachment records the verified immutable deployment digests. The
  workflow also rechecks the remote tag commit and exact draft metadata/assets
  immediately before publication, and fails unless active no-bypass tag
  rulesets protect the version tag from updates and deletion.
- Made host and container self-tests wait for first-boot reference ingestion
  instead of treating the first normal in-progress response as a terminal
  failure; a real failed ingestion still fails immediately. An auth-protected
  full self-test now exits `3` after a readiness-only check instead of reporting
  a false pass.
- Corrected reset guidance for the external PostgreSQL bind directory and made
  the legacy `make reset` target fail closed instead of deleting named volumes
  while silently preserving the database and its old credentials.
- Fixed source-build Compose startup for existing MalwareGraph volumes with a
  least-privilege one-shot ownership initializer shared by the UID 10001
  MalwareGraph service and GID 999 backend export path.
- Replaced the backend image's inherited HTTP healthcheck on Celery worker and
  beat services with process-appropriate checks, eliminating false unhealthy
  states while retaining API readiness checks on the API service.
- Added a unified normalized RAG corpus across IOC, CVE, ATT&CK/TTP, actor,
  actor sector/region/technology observations, campaign, report, knowledge,
  Threat Radar, Threat Hunting, Evidence Graph, and sanitized asset records,
  using exact identifier resolution,
  PostgreSQL full-text search, pgvector cosine search, reciprocal-rank fusion,
  source provenance, TLP/legal controls, and visible lexical-only fallback.
- Added relationship-aware retrieval over stored evidence-bearing actor-to-IOC
  and actor-to-CVE links plus current local ATT&CK actor-to-technique and
  actor-to-campaign relationships. Explicit IOC/CVE/TTP/campaign/actor requests
  can perform one bounded, non-recursive full-text expansion over allowlisted
  relationship identifiers; results label that retrieval signal and warn that
  link-based relevance is not proof of targeting, exploitation, or compromise.
- Added a governed Navigator-level intelligence assistant with strict structured
  output, verified source markers, stale-source rejection, local ATT&CK catalog
  validation, expiring checksum-bound proposals, temporary preview, and explicit
  Add/Replace confirmation without automatic named-layer persistence. Proposal
  and confirmation state is still persisted for audit.
- Added saved business profiles for private region, sector, technology, and
  crown-jewel context. Profiles participate in request-time retrieval/reranking
  and generation but are not exposed as globally searchable corpus documents.
- Added an MCP integration for bounded authenticated retrieval and advisory
  proposals through the same RAG API boundary, without arbitrary SQL, URL
  fetching, proposal confirmation, response actions, or Navigator mutation.
- Reduced the MCP subprocess configuration boundary to transport, API origin,
  token, and auth mode so it no longer imports or requires database, Redis,
  feed, or provider credentials.
- Made CVE retrieval fail closed when correlation evidence derives from linked
  IOCs: the document inherits the strictest IOC TLP, unresolved actor/IOC
  provenance becomes `TLP:AMBER+STRICT`, and relationship-derived CVE documents
  are legal-sensitive before provider selection.
- Enforced a loopback/private-host boundary for the local embedding endpoint,
  documented `http://127.0.0.1:3000` as the standard host-side MCP API origin,
  and documented that RAG reconciliation workers must use a direct PostgreSQL
  connection or PgBouncer session pooling because their advisory lock spans
  commits on one physical database session.
- Added scheduled, idempotent corpus reconciliation with run history,
  heartbeats, stale-run redispatch, lexical-only degraded operation, and a
  corpus-wide session advisory lock. Added bounded daily retention for inactive
  tombstoned documents and assistance/proposal records, including auditable
  operator-controlled legal-hold mode.

- Added a hypothesis-driven Threat Hunting workspace with lifecycle controls,
  ATT&CK mappings, telemetry and field requirements, bounded scope, TLP
  handling, reviewed findings, controlled dispositions, and soft archival.
- Unified analyst-created and Threat Radar-created hunts on the existing
  `threat_hunt_requests` record, including an additive upgrade migration and
  legacy context backfill.
- Added append-only query revisions with checksums so findings and exports keep
  reproducible query provenance without claiming that AdversaryGraph executed
  an external SIEM query.
- Added a comprehensive threat-hunting guide with a table of contents,
  governance and telemetry methodology, reusable worksheets and checklists,
  and twenty worked hunt playbooks using current ATT&CK v19 terminology.
- Added governed, advisory-only AI assistance to the plan, query, findings, and
  outcome stages, with stage-specific safe fields, explicit analyst review, and
  no automatic query execution, evidence creation, disposition, or lifecycle
  changes.
- Added report-to-hypothesis generation from completed, stored Enterprise ATT&CK
  report or research sessions, including bounded source coverage, exact citation
  binding, local ATT&CK ID verification, stale-context rejection, and editable
  draft application.
- Added operator-controlled provider policy for Threat Hunting AI: local/private
  processing by default, cloud processing disabled by default, per-request cloud
  acknowledgement, local-only handling for `TLP:AMBER+STRICT` and `TLP:RED`,
  bounded timeouts, rate limiting, and append-only sanitized assistance records.
- Reworked route authorization around explicit permissions and aligned frontend
  route/action visibility with the API, including separate user-management,
  authentication-administration, audit, upload, export, simulation, SIEM, feed,
  intelligence, detection, and analysis capabilities.
- Corrected local-auth lifecycle behavior for failed MFA logins, bootstrap
  password policy, MFA re-enrollment, session revocation, user changes, and
  security-event auditing.
- Added decoded byte limits for uploads and remote responses, bounded query and
  form schemas, safer archive extraction, path/identifier validation, and
  deterministic ATT&CK-version scoping for STIX analysis exports.
- Hardened caller-controlled outbound HTTP against unsafe schemes, local and
  metadata destinations, redirects, environment-proxy bypass, and unbounded
  responses; public DNS answers are revalidated and pinned at connect time
  while the original HTTPS hostname remains authoritative for SNI and
  certificate verification. Production DNS/egress controls remain defense in
  depth.
- Improved frontend reliability with authenticated startup gating, abortable
  streams, stale-response suppression, state isolation, safe URL handling,
  recoverable errors, deep-link restoration, and route-level code splitting.
- Added database-backed readiness, bounded/redacted observability data,
  deterministic background-job shutdown, and safer error responses that keep
  provider and internal details in server logs.
- Hardened non-root containers, Compose and Helm security contexts and storage,
  production environment preflight, backup/restore scripts, immutable CI
  dependencies, tag-only release publication, and scans for all seven published
  image families plus three digest-pinned supporting images.
- Hardened the post-v6 container release path: strict local and CI scans build
  with refreshed base images and no layer cache; runtime images install OS
  security updates available at build time; fixable high/critical findings fail
  the gate; and the tag workflow loads and scans versioned images before
  pushing those same local images. Added optional validated Helm digest fields
  for operator-resolved registry artifacts.
- Made the Anomaly Detection Atlas documentation build a release gate, with a
  reviewed source commit recorded in the image, durable AdversaryGraph overlay
  handling, and fail-closed validation for internal links and explicit anchors.
- Raised the enforced backend line-coverage baseline from 35% to 60% and added
  regression coverage for authorization, uploads, input limits, rate limiting,
  network clients, exports, observability, lifecycle shutdown, archive handling,
  simulation persistence, and Threat Hunting AI.

## v6.0.0 - 2026-07-17

- Promoted release metadata to v6.0.0 across backend, frontend, Helm, README,
  roadmap, security policy, version matrix, and release documentation.
- Added a consolidated v5 overview and corrected inaccurate v5.1-v5.4 release
  notes against the canonical changelog and repository history.
- Added a reproducible, opt-in Playwright screenshot workflow with sanitized
  deterministic data and a v6 screenshot evidence manifest.
- Added evidence-backed local case studies covering report-to-detection review,
  asset exposure prioritization, and controlled Attack Simulation validation.
- Added a v6 production-readiness and release go/no-go guide with explicit
  deployment boundaries, evidence requirements, rollback preparation, and
  post-release checks.
- Replaced stale hard-coded frontend version text with package-derived release
  metadata.
- Added a narrow Gitleaks policy for archived third-party HTML and explicit
  non-secret fixtures so local secret scanning matches the CI gate while
  application source remains fully scanned.
- Expanded reviewer and release-process documentation with v6 evidence links
  and repeatable validation commands.

## v5.9.1 - 2026-07-11

- Promoted active release markers to v5.9.1 across backend, frontend, README,
  roadmap, security policy, Helm metadata, version matrix, release notes, and
  documentation.
- Added JA3, JA3S, JA4, JA4S, JA4H, JA4L, JA4LS, JA4X, JA4SSH, and JA4T
  network fingerprint types to IOC import, normalization, tagging, and raw
  context preservation.
- Extended report-text IOC extraction so labeled JA3/JA4+ fingerprints are
  imported as network-fingerprint observables instead of generic hashes.
- Added network fingerprint context to IOC Detail, IOC Library filters, IOC
  node detail pages, and IOC Investigation pivot ranking.

## v5.9.0 - 2026-07-07

- Promoted active release markers to v5.9.0 across backend, frontend, README,
  roadmap, Helm metadata, version matrix, and release consistency checks.
- Added EMB3D backend service, API route, frontend page, unit coverage, and
  documentation for embedded-device threat model assessment workflows.
- Added unified product, component, dependency, and asset modeling support for
  cross-module exposure analysis.
- Expanded Threat Radar with full asset-inventory import templates,
  product-security example datasets, and a dedicated asset review page.
- Extended Asset Surface and Threat Radar backend/frontend workflows for
  product, component, dependency, and exposure triage.

## v5.8.0 - 2026-07-04

- Added Threat Radar product-security CTI early warning with scored signals,
  claims, evidence, case graphs, and sanitized legal-sensitive metadata.
- Added product/component/dependency exposure mapping, watchlists, workflow
  queues, and generated PSIRT, Threat Hunt, IR, Detection, and report outputs.
- Added Threat Radar route tests and documentation for the new workflow.

## v5.7.0 - 2026-07-03

- Promoted active release markers to v5.7.0 across backend, frontend, README,
  roadmap, security policy, Helm metadata, and release consistency checks.
- Added Reports / Research collection workflow with deterministic TTP, IOC,
  CVE, threat actor, sector, and infrastructure tag buckets.
- Added linked report review pages that preserve source text and link report
  entities back to Navigator, IOC Library, CVE Library, and ATT&CK Group
  Library.
- Added research upload from the collection page with a `Parse with AI`
  checkbox for either direct LLM extraction or source-only staging.
- Added a research analysis guide for turning strategic hardware, firmware,
  embedded, and edge-device research into AdversaryGraph CTI, CVE, telemetry,
  and detection-validation workflows.

## v5.6.0 - 2026-07-02

- Promoted active release markers to v5.6.0 across backend, frontend, README,
  roadmap, security policy, Helm metadata, and release consistency checks.
- Expanded the Statistics module with tag analytics across IOC, CVE, TTP,
  actor/group, report, sector, and cross-dataset views.
- Added risk, confidence, region, sector, type, source, telemetry source, TLP,
  attack-vector, malware-family, freeform IOC tag, and relationship-confidence
  statistics widgets.
- Hardened statistics query execution so one failed widget query rolls back
  cleanly and does not suppress later widgets.
- Added regression coverage for the new Statistics tag widget catalog.

## v5.5.0 - 2026-06-30

- Promoted active release markers to v5.5.0 across backend, frontend, README,
  roadmap, security policy, Helm metadata, and release consistency checks.
- Added enterprise access controls with expanded RBAC roles, per-user
  permissions, password policy settings, MFA workflow support, and trusted
  proxy SSO metadata.
- Added session administration, revoke-all controls, user-session revocation,
  and authentication audit history in the backend and Admin Panel.
- Updated Docker Compose, production overlay, Helm values, and `.env.example`
  with the new auth policy controls.
- Updated authentication, admin, and production-readiness documentation for
  enterprise access operations.

## v5.4.0 - 2026-06-30

- Promoted active release markers to v5.4.0 across backend, frontend,
  README, roadmap, security policy, version matrix, and release metadata.
- Added authenticated Observability dashboard coverage for API uptime,
  request metrics, recent traces, top routes, redacted API log tails, and
  Prometheus-compatible metrics.
- Added backend observability API routes for summary, traces, logs, and
  metrics.
- Added `make security-scan` and `scripts/security-scan.sh` for local
  validation of lint, SAST, dependency audit, secret scan, Docker config, and
  container scan where tools are installed.
- Added Bandit backend SAST coverage to CI and fixed SAST findings around weak
  hashes and XML parsing.
- Added screenshot-backed observability, security scanning, and validation
  documentation, including Attack Simulation, CVE correlation, authentication,
  and malware-analysis validation examples.

## v5.3.0 - 2026-06-30

- Promoted active release markers to v5.3.0 across backend, frontend,
  README, roadmap, security policy, version matrix, and release metadata checks.
- Added a local authentication guide page at `/auth-guide` that remains
  reachable before sign-in when native auth is enabled.
- Linked the login page directly to the authentication setup guide.
- Updated authentication, quickstart, admin, security, production-readiness,
  and public-demo privacy documentation for native username/password auth,
  roles, bootstrap admin cleanup, session behavior, and optional
  identity-aware reverse-proxy deployments.
- Revalidated frontend production build, backend lint, and the full GitHub CI
  workflow during the release update.

## v5.2.0 - 2026-06-30

- Promoted active release markers to v5.2.0 across backend, frontend,
  README, roadmap, security policy, version matrix, and release metadata checks.
- Made backend tests reproducible in a clean local shell by seeding explicit
  test-safe `DB_PASS` and `LOG_DIR` defaults before app settings are imported.
- Added a frontend npm override for Monaco's transitive DOMPurify dependency,
  clearing the frontend audit finding while preserving the decompilation/debug
  editor integration.
- Revalidated backend lint, backend tests with coverage, frontend dependency
  audit, and frontend production build during the release QA pass.

## v5.1.0 - 2026-06-30

- Promoted the active release marker to v5.1.0 across backend, frontend,
  README, roadmap, security policy, and release metadata checks.
- Added the Attack Simulation telemetry fidelity policy: scenarios and
  AI-assisted simulations must use source-correct telemetry and
  vendor/source-shaped event structures, and unsupported TTPs must be reported
  as telemetry gaps instead of generic fake logs.
- Added raw STIX preservation tables for every ingested STIX object and
  relationship while keeping the existing normalized ATT&CK query tables.
- Added CVE Library with NVD CVE API 2.0 and CISA KEV source sync,
  normalized CVE/CVSS score/CWE/CPE storage, strict evidence-backed
  CVE-to-technique/IOC/actor correlation tables, API routes, and a frontend
  CVE review page.
- Documented the Attack Simulation telemetry architecture rule for detection
  engineering and SIEM validation review, plus the ATT&CK/STIX and CVE Library
  data models.

## v4.1.0 - 2026-06-27

- Added Asset Attack Surface Mapping for uploaded or pasted CSV/JSON/TXT asset
  inventories, deterministic exposure/risk scoring, ATT&CK candidate links,
  priority actions, validation gaps, and optional AI-enriched summaries.
- Added saved backend cases for each Asset Surface analysis, with reload and
  delete actions for inventory reviews.
- Added white ATT&CK comparison layers for asset-inventory-derived TTPs so
  inventory findings are visually distinct from manually selected techniques.
- Updated Discover with first-screen launchers for Asset Surface, Malware
  Analysis, String Analyzer, Decompilation and Debug, Malware Unpacker, and
  Dynamic Analysis.
- Fixed sidebar scrolling for long module lists and updated the UI footer,
  backend version, frontend package version, and release documentation to
  v4.1.0.
- Added v4.1 screenshot evidence for Discover, Asset Surface analysis, saved
  Asset Surface history, and the white asset-surface Navigator layer.

## v3.1.0 - 2026-06-21

- Published the From Log to Report workflow as the v3.1 documentation and
  use-case refresh.
- Added the full Medium article media set, including animated GIF workflows,
  to the official guide, use-case drafts, Docusaurus docs, and 1200km site.
- Reworked use case 21 from the older ransomware triage placeholder into the
  end-to-end investigation workflow: create investigation, analyze firewall and
  EDR logs separately, enrich IOCs, review relationship graph pivots, compare
  TTPs, summarize with AI, and generate the report.
- Updated public documentation entry points for AI Analysis, Capabilities,
  Full Flow, and Use Cases.

## v3.0.0 - 2026-06-20

- Promoted AdversaryGraph to v3.0.0 with the investigation workflow as the
  main platform focus.
- Expanded IOC Investigation with Tier 1, Tier 2, and Tier 3 relationship
  expansion for IPs, domains, URLs, hashes, and suspicious artifacts.
- Added saved IOC investigations with history, reload, and delete actions.
- Added an analyst-focused relationship graph with actionable-node filtering,
  node detail pages, connected-node focus, clickable pivots, and observable
  reinvestigation from any graph node.
- Added evidence ranking, next-best pivot ranking, timeline extraction, and
  source-conflict summaries to make IOC investigations easier to defend.
- Added urlscan activity analysis for suspicious URL/page behavior and TTP
  leads.
- Added AI log/PCAP analysis workflows for extracting IOCs, suspicious
  behavior, functions, PowerShell indicators, TTP leads, and report-ready
  summaries from telemetry.
- Added richer AI report formatting and safer overlap/explanation language for
  analyst handoff.
- Added the v3.0 release notes, release summary, and Medium-style publication
  draft.

## v2.7.0 - 2026-06-20

- Added IOC Investigation as a dedicated Tier 1 / Tier 2 pivot workflow for
  IPs, domains, URLs, hashes, and other suspicious artifacts.
- Added `/api/ioc/investigate` to combine local IOC DB evidence, configured
  enrichment providers, relationship expansion, ATT&CK TTP leads, actor leads,
  kill-chain/tactic context, and AI-ready report input.
- Added enrichment pivots for VirusTotal, ThreatFox, MalwareBazaar, OTX,
  urlscan.io, GreyNoise, AbuseIPDB, Shodan, and local IOC/OpenCTI/MISP-loaded
  records.
- Added the IOC Investigation page with actions to show discovered TTPs on the
  ATT&CK matrix, add them to My TTPs, search IOC Library, and open VirusTotal
  Lookup.
- Added optional AI summarization for IOC investigations through the configured
  LLM providers.
- Updated Discover, quickstart, admin docs, and environment examples for the
  new investigation workflow and optional enrichment keys.

## v2.6.0 - 2026-06-19

- Added AI log/PCAP analysis for pasted telemetry or uploaded files, with IOC
  extraction, suspicious activity triage, ATT&CK mapping, actor-overlap hints,
  and report output.
- Added Navigator layer save/import/compare workflows for reviewing overlapping
  ATT&CK layers with distinct layer colors and overlap tags.
- Added AI Analysis actions to inject extracted TTPs into Navigator or compare
  them as a separate layer.
- Expanded the Discover page with direct workflow actions for self-test, report
  analysis, IOC investigation, actor review, feed management, and matrix work.
- Updated the 30-use-case documentation set to v2.6.0, removed draft markers,
  and embedded the animated GIF walkthroughs from the published Medium use-case
  article.

## v2.5.9 - 2026-06-19

- Added the public Yara-Rules malware repository as a default YARA feed source.
- Added YARA-L detection skeleton generation and validation support.
- Added optional AI-assisted detection rule generation for Sigma, YARA, YARA-L,
  KQL, SPL, and EQL outputs.
- Added provider selection, model override, telemetry input, and analyst context
  fields for AI rule generation in Intelligence Pipeline.
- Updated operator documentation for detection generation workflows.

## v2.5.8 - 2026-06-19

- Added per-IOC enrichment detail pages with source metadata, raw enrichment
  values, mapped TTPs, actor links, source metadata, and raw JSON.
- Made IOC values clickable from the IOC Library and actor/group IOC tabs.
- Added clickable pivots into Navigator, ATT&CK Group Library, source reports,
  and IOC Library search.
- Updated operator documentation for the IOC detail workflow.

## v2.5.7 - 2026-06-19

- Added MiniMax as a first-class external LLM provider through its
  OpenAI-compatible Chat Completions API.
- Added `MINIMAX_API_KEY`, `MINIMAX_MODEL`, and `MINIMAX_BASE_URL` settings.
- Wired MiniMax into AI Analysis, Navigator AI chat, IOC AI-enrichment provider
  selection, backend provider validation, self-test API-key reporting, Docker
  Compose API/worker environment forwarding, and operator documentation.
- Added focused provider factory test coverage for MiniMax registration.

## v2.5.4 - 2026-06-19

- Normalized legacy/provider hash IOC labels into `sha256`, `sha1`, and `md5`.
- Added duplicate IOC consolidation with actor-link and metadata preservation.
- Added evidence-priority IOC-to-TTP mapping: strict source/report evidence,
  enrichment-platform metadata, then optional AI fallback.
- Added `/api/ioc/enrich/ttps` for local IOC DB reprocessing.
- Added opt-in AI fallback controls to IOC Library and Feeds Management.
- Updated IOC sync APIs with `ai_enrich` and `ai_provider` options.
- Added focused tests and updated operator documentation.

## v2.5.0 - 2026-06-18

- Added a full IOC Library page with search, type/source filtering, group/actor
  filtering, sorting, enrichment actions, STIX export/import, TAXII pull, MISP
  JSON export connection, and custom feed registration.
- Added searchable multi-select ATT&CK group filtering for IOC Library records
  and STIX exports.
- Added VirusTotal IOC enrichment with structured verdicts, detection context,
  sandbox/rule details, extracted ATT&CK TTP evidence, actor matches, and
  Navigator/My TTP actions.
- Added YARA/Sigma rule-feed synchronization and sandbox behavior feed
  enrichment for malware behavior and detection context.
- Added IOC-to-TTP mapping from imported reports, source metadata, VirusTotal,
  OTX, Malpedia, and custom feeds.
- Added STIX 2.1 and TAXII workflows for IOC exchange with CTI platforms.
- Fixed dynamic reference DB manual sync so FastAPI no longer calls
  `asyncio.run()` from an active event loop.
- Improved IOC Library group dropdown behavior and visibility.
- Changed project licensing from MIT to the AdversaryGraph Personal Use License:
  personal/private use is free; business, commercial, organizational,
  client-delivery, production, or government use requires prior written
  approval from Andrey Pautov.

## v2.4.0 - 2026-06-18

- Added daily dynamic reference database synchronization for MITRE ATT&CK,
  MISP Galaxy, and configured IOC intelligence sources.
- Added an external persistent Postgres data directory controlled by
  `ADVERSARYGRAPH_DB_DIR`, so private reports, custom IOCs, custom feeds, and
  analyst data survive Docker image rebuilds.
- Added `POST /api/sync/dynamic-db` and a Reference Sync UI action for manually
  refreshing the dynamic reference database.
- Added a migration helper for moving existing Docker named-volume Postgres data
  into the external deployment directory.
- Extended deployment self-test output with database host/name and external data
  directory details.
- Fixed ATT&CK Group Library IOC count mismatch by using the same active
  180-day IOC definition in the group list and actor IOC tab.
- Updated docs for the dynamic DB model, external data directory, release
  workflow, and IOC count semantics.

## v2.2.0 - 2026-06-18

- Added an internal Docker troubleshooting page at `/troubleshooting` with
  deployment checks, self-test commands, log commands, ATT&CK data probes, and
  recovery order.
- Added contextual troubleshooting links to API and startup self-test error
  popups.
- Added a global API error popup with clear HTTP status, request path, and
  message context.
- Added a `Recheck` action on API error popups that reruns the AdversaryGraph
  self-test and turns the popup green with `All correct.` when the deployment
  is healthy.
- Added `/api/system/selftest` and a Docker `selftest` service for validating
  database connectivity, ATT&CK/ATLAS ingestion, and Redis connectivity after
  `docker compose up`.
- Improved startup behavior by retrying matrix data queries and refreshing
  matrix/discover/sync data after self-test passes.
- Documented the v2.2 operational troubleshooting workflow in release notes,
  release summary, quickstart, and full guide examples.

## v2.1.1 - 2026-06-18

- Published the project under the canonical AdversaryGraph name after the
  product rename.
- Renamed repository, docs, Docker defaults, generated assets, docs, release
  material, and ecosystem links to AdversaryGraph.
- Preserved old public site URLs through compatibility redirects and retained
  legacy asset paths where external links may exist.
- Updated connected 1200km ecosystem repositories to point to the new
  AdversaryGraph project hub, docs, article, and repository.
- Fixed the embedded ATLAS docs nginx fallback to avoid pre-build redirect-loop
  errors during fresh Docker startup.
- Verified a clean clone deployment with `docker compose up -d --build` and
  HTTP 200 probes for API, frontend, and embedded ATLAS docs.

## v2.1.0 - 2026-06-17

- Added Sector Intelligence MVP for client-facing actor relevance scoring.
- Added local intel source tables, MISP Galaxy threat-actor sync, sector/region
  observations, and actor relevance scoring from sector evidence, geography,
  ATT&CK campaign recency, and TTP depth.
- Added `/api/sector/*` endpoints and a Sector Intel UI page for syncing actor
  metadata and ranking actors by client sector, region, environment keywords,
  and activity window.
- Added IOC Intelligence MVP with local IOC source/indicator/actor-link tables,
  ThreatFox sync support, manual IOC import, actor IOC tabs, freshness filtering,
  confidence/source evidence, and CSV export.
- Added custom/personal IOC feed registration and sync for JSON, CSV, and TXT
  feeds with actor-aware IOC normalization.
- Added centralized Reference Sync action for all IOC sources, including
  ThreatFox and custom IOC feeds.
- Added AlienVault OTX actor pulse sync to enrich IOC-to-actor links from pulse
  adversary fields, actor aliases, pulse tags, and pulse indicators.
- Added report-upload IOC extraction for private PDF/DOCX/TXT analysis inputs.
- Added actor IOC count display, actor IOC tab actions, and Sector Intelligence
  actor IOC shortcuts.
- Improved Sector Intelligence filters with multi-select A-Z searchable
  dropdowns for sectors, regions, and technologies/environments.

## v2.0.0 - 2026-06-16

- Added local LLM support through OpenAI-compatible endpoints such as Ollama,
  LM Studio, LocalAI, and vLLM.
- Added STIX 2.1 export for OpenCTI workflows from completed analysis sessions.
- Added DFIR Examples with public report metadata, TTP/actor indexing, and a
  local PDF workflow for private AI analysis.
- Added Reference Sync UI/API for MITRE ATT&CK Enterprise, Mobile, ICS, and
  MITRE ATLAS synchronization status and manual sync.
- Added MITRE ATLAS matrix ingestion as a first-class sync domain with ATLAS
  tactics, techniques, sub-techniques, and domain-aware AI extraction prompts.
- Enriched ATT&CK Group Library with actor metadata, aliases, external
  references, technique evidence, tactic coverage, platform coverage, and
  source context.
- Added cached ATT&CK bundle fallback behavior to reduce GitHub API-rate and
  startup fragility.
- Added demo video, GIF, and poster for the report-to-analysis-to-comparison
  workflow.
- Added full v2 user/operator guide and OpenCTI export documentation.
- Expanded backend coverage to 76 passing tests and kept frontend production
  build green.

## v0.9.0 - 2026-06-15

- Added maturity documentation package: security policy, contribution guide, maintainers file, roadmap, validation plan, demo dataset, sample outputs, and issue templates.
- Added CI workflow for backend tests and frontend build.
- Documented product limitations, deployment boundaries, and evidence requirements for analyst review.
- Added production-readiness tracker for self-hosted deployment boundaries,
  implemented gates, and remaining blockers.
- Added analyst review-state support and evidence-binding notes to the roadmap
  and maturity documentation.
- Added release notes and a repeatable release checklist for reviewer-friendly
  tagged releases.

## v0.8.5

- Public intelligence and ecosystem release.
- Promoted AdversaryGraph Web as the browser-native workspace.
- Added correlated CTI/IR report and 1200km resource indexes.
- Added persistent evidence, source, confidence, mapping quality, notes, and coverage maturity fields.
- Added Anomaly Detection Atlas integration and ATT&CK technique cross-links.
