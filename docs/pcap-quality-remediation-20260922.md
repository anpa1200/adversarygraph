# PCAP investigation quality remediation

Baseline: `96b72e9e27b161e11ee41de7f668d2a73ff05640`. The frozen ten-case
benchmark under `pcap-platform-ten-20260922` remains unchanged. These captures
are now regression fixtures, not unseen accuracy tests.

## Acceptance plan

1. Preserve typed PCAP evidence through investigation, report, PDF and story.
   Never treat identities, all file hashes or ordinary network inventory as IOCs.
   Permit evidence reports without selected ATT&CK techniques.
2. Preserve provider error categories, apply quota backoff across batches and
   reuse dated exact-target results without changing immutable packet evidence.
3. Add bounded protocol/body interpretation and recovery for email, embedded
   payloads and raw HTTP/TCP evidence. Never execute sample content; retain
   provenance, truncation, direction and uncertainty.
4. Replace noisy TLS cadence candidate propagation with evidence-based triage
   and a ranked, bounded enrichment plan spanning DNS, TLS, HTTP and file pivots.
5. Improve narrative evidence packing and factual validation. Keep governed
   disclosure controls; no implicit TLP downgrade. Do not run qwen3:8b.
6. Run unit/integration/browser tests and real-capture regressions. Upgrade the
   local service only after gates pass, then verify the actual platform flow.

## Measurement boundaries

- Observation extraction, IOC selection, hash recovery, interpretation,
  provider availability, report preservation and native LLM synthesis are
  separate measures, not a single invented accuracy percentage.
- No family/actor attribution is inferred solely from rarity, a port, a hash
  label, a related provider object or an overlapping ATT&CK technique.
- No sample-specific IP, domain, hash or expected answer is embedded in rules.
- Secrets in decoded traffic remain redacted in narrative evidence; downloads
  are untrusted attachments behind platform permission checks. The existing
  local/no-login deployment does not exercise authenticated production access.
- Performance comparisons record decoder version, profile, timing and cache
  state. Failed or missing provider coverage is not a clean verdict.

## Implemented changes

| Area | Changes | Principal files |
|---|---|---|
| Deterministic decoding | Combined protocol pass; explicit protocol selectors preserve CLDAP/LDAP; direction-aware HTTP-on-443; cleartext credential/inventory structural signals; SMTP metadata and connection fanout | `pcap_analyzer/app.py` |
| File recovery | Inert embedded base64, bounded contiguous raw HTTP recovery, IMF message export; exact SHA-256/SHA-1/MD5; frame/stream/parent provenance and completeness; protected recovery endpoint | `pcap_analyzer/app.py`, `backend/app/services/pcap_analyzer.py` |
| IOC assessment | TLS cadence is an enrichment lead, not automatically an IOC; public-peer direction including IPv6; evidence-ranked query queue; weak network-only engine warnings remain context | `pcap_assessment.py`, `PcapReputationPanel.tsx` |
| Provider resilience | Typed exact-target verdicts; optional VirusTotal enrichment failure cannot discard direct verdict; dated cache; shared quota cooldown; partial-provider coverage remains pending; error/not-found are not clean results | `pcap_provider_cache.py`, `pcap_reputation.py`, `pcap_assessment.py`, `virustotal.py`, `ioc_investigation.py` |
| Platform handoff | Typed identity/artifact/IOC nodes; direct malicious hash candidates survive deduplication; zero-TTP reports allowed; native PDF byte offsets corrected | `Analyze.tsx`, `InvestigationReport.tsx`, `api/client.ts` |
| Narrative governance | Audited workspace markings; source/local-CTI TLP inheritance including canonical aliases; privacy-aware preflight; ungoverned cross-case records stay local; source-bound IOC allowlist and quote validation | `operations.py`, `investigation_story.py`, operations model/database startup |
| Narrative reliability | Native strict JSON schema; model selects passage IDs and server binds original quotations; lossless source-text segmentation; one bounded, paced regeneration; 4,096-token story-only output reservation; separate bounded story timeout; safe provider failure categories and actual usage | `investigation_story.py`, `threat_hunting_ai.py`, `ai/openai.py`, `core/config.py` |

The network-only VirusTotal shortlist threshold is three malicious engine
reports when no capture behavior or local intelligence independently justifies
review. This is a conservative triage rule, **not** statistical calibration or
three independent confirmations. The complete dated provider assertion remains
visible even when it is not shortlisted. Thresholds must be evaluated against
the environment's acceptable miss/false-positive trade-off.

The model does not receive every raw packet or every exported fragment. It
receives the selected saved report in full, all normalized identities/findings
with representative references, candidate-file/selected artifact details and
dated provider evidence. Counts, scope and source hashes document the
projection; complete native evidence remains available locally. Exact quote
binding is not semantic entailment, and accepted stories remain review drafts.

Story prompt v4 no longer asks the model to reproduce long escaped quotations.
It selects server-issued passage IDs; the server attaches the original text and
runs the unchanged identifier, IOC-allowlist, evidence-level and word-budget
validators. All source text remains visible in ordered passages. Ten live stored
evidence packs were checked locally for lossless segmentation and unique quote
bindings. This is a local validation, not proof of a successful LLM story.

Queue policy v2 distinguishes completed attempted providers from pending failed
providers. A ThreatFox `not_found` no longer masks a VirusTotal rate limit.
Expired cooldowns can return to the reviewed queue; active cooldowns and
credential failures do not enter an automatic retry loop. The historical
enrichment measurements below predate this final bookkeeping correction; no
improved external-provider coverage is claimed without another authorized run.

## Validation evidence

Evidence root: `/home/andrey/wireshark/pcap-quality-retest-20260922`.
The authoritative capture re-run is `final/`; `live/` and `offline/` retain
intermediate diagnostics and are not silently substituted for final results.

- Ten real platform submissions, same 130,815 packets and unchanged source
  capture hashes. Decoder: TShark 4.4.18, profile `tshark-evidence-v6`, rules
  `pcap-rules-v5`; source hashes are in each analyzer manifest.
- All 12 comparable published payload SHA-256 values recovered, previously 10.
  The added Word document is inertly decoded from its parent HTML; the added DLL
  is recovered from a bounded contiguous TCP stream. No sample is executed.
- 21 selected artifacts downloaded through the platform and independently
  checked against recorded SHA-256 and byte counts. This is not an assertion
  that every exported object was downloaded or is malware.
- Ten native full reports, ten independently text-parsed PDFs and 50 screenshots.
  Additional native story outcomes are recorded separately in `final/metrics.json`.
- 255 stored cross-case overlaps checked against both captures. Routine shared
  addresses remain non-specific context, not common-campaign or actor evidence.
- Final decoder API time 80.974 seconds total, prior 119.667 seconds. Single runs
  under different load/profile conditions: approximately 32.3% lower measured
  time, not a controlled throughput guarantee.
- All 54 comparable answer-listed network values are in inventory. The strict
  final IOC shortlist matches 20/54 versus the prior native 22/54; the earlier
  human-agent curated list matched 35/54 and is a different workflow. No previous
  shared-service rejection remains shortlisted, but this is not a complete
  false-positive census. **There is no defensible overall 100% accuracy claim.**
- Exact expected identity strings improve from 19/24 to 22/24. One remaining
  mismatch is FQDN versus short-host form; another has conflicting hostname and
  machine-account evidence. Do not turn directory subjects into authenticated
  identities to improve the score.
- Backend suite: 1,604 passed, 180 skipped, coverage 73.22%; 35 analyzer
  tests; 3 browser regression tests plus the ten real-browser case workflows.
  Read the versioned test logs for exact commands/results and skipped scope.
- All 552 frozen original files hash-verified unchanged. Answers were already
  known, so these are regression cases and not a blinded/unseen benchmark.

## Local deployment and rollback

Implementation worktree: `/home/andrey/wireshark/adversarygraph-pcap-quality`,
based on `96b72e9`; prepared as source candidate `v8.1.0-beta.1` on
`release/8.1.0-beta.1`. Commit/push receipts, rather than this source document,
establish publication. Unrelated canonical checkout edits were preserved.
`frontend/node_modules` is a test-only symlink, not source to stage.

The existing `adversarygraph` Compose project uses its original compose file,
the existing `pcap-upgrade-20260922/compose.pcap.yml`, then the retained
`pcap-quality-retest-20260922/compose.quality.yml` override. Data volumes are
unchanged. Backend image is `quality-20260922-v12`, frontend `quality-20260922-v3`,
analyzer `quality-20260922-v2`. The tags are worktree builds, not fictional Git
commits. `PROVENANCE.json` checks deployed Python sources against local SHA-256
and records actual container image IDs and health.

Those regression images precede the metadata-only version bump and identify
themselves as `8.0.0-beta.1`. Committing/pushing `8.1.0-beta.1` source does not
upgrade the running instance, publish registry tags, or certify the full v8
production/manual acceptance matrix.

After recreating the API container, reload/restart the frontend: its existing
Nginx configuration resolves the Docker service address at configuration load.
Otherwise the static SPA may be healthy while API requests receive stale-upstream
502s. Verify `/api/ready` through port 3000 after the reload.

Rollback uses the original two compose files without the quality override and
recreates only API/worker/beat/frontend/analyzer. Original image tags and data
volumes remain available. The added `investigations.tlp` column is additive and
does not need to be destructively removed for rollback.

## Operational boundaries and remaining work

- Native narratives use the instance's configured GPT-4.1, not the assistant's
  model and not Qwen. Provider quota reports show a 30,000-token/minute limit.
  Oversized requests cannot be repaired by immediate retries. Do not silently
  change models, truncate a full report, or claim a story was saved when it failed.
- Latest recorded native story result is **0/10 saved**, with rate/size/schema
  failures preserved. The v10 strict-schema pilot progressed from structure
  failures to quote-binding failure. The subsequent v4 passage-binding change
  passes local tests but its cloud retest was blocked by automatic review pending
  explicit permission to disclose the public training evidence to GPT-4.1.
  It is not appropriate to describe that final fix as live-validated.
- `final-story-local-validation.json` preserves safe historical failure audit
  details: 11 model responses recorded 330,307 input and 20,501 output tokens
  (350,808 total). These are failed-response records for these workspaces, not
  all experiment usage, not all billing records and not this assistant's tokens.
- The OpenAI Docs troubleshooting guidance informed separation of authentication,
  rate-limit, quota, request, timeout and validation failures:
  <https://developers.openai.com/api/docs/guides/error-codes>.
- External enrichment is bounded and requires explicit consent; no file uploads,
  active scans or reputation propagation from a malicious file to its hosting IP.
  Provider availability, historical IP reuse and unknown encrypted traffic leave
  real recall gaps. Review statuses/call timestamps before operational blocking.
- One Asco raw-HTTP fallback reaches its 100-of-248-stream cap. Some exported
  HTTP records are fragments, not distinct complete malware downloads. Unknown
  completeness, binding ambiguities and parser corruption must remain visible.
- Cross-case overlap can be mathematically correct but operationally weak.
  Routine multicast/vendor overlaps must not be counted as verified intrusion
  links. Campaign correlation and family-label reconciliation still need review.
- The local instance remains in its existing local/no-login mode. These tests
  do not establish authenticated multi-tenant production isolation. Permission
  checks have unit/integration coverage but no authenticated live login was used.
- The frontend's pre-existing large-chunk build warning remains; it is not a
  compiler failure and this change does not refactor unrelated application chunks.
