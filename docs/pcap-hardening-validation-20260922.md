# PCAP evidence and reputation hardening — validation

Date: 2026-09-22. Baseline: `131dcdd`. Implementation worktree:
`feat/pcap-evidence-reputation`, created separately to preserve unrelated edits.
This is an implementation/regression exercise, not an independent malware
detection accuracy benchmark or a claimed 100% detection result.

## Delivered behavior

- Observations are separate from suspicious, exact local-intelligence matches,
  and direct provider-reported malicious candidates. The Review Gate does not
  receive every public address/domain as an indicator.
- Recovered HTTP objects have SHA-256, SHA-1 and MD5. Exact response-body hashes
  and verified HTTP request references supply provenance where available.
  Unknown completeness, direction and request associations are not guessed.
- Authenticated object recovery re-extracts from the retained capture and
  independently verifies bytes. Objects remain untrusted attachment downloads;
  no execution, archive unpacking or active destination access occurs.
- Selected passive enrichment reuses existing platform provider adapters and
  credentials. It requires consent, permissions and TLP:CLEAR; private/reserved
  targets, full URLs and special-use domains cannot be automatically disclosed.
- Dated reputation snapshots are distinct from immutable packet evidence.
  Provider context and correlations reach the investigation story as
  intelligence leads, not observed behavior or attribution. The story prompt
  is versioned and explicitly rejects inventory-to-IOC copying.
- Case-sensitive URLs stay separate. Verbose registry replies retain typed
  hash evidence instead of converting it into truncated free text. Rate-limited
  providers are deferred for the remainder of the batch.

See [the module contract and workflow](pcap-analysis.md) for API routes,
disclosure policy, provider interpretation and limits.

## Verification results

| Check | Observed result |
|---|---|
| Full backend unit/integration suite | 1,587 passed, 180 skipped, 44 warnings; 70.57 seconds |
| Final focused decoder/assessment/story/API suite | 87 passed; 6.65 seconds; overlaps the full suite, not additional independent cases |
| Frontend production build | TypeScript and Vite passed; existing large-chunk warning remains |
| Browser controls | Selection, consent, refreshed report, file download, bounded investigation handoff and non-attribution passed |
| API contract | 358 operations, 31 modules, 322 frontend API calls validated; reference regenerated |
| Changed Python correctness lint | Passed |
| Whitespace validation | Passed |
| Original six captures | Six passed; each decoded twice with identical semantic hashes |
| Real file recovery | One object from each capture recovered through local ASGI + real TShark; size and all three hashes matched |
| Unauthorized sidecar recovery | HTTP 401 with token enforcement enabled |
| Benign keep-alive control | Zero IOC candidates |

The full backend run uses mocked API persistence/provider fixtures. Its 180
skips include opt-in PostgreSQL and standalone-service tests. The file-recovery
checks use real captures/TShark but an in-process ASGI transport, not the user's
running deployment. Browser tests use fixture API responses. No live paid
provider reputation check or LLM generation was performed; neither current
provider availability nor narrative quality is claimed validated here.

## Real-capture evidence

| Capture | First decode (s) | Recovered objects with three hashes | Exact response-body bindings | IOC review candidates, no live reputation |
|---|---:|---:|---:|---:|
| 2025-01-22 | 25.953 | 24 | 24 | 3 |
| 2025-06-13 | 25.174 | 68 | 4 | 78 |
| 2026-01-31 | 32.438 | 8 | 6 | 6 |
| 2026-02-28 | 15.188 | 36 | 31 | 16 |
| 2026-08-09 | 19.582 | 157 | 58 | 45 |
| 2026-09-11 | 47.471 | 58 | 15 | 70 |
| Total | 165.806 | 351 | 138 | 218 |

The 213 objects without a response-body match remain unbound: these counts
must not be presented as 351 proven downloads or 218 confirmed malicious IOCs.
All matching object hashes identify exact exported bytes, not necessarily
complete original files. Candidate counts express triage policy, not measured
precision/recall. Microsoft update executables and other ordinary downloads
do not become malicious merely because they are executable files.

Per-capture deterministic JSON, assessment Markdown reports, repeated-result
hashes, recovery checks and the benign control are saved locally at:

`/home/andrey/wireshark/pcap-hardening-validation-20260922/`

Key artifacts: `summary.json`, `recovery-controls.json`, `benign-control.json`,
and the six dated `.json` / `.md` pairs. The reproducible recovery runner is
`verify_recovery.py`. Browser screenshot evidence is in the implementation
worktree's `frontend/test-results/pcap-reputation-*/pcap-evidence-assessment.png`.
Raw malicious objects are not added to the repository.

The first real-capture run exposed a 128 KiB CSV parser field limit. This was
fixed using the already-bounded decoder-output limit and the six captures
rerun successfully. Browser testing found that no-IOC captures were incorrectly
disabled for investigation handoff after stricter filtering; that was fixed.
The sandbox also blocked local browser binding and asynchronous thread wakeups;
bounded reruns outside it passed. Those failed/interrupted attempts are not
counted as successful tests.

## Release boundary

Source changes are not a running-instance update. No container rollout,
commit, push or deployment is claimed by this validation. Rebuild the API,
frontend and PCAP sidecar together when releasing. Existing retained captures
can be reanalyzed under profile v4; their old authority records stay intact.
No database migration is needed: the new dated snapshot uses existing session
provenance storage. A live deployment smoke test, real PostgreSQL concurrent
snapshot update test, and explicitly authorized configured-provider check
remain release follow-ups.
