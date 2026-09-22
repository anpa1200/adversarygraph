# Deterministic PCAP analysis

AdversaryGraph accepts saved PCAP and PCAPNG files as packet evidence. This is
separate from the legacy AI-assisted log workflow: packet decoding, event
normalization, hashes, findings, and frame references are deterministic for a
recorded analyzer manifest. LLMs and live intelligence providers do not run in
the packet-decoding trust boundary.

## Architecture

```text
browser
  -> authenticated API upload and SHA-256 acquisition
  -> durable analysis/session record
  -> internal-only PCAP analyzer (TShark, no external network)
  -> schema and semantic-checksum validation
  -> ATT&CK ID validation and TTP-overlap actor leads
  -> internal-IR Review Gate preflight
  -> IOC, investigation, Navigator, actor, and artifact pivots
```

The `pcap-analyzer` sidecar is non-root, read-only, capability-free, bounded by
CPU, memory, PID, upload, tool-output, event, flow, endpoint, and timeout
limits, and attached only to the Compose `pcap_control` internal network. The
API authenticates to it with `PCAP_ANALYZER_TOKEN`. Temporary capture contents
and exported HTTP objects are deleted when the request ends. The API can retain
the original capture in its private `pcap_data` volume when
`PCAP_RETAIN_UPLOADS=true`.

## Deterministic contract

Every completed result contains:

- capture SHA-256, byte size, format, packet count, time range, duration,
  encapsulation/interface facts, and protocol counts;
- normalized endpoints and directional byte/packet counts;
- normalized TCP/UDP flows with stable IDs and stream numbers;
- bounded DNS, HTTP, TLS ClientHello/JA3, DHCP, and identity-protocol events;
- recovered host/account/domain identity candidates with IP/MAC associations;
- HTTP-exported object metadata and SHA-256 hashes (object contents are not
  retained by the analyzer);
- typed observables with roles, first/last seen values, and packet evidence;
- versioned rule findings with severity, confidence, metrics, and frame/stream
  references;
- suggested ATT&CK mappings tied to finding IDs and evidence;
- coverage caps, truncation warnings, and encrypted-payload limitations;
- a semantic SHA-256 over canonical JSON.

The idempotency key binds the source capture hash to the analyzer manifest. A
repeat upload under the same manifest returns the existing completed analysis.
Changing TShark/profile/rule-pack material or any output/coverage limit changes
the manifest and therefore creates a new analysis authority record. The API
independently recomputes the semantic result hash and rejects source or
manifest mismatches.

## Rule-pack boundary

### Evidence profile v4 and rule pack v3

The v2 manifest includes the analyzer source-code SHA-256. The API returns the
original verified JSON object without Pydantic default insertion or field
removal, preserving the semantic checksum on upload and retrieval.

HTTP decoding uses two-pass frame references for keep-alive request/response
association. Missing or contradictory linkage stays unknown. Object hashing
visits all exported objects within byte budgets, deduplicates full SHA-256s,
then prioritizes content-classified objects and size before applying the unique
metadata cap. Inventory totals, omissions, aliases and occurrence counts are
explicit. Bounded static inspection never executes, imports, or unpacks files.

Identity extraction includes Browser announcements and SAMR full names. SAMR
subjects are not automatically assigned to the replying server or requesting
client; full-name/client binding requires an independently observed principal.
NBNS queries are not hostname ownership evidence and group names are distinct.

Repeated NXDOMAIN, directory-service operations and multi-name TLS cadence are
contextual leads, not DGA, DCSync or attribution claims. Generic octet-stream or
zero-length responses do not establish executable delivery. POST size/count
does not automatically map to T1041. Static content and User-Agent claims do
not establish execution. Rule confidence measures the pattern, not maliciousness.

Every successful upload also creates a dated, independently hashed `context`
snapshot in session provenance: up to 5,000 exact typed local IOC lookups,
current local ATT&CK catalog/detection links, source-backed actor assertions,
and observation overlap with up to 50 prior completed captures. URL path case
is preserved; a substring is not an exact match. These snapshots are outside
the immutable packet result and do not promote indicators or attribute actors.
Their limits are visible. Historical knowledge may postdate the incident.
External provider calls remain explicit analyst actions, now also available
inside the PCAP result. PCAP ingestion makes none. No match means unknown in
the available corpus.

The shared AI extraction system prompt and legacy log/PCAP prompt separate
facts, heuristics, source claims and hypotheses; reject instructions embedded
in evidence; and require grounded mappings without fabricated family labels.
The deterministic PCAP route does not invoke an LLM, so its retest cannot
measure a prompt-quality or model-accuracy improvement.

The v3 follow-up preserves a compact overflow hash index (up to 50,000 entries)
beyond the 500 rich artifact records, exposing those hashes as observables for
local enrichment. It also normalizes TShark boolean spellings, suppresses NULL
NTLM placeholders, and exposes bounded short unclassified TCP payloads.
Structured software self-identification is reported literally, without a
sample-specific IOC list. Sustained unclassified public TCP conversations are
review leads, not automatic C2 verdicts. The first ten unseen v2 outputs are
preserved separately; v3 retests on those captures are regression tests, not a
second independent held-out benchmark.

The initial rule pack recognizes evidence-backed behaviors including:

- cleartext HTTP on TCP/443;
- stable HTTP callback cadence;
- NetSupport/TeamViewer remote-access User-Agents;
- PowerShell-originated HTTP;
- repeated, high-volume, or multi-target periodic POST activity;
- multi-megabyte POST bodies;
- token-bearing cleartext API requests and multi-kilobyte fingerprint uploads;
- script, archive, and executable transfers indicated by HTTP metadata.

These findings prove the stated packet behavior only. For example, a large POST
proves declared transfer volume, not the body contents or malicious intent; an
executable response proves delivery metadata, not execution. Rules are
candidates until analyst review.

## Platform enrichment and promotion

Deterministic packet evidence remains unchanged while derived context is
handled by existing governed components:

| Evidence | Native destination | Boundary |
|---|---|---|
| IP, domain, URL, JA3/JA4, hash | IOC Investigation and IOC Library | Live provider results are separate enrichment, never part of the semantic packet hash |
| HTTP object SHA-256 | IOC Investigation; MalwareGraph if an analyst separately supplies the object | Analyzer retains metadata/hash, not executable contents |
| ATT&CK candidate | My TTPs, Navigator comparison, linked report | Suggested until reviewed and promoted |
| Actor similarity | APT profile | TTP-overlap investigation lead, never attribution |
| Identity, finding, observable | Investigation Evidence Graph | Preserves capture, analysis, rule, and frame lineage |
| Exported-object artifact | Investigation Evidence Graph and authenticated file recovery | Exact body SHA-256 can bind a decoded HTTP response; unresolved bindings remain unknown |
| Full report | internal-IR Review Gate | Promotion requires the normal claim/evidence governance path |

Up to 200 evidence-qualified indicator candidates are staged at ingestion.
Ordinary observations, standalone executable downloads, DNS failures and
directory activity do not qualify on their own. They enter the IOC Library
only after claim review and promotion; private/reserved IPs remain evidence,
not threat IOC candidates. TTP-overlap actor leads are excluded from actor
claims. Later provider snapshots do not overwrite approved claims or silently
promote new indicators: review their candidate assessment and use the existing
IOC Investigation / report-review workflows.

### Evidence-backed reputation workflow

Open a capture under **Analyze → Log / PCAP**. The assessment separates:

- `observed`: no supporting maliciousness evidence; retained for investigation.
- `suspicious`: a linked behavior/static feature or direct suspicious provider
  report merits review; this is not confirmed malware.
- `intelligence-match`: exact typed local IOC match; source quality and dates
  still require review.
- `provider-reported-malicious`: direct typed provider evidence for this exact
  target; not independent confirmation, capture-time intent or actor attribution.

The panel initially shows candidates and recovered hashes, not every network
endpoint as an IOC. Select up to ten targets, up to three providers, and explicitly
authorize disclosure. Source marking must be **TLP:CLEAR**, with `run_analysis`
and `export_data` permissions. An authorized analyst can review/change the
source marking through the existing linked-report editor. Consent cannot
bypass a restricted marking. Public-looking enterprise domains may still be
sensitive: the operator must review the selected values.

`POST /api/pcap/analyses/{id}/enrich` accepts `observable_ids`, `providers`, and
`consent: true`. It reuses existing IOC Investigation credentials/adapters for
VirusTotal, ThreatFox, MalwareBazaar, OTX, urlscan, GreyNoise, AbuseIPDB, Shodan
and Censys. Unsupported target/provider combinations are reported, not queried.
No sample upload, scan submission, DNS resolution or request to an observed
destination occurs. Private/reserved IPs, special-use domains, identities and
full URLs cannot be automatically disclosed. Hashes are exact exported-byte
identifiers, not proof that a complete server-side file was recovered.

Only direct typed fields establish reputation: VirusTotal's target-bound engine
counts; exact MalwareBazaar/ThreatFox records; target-bound GreyNoise
classification; and AbuseIPDB confidence as a suspiciousness lead, not malware
proof. Related-object detections, arbitrary threat-name text, graph size, DNS
resolution and shared hosting do not transfer maliciousness. IP:port records
are not treated as exact bare-IP verdicts. Context providers supply leads only.
No detections, no record, no credentials, errors and rate limits never mean benign.
Conflicting direct benign/malicious provider reports remain visible.

Each signal has a query timestamp and available provider analysis/observation
dates. The dated `pcap_enrichment` snapshot is stored in session provenance,
outside the immutable packet result. Updates are serialized per capture and
audited. A batch has a 90-second budget, each provider lookup at most 25 seconds;
budget skips are explicit. The latest results for at most 200 targets are
retained, with omission counts and a previous-snapshot hash. This is a bounded
rolling snapshot, **not** an immutable archive of every previous response.
Reports include the current assessment and snapshot identity without replacing
the original source report or invalidating its citation offsets. Investigation
graph handoffs link back to the authoritative capture, and the second-layer
story fetches provider assertions as intelligence leads, never packet facts.

### Verified file recovery

Profile v4 calculates SHA-256, SHA-1 and MD5 over the exported bytes. It hashes
decoded HTTP response bodies separately, removes body bytes from returned JSON,
and links a response only on a full SHA-256 match. Request linkage additionally
requires TShark's frame reference, matching stream, ordering and reversed peers.
No filename-only or same-stream-only association is accepted. A matching
declared Content-Length is reported narrowly, not as proof of complete capture,
successful execution or original compressed/ranged server-file identity.

**Download verified bytes** calls
`GET /api/pcap/analyses/{id}/artifacts/{artifact_id}/download`. It requires
`export_data` and a retained capture. The API validates the storage location
and source hash, requests re-extraction from the isolated decoder, and checks
returned size and SHA-256 independently. Responses are `application/octet-stream`,
attachment-only, `nosniff`, `no-store`, with a SHA-256 `.bin` filename. User-supplied
filenames are never filesystem paths. Export symlinks are ignored. Downloading
does not execute or unpack anything; analysts must handle bytes in isolation.

Exports are watched for file-count, single-file, total-byte, diagnostic-output
and time budgets while TShark runs. Exceeding a budget discards that export
inventory with an explicit warning; packet evidence remains available. The
watcher checks every 100 ms, so this is not a hard filesystem quota: retain the
container's resource limits. HTTP only is supported here; encrypted TLS without
keys, missing packets, unsupported protocols and ambiguous bodies remain
coverage limits. Existing captures need reanalysis to gain v4 hashes/bindings;
old SHA-256 inventory remains readable.

The Analyze UI adds bounded evidence nodes for these entities and exposes direct
investigation, IOC, hash, Navigator, actor, and Review Gate pivots. The
deterministic analyzer itself has no provider credentials and cannot silently
turn an enrichment result into packet evidence.

## API

- `POST /api/pcap/analyze` — upload, decode, validate, save, and start review.
- `GET /api/pcap/analyses` — list durable PCAP analyses.
- `GET /api/pcap/analyses/{analysis_id}` — retrieve the complete structured
  result and linked analysis/report IDs.

The normal `run_analysis` and `upload_files` permission gates apply. The
legacy `POST /api/analyze/log-pcap` endpoint remains available for pasted logs
and text-derived telemetry; it is not the packet decoder.

## Configuration

```dotenv
PCAP_ANALYZER_ENABLED=true
PCAP_ANALYZER_TOKEN=<long-random-secret>
PCAP_ANALYZER_TIMEOUT_SECONDS=600
PCAP_ANALYZER_TOOL_TIMEOUT_SECONDS=300
PCAP_ANALYZER_MAX_TOOL_OUTPUT_BYTES=268435456
PCAP_MAX_UPLOAD_BYTES=536870912
PCAP_RETAIN_UPLOADS=true
```

Production validation requires a distinct analyzer token and an immutable
`ADVERSARYGRAPH_PCAP_ANALYZER_IMAGE` digest.
Helm installations can set `pcapAnalyzer.enabled=false`; new uploads then return
HTTP 503, while previously saved analyses remain readable.

## Regression fixtures

Large training captures are not committed. Operators can validate their local
fixtures with:

```bash
python3 scripts/validate-pcap-fixtures.py --repeat /path/to/capture.pcap
```

The checked-in fixture contracts cover six malware-traffic-analysis captures
and assert immutable source hashes, packet counts, case-relevant behavior
rules, result integrity, and optional semantic repeatability. On the reference
TShark 4.2.2 run, all six contracts passed; a repeated 15,512-packet capture
produced the same semantic SHA-256 twice.

## Limitations

### Passive enrichment handoff

IOC Investigation is a separate, opt-in disclosure boundary: submit only
authorized indicators to configured providers, not raw captures or payloads.
Depth-two/three expansion uses the local corpus. Saved provider results can be
opened without a fresh lookup at `/ioc-investigation?session=<session-id>`.
Case handoff retains a bounded graph preview, full-result reference, provider
provenance and explicit truncation counts. Graph edges reference transferred
node IDs; actor assertions remain unreviewed leads, not case actor associations.
Provider-reported ATT&CK leads distinguish the submitted indicator from local
pivots and do not establish that a captured host executed those techniques.

MalwareBazaar hash metadata queries use the documented form-encoded `get_info`
request. Application-level request failures are errors even with HTTP 200;
missing records have `not_found` status, not a benign verdict. No sample upload
or download is performed. See the [provider API contract](https://bazaar.abuse.ch/api/#query_hash).

### Packet coverage

- Saved-capture decoding is not traffic capture, malware execution, fake
  internet, TLS decryption, memory analysis, or endpoint telemetry.
- Encrypted payload contents remain unavailable unless the analyst provides
  suitable decryption material through a separate controlled workflow.
- TShark support and output can change between versions; the manifest makes
  that change explicit rather than claiming cross-version byte identity.
- Caps and truncation warnings must be reviewed before treating absence as
  evidence.
- Actor overlap, ATT&CK mappings, IOC reputation, and maliciousness decisions
  require analyst review.
