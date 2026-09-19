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
| Exported-object artifact | Investigation Evidence Graph | Preserves capture/analysis lineage and object hash; TShark export does not supply an object-to-frame binding |
| Full report | internal-IR Review Gate | Promotion requires the normal claim/evidence governance path |

Up to 200 public IP, domain, URL, network-fingerprint, and file-hash
observations are staged as report-local indicator candidates. They enter the IOC Library and
intelligence graph only after claim review and promotion; private IPs are kept
in capture evidence but are not staged as threat IOCs. TTP-overlap actor leads
are deliberately excluded from actor claims.

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
