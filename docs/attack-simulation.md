# Attack Simulation

Attack Simulation prepares and records ATT&CK-aligned validation scenarios
for approved lab targets. It is designed for detection validation, telemetry
verification, and coverage-gap documentation.

## Safety Model

The MVP is intentionally conservative:

- No arbitrary command execution from the UI.
- No exploit payloads.
- No user-supplied internet targets.
- No password attacks against real users.
- No malware or live payload execution.
- No network traffic emitted by the AdversaryGraph API runner.
- Only predefined simulations and approved lab targets are available.

The module creates dry-run plans, expected telemetry checklists, and manual
validation records. Analysts must attach evidence from an authorized lab run
before marking detection coverage as passed.

## Local Web Telemetry Server

For web-focused simulations, AdversaryGraph starts an internal lab web server on
`127.0.0.1:8765` inside the API runtime. The runner sends only predefined benign
requests to this local server and writes JSONL telemetry files under:

```text
<LOG_DIR>/attack-simulation/
```

Generated files include:

- `lab-web-access.jsonl` — server-side web access telemetry with method, path,
  client IP, headers, status, response bytes, run ID, and simulation ID.
- `run-*.jsonl` — attack-run telemetry with request sequence, response status,
  duration, response headers, byte counts, summary, and errors if any.

The **Real-Time Attack Logs** panel tails these JSONL files from the UI. The
**Forward Logs To SIEM** panel can POST the selected telemetry to an HTTP(S)
collector, for example a Splunk HEC, Logstash HTTP input, custom webhook, or
test receiver. The POST body is JSON:

```json
{
  "product": "AdversaryGraph",
  "module": "Attack Simulation",
  "source": "web",
  "run_id": "run-...",
  "event_count": 3,
  "events": []
}
```

Forwarding guardrails:

- Only `http` and `https` collector URLs are accepted.
- URL-embedded credentials are rejected; use the optional bearer token field.
- Metadata/link-local/multicast/unspecified destinations are blocked.
- Only generated Attack Simulation telemetry is sent.

The local server is a lab fixture, not a production target. It is useful for
validating event shape, ATT&CK mapping, parser behavior, SIEM ingestion, and
detection logic before running any approved scenario in a wider lab.

## Workflow

1. Open **Attack Simulation** from the sidebar or Discover page.
2. Select the ATT&CK TTP first.
3. The selected TTP opens a dedicated attack simulation configuration page.
4. Select an approved lab target from the target registry and review the target address context.
5. Add analyst context such as ticket, purpose, and maintenance window.
6. Generate a dry-run plan.
7. Review safety controls, expected telemetry, and approval checklist.
8. Create a controlled run record. For web simulations this starts the local
   telemetry server, performs the predefined benign request set, and writes JSONL
   telemetry.
9. Paste SIEM/WAF/firewall/DNS/proxy/EDR/IdP evidence into the manual result form
   when validating beyond the local lab server.
10. Mark the detection result as `passed`, `failed`, `partial`, or `not_proven`.

## Current Simulation Catalog

| Simulation | ATT&CK | Purpose |
|---|---|---|
| HTTP/TLS service fingerprint plan | `T1595` | Validate telemetry for benign local service fingerprinting |
| Public web exposure validation plan | `T1190` | Validate web visibility without exploit payloads |
| External remote service reachability plan | `T1133` | Validate remote-service reachability telemetry without authentication attempts |
| Controlled HTTP/DNS beacon validation plan | `T1071` | Plan lab-agent egress telemetry validation |
| Lab-only failed-login sequence plan | `T1110` | Plan low-rate identity telemetry validation against lab-only test accounts |

## API Endpoints

```text
GET  /api/simulation/catalog
GET  /api/simulation/targets
GET  /api/simulation/logs
POST /api/simulation/plan
POST /api/simulation/run
POST /api/simulation/forward-logs
POST /api/simulation/manual-result
```

## Validation Status

The default status is `not_proven`. A detection should only be marked `passed`
after external evidence confirms:

- The planned behavior happened in an authorized lab.
- Expected telemetry was collected.
- The relevant detection fired.
- Benign lookalikes and known gaps were considered.

## Future Build Path

The next safe expansion is an isolated runner agent:

```text
AdversaryGraph API
  -> job queue
  -> isolated lab runner
  -> approved lab target
  -> telemetry evidence
  -> AdversaryGraph validation record
```

The runner must enforce target allowlists, predefined adapters, rate limits,
timeouts, transcript logging, and cleanup hooks.
