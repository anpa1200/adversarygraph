# Attack Simulation

Attack Simulation prepares and records ATT&CK-aligned validation scenarios
for approved lab targets. It is designed for detection validation, telemetry
verification, and coverage-gap documentation.

## Safety Model

The MVP is intentionally conservative:

- No arbitrary command execution from the UI.
- No exploit execution. Web scenarios use fixed benign canary strings that look
  like attack telemetry but are never executed by the lab server.
- No user-supplied internet targets.
- No password attacks against real users.
- No malware or live payload execution.
- No arbitrary network traffic emitted by the AdversaryGraph API runner.
- Only predefined simulations and approved lab targets are available.

The module creates dry-run plans, expected telemetry checklists, and manual
validation records. Analysts must attach evidence from an authorized lab run
before marking detection coverage as passed.

## Local Web Telemetry Server

For web-focused simulations in Docker Compose, AdversaryGraph runs a separate
`attack-lab-web` target container and the API performs real HTTP attack flows
against `http://attack-lab-web:8080` over the compose network. The target
container uses NGINX as the front web server and a small upstream lab
application for controlled responses. `lab-web-access.log` and
`lab-web-error.log` are emitted by NGINX from the real requests received by the
container; they are not formatted by the AdversaryGraph API runner. The
in-process `127.0.0.1:8765` server remains only as a test/development fallback
when the Docker target URL is not configured.

The Docker target is configured to generate consistent telemetry for
reconnaissance, public exposure checks, path discovery,
traversal-shaped canaries, SQLi/XSS-shaped canaries, SSRF-shaped parameters,
command-injection-shaped requests, web-shell-shaped requests, upload/download
canaries, exposed secret/config/key access canaries, failed-login sequences,
brute-force login sequences, password-spray sequences, user-enumeration probes,
HTTP beacon canaries, and exfiltration-shaped POST bodies.

The runner sends only predefined requests to the approved lab target. The target
server writes logs under:

```text
<LOG_DIR>/attack-simulation/
```

At the start of every new web attack run, AdversaryGraph clears the shared target
log streams listed below. This keeps the real-time view and SIEM forwarding
focused on the current attack. Historical per-run `run-*.jsonl` files are not
deleted.

Generated files include:

- `lab-web-access.jsonl` — server-side web access telemetry with method, path,
  clean path, query keys, client IP, headers, request body length, request body
  hash, short body preview, matched canary categories, status, response bytes,
  run ID, and simulation ID.
- `lab-web-access.log` — real NGINX access log lines written by the Docker lab
  web server while it receives the attack requests. The format includes normal
  webserver fields plus correlation fields for run ID, simulation ID, request
  index, request length, request time, upstream time, and upstream status.
- `lab-web-security.log` — WAF/security-style alert lines emitted whenever a
  canary category is matched, including severity, category, rule ID, client,
  URI, run ID, simulation ID, and body hash.
- `lab-web-error.log` — real NGINX error log for the Docker lab web server.
  Most benign canary requests are valid HTTP requests and may not generate error
  lines unless NGINX or upstream handling emits an operational warning/error.
- `lab-web-auth.log` — application authentication log lines for login attacks,
  including username, user-exists flag, outcome, failure reason, attack type,
  password length/hash, source IP, status, run ID, and simulation ID. The lab
  server does not write cleartext passwords to this log.
- `run-*.jsonl` — attack-run telemetry with request sequence, response status,
  request purpose, request body length/hash, duration, response headers, byte
  counts, summary, and errors if any.

The **Real-Time Attack Logs** panel tails the real access, security, and error
logs by default. Structured JSONL sources remain available for programmatic
analysis. The **Forward Logs To SIEM** panel can POST the selected telemetry to
an HTTP(S) collector, for example a Splunk HEC, Logstash HTTP input, custom
webhook, or test receiver. The POST body is JSON:

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
- Destination can be entered as a full URL or as raw `host:port/path`; raw
  values are normalized to `http://host:port/path`.
- Connection route can be selected per send:
  - **Direct exact address** preserves the destination exactly from the API
    runtime.
  - **Docker host gateway** maps `localhost` and `127.0.0.1` to
    `host.docker.internal` for collectors running on the Docker host.
  - **Auto** uses Docker host gateway for loopback destinations when the API is
    running inside a container.
- `0.0.0.0` and `[::]` are accepted as convenience inputs even though they are
  bind addresses, not remote destinations. The forwarder maps them to
  `host.docker.internal` in Docker-host/auto mode or `127.0.0.1` in direct mode.
- For Docker host gateway mode, the collector must listen on the host network
  interface or `0.0.0.0`, not only loopback.
- Authentication modes: none, bearer token, token auth, basic
  username/password, or custom token header.
- Optional HTTP fallback can retry the same destination with `http://` when an
  `https://` collector fails with a TLS protocol error. This is intended for
  local lab collectors that expose an HTTPS-looking URL while listening over
  plain HTTP.
- Payload formats:
  - **Raw original line per request** is the recommended mode for
    Logeye/XpoLog-style `logger.jsp` collectors when you want the SIEM event
    body to be the native NGINX/auth/security log line rather than an
    AdversaryGraph JSON wrapper.
  - **JSON event per request** sends one normalized AdversaryGraph JSON event per
    POST.
  - **JSON lines** sends newline-delimited JSON events in one request.
  - **Batch envelope** sends the original AdversaryGraph wrapper object with an
    `events` array.
- Log sources:
  - **Real web access log** sends `lab-web-access.log` lines.
  - **Real WAF/security log** sends `lab-web-security.log` alert lines.
  - **Real web error log** sends `lab-web-error.log` error lines.
  - **Real auth log** sends `lab-web-auth.log` login/authentication lines.
  - **Structured web JSONL** sends `lab-web-access.jsonl`.
  - **Attack run JSONL** sends the selected `run-*.jsonl` file.
- The UI keeps the last 10 SIEM destinations in browser local storage, including
  route, payload format, source, and non-secret auth metadata. Passwords, bearer
  tokens, and custom auth token values are not saved.
- URL-embedded credentials are rejected; use the dedicated auth fields.
- Sensitive query parameters such as `api_key`, `secret`, and `password` are
  redacted in API responses and audit metadata. A Logeye-style `token`
  parameter is treated as a listener identifier and remains visible.
- Metadata/link-local/multicast/unspecified destinations are blocked.
- Only generated Attack Simulation telemetry is sent.

The Docker target is a lab fixture, not a production target. It is useful for
validating real request flow, server-side log shape, ATT&CK mapping, parser
behavior, SIEM ingestion, and detection logic before running any approved
scenario in a wider lab.

## Workflow

1. Open **Attack Simulation** from the sidebar or Discover page.
2. Select the ATT&CK TTP first.
3. The selected TTP opens a dedicated attack simulation configuration page.
4. Select an approved lab target from the target registry and review the target address context.
5. Add analyst context such as ticket, purpose, and maintenance window.
6. Generate a dry-run plan.
7. Review safety controls, expected telemetry, and approval checklist.
8. Create a controlled run record. For web simulations this starts the shared
   local telemetry server, performs the predefined benign request set for the
   selected TTP, classifies canary indicators, and writes JSONL telemetry.
9. Paste SIEM/WAF/firewall/DNS/proxy/EDR/IdP evidence into the manual result form
   when validating beyond the local lab server.
10. Mark the detection result as `passed`, `failed`, `partial`, or `not_proven`.

## Current Simulation Catalog

| Simulation | ATT&CK | Purpose |
|---|---|---|
| HTTP/TLS service fingerprint plan | `T1595` | Validate telemetry for benign local service fingerprinting |
| Public web exposure validation plan | `T1190` | Validate web visibility without exploit payloads |
| Web content discovery and path enumeration | `T1595` | Validate admin, API, backup, and repository path discovery telemetry |
| Path traversal canary validation | `T1190` | Validate traversal-shaped parser, WAF, and SIEM telemetry |
| SQL injection and XSS canary validation | `T1190` | Validate SQLi/XSS-shaped request detection without database or browser execution |
| SSRF metadata and loopback canary validation | `T1190` | Validate SSRF-shaped URL parameter detection without server-side fetches |
| Web command execution canary validation | `T1059` | Validate command-injection-shaped GET and POST telemetry without execution |
| Web shell URI and POST canary validation | `T1505.003` | Validate web-shell-shaped access telemetry without file creation |
| Ingress tool transfer upload/download canary | `T1105` | Validate upload/download-like web transfer telemetry with benign bodies |
| Web-exposed secret and backup file canary | `T1552.001` | Validate exposed `.env`, backup config, and private-key path access telemetry |
| Web failed-login sequence canary | `T1110` | Validate low-rate web login failure telemetry against lab-only endpoints |
| Web login brute-force sequence | `T1110.001` | Validate repeated-password attempts against one lab user, including final success telemetry |
| Web password spraying sequence | `T1110.003` | Validate one-password-across-many-users auth telemetry without real accounts |
| Web user enumeration sequence | `T1589.002` | Validate known/unknown username probe telemetry and enumeration alerts |
| HTTP web beacon canary | `T1071.001` | Validate web-protocol beacon-shaped telemetry with a fixed small sequence |
| Web exfiltration-shaped upload canary | `T1041` | Validate small benign POST body telemetry and exfiltration-shaped parser logic |
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
