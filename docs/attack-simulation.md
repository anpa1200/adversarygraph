# Attack Simulation

Attack Simulation prepares and records ATT&CK-aligned validation scenarios
for approved lab targets. It is designed for detection validation, telemetry
verification, and coverage-gap documentation.

The v5 workspace combines three related workflows:

- TTP-first simulation selection from an ATT&CK-style matrix.
- Real lab-target attack flows that produce target-side telemetry.
- AI-assisted kill-chain telemetry generation for SIEM rule validation,
  scenario drills, and detection engineering exercises.

Screenshots for this release are stored in
[`docs/assets/attack-simulation-v5`](assets/attack-simulation-v5/manifest.md).

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
- Each TTP family must run against the correct lab fixture type. Web TTPs use
  the web target, endpoint/internal-activity TTPs use the endpoint target, and
  SQL/FTP/identity/egress TTPs must use dedicated lab targets with their own
  native telemetry. Do not map every scenario to webserver logs.

The module creates dry-run plans, expected telemetry checklists, and manual
validation records. Analysts must attach evidence from an authorized lab run
before marking detection coverage as passed.

## Visual Walkthrough

### TTP-First Simulation Matrix

![Attack Simulation matrix](assets/attack-simulation-v5/01-attack-simulation-matrix.png)

The Attack Simulation landing page shows the ATT&CK matrix first. Techniques
with available simulations are marked as runnable cells so an analyst starts
from the behavior they want to validate, not from a generic form.

### Per-TTP Configuration

![Per-TTP configuration page](assets/attack-simulation-v5/02-ttp-configuration-page.png)

After selecting a technique, the workspace opens a dedicated configuration page.
The left panel explains the selected scenario, adversary activity, production
log sources, detection logic, discriminators, and validation gaps. The analyst
can run a lab simulation, inspect live telemetry, forward events to a SIEM, or
use the AI assistant to build a broader kill chain.

### SIEM Forwarding

![SIEM forwarding configuration](assets/attack-simulation-v5/03-siem-forwarding-configuration.png)

Forwarding supports HTTP(S) collectors, raw host/IP inputs, route selection,
payload format selection, source selection, and authentication modes. Recent
destinations are saved so repeated validation against the same collector does
not require retyping the URL. Secret values such as bearer tokens and passwords
are not stored.

### AI Scenario Library

![AI scenario library](assets/attack-simulation-v5/04-ai-scenario-library.png)

The AI Attack Assistant can work from a selected TTP, a named threat actor, or
Challenge Me mode. For repeatable work, the Scenario Library contains named
coherent kill-chain templates with preconditions, success criteria, expected
detections, and ordered phase definitions.

### Attack Chain Graph

![AI generated attack chain graph](assets/attack-simulation-v5/05-ai-generated-attack-chain-graph.png)

Generated scenarios include an attack-chain graph. Each phase shows the ATT&CK
technique, phase order, telemetry source, event format, event count, and
detection goal. This helps analysts verify that the story is a plausible
sequence rather than a random set of unrelated events.

### Explain Attack

![Explain attack panel](assets/attack-simulation-v5/06-explain-attack-panel.png)

Challenge and AI-generated scenarios expose an **Explain attack** action. The
explanation summarizes the kill chain, phase rationale, expected telemetry,
detection opportunities, and assumptions that must be validated in the SIEM.

### Real-Time Logs

![Real-time attack logs](assets/attack-simulation-v5/07-real-time-attack-logs.png)

The real-time log panel tails target-side logs. For web scenarios, this includes
the Docker lab web server access log, security/WAF-style log, error log, auth
log, structured web JSONL, endpoint fixture log, or merged attacked-server
events.

### Delivery and History

![SIEM history and delivery](assets/attack-simulation-v5/08-siem-history-and-delivery.png)

Delivery status reports how many events were posted to the configured SIEM
collector and the HTTP result. The UI keeps the last 10 non-secret destinations
for fast retesting.

## Target-Specific Lab Instances

Attack Simulation uses target-specific lab instances. This matters because a
valid detection test needs the telemetry that the real target class would
produce:

| TTP family | Lab target | Primary telemetry |
|---|---|---|
| HTTP reconnaissance, web exploitation, web auth attacks, web C2/exfil canaries | `attack-lab-web` / `lab-web-01` | NGINX access/error logs, application auth logs, WAF/security-style alerts |
| Endpoint credential access and internal host activity | `attack-lab-endpoint` / `lab-endpoint-01` | Sysmon-style process events, process-access events, Linux auditd-style file access, EDR canary records |
| SQL service attacks | dedicated SQL lab target | Database authentication logs, query audit logs, connection/source metadata |
| FTP/service transfer attacks | dedicated FTP lab target | FTP command logs, login result logs, upload/download metadata |
| Identity and SSO attacks | identity lab target | IdP sign-in logs, MFA logs, VPN/SSO events |
| Egress/C2 validation | lab agent/egress target | DNS resolver logs, proxy logs, NDR/EDR network events |

The current Docker Compose deployment includes the web and endpoint fixtures.
SQL, FTP, identity, and egress scenarios are kept as separate target classes and
remain plan-only until dedicated fixtures are deployed. They are not exposed as
executable simulations because they would otherwise create run records without
native target logs.

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
brute-force login sequences, Basic auth brute-force sequences, password-spray
sequences, user-enumeration probes, HTTP method probing, 404 discovery bursts,
scanner/tool user-agent fingerprinting, suspicious extension upload attempts,
HTTP beacon canaries, and exfiltration-shaped POST bodies.

The runner sends only predefined requests to the approved lab target. The target
server writes logs under:

```text
<LOG_DIR>/attack-simulation/
```

At the start of every new attack run, AdversaryGraph clears the shared target log
streams listed below. This keeps the real-time view and SIEM forwarding focused
on the current attack. Historical per-run `run-*.jsonl` files are not deleted.

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
- `lab-endpoint.log` — endpoint telemetry for internal host activity. Linux
  credential-file canaries are written as auditd/EDR-style file access events.
  Windows credential-dumping canaries are written as Sysmon/EDR-style process
  creation and process-access events. These records are not WAF or webserver
  logs.
- `lab-endpoint.jsonl` — structured endpoint target telemetry from the endpoint
  fixture, including run ID, simulation ID, process, command, operation, target
  process, file path, and canary classification.

Endpoint simulations currently cover credential dumping, command execution,
LOLBin/proxy execution, persistence, tool transfer, and discovery canaries. They
are sent as real HTTP requests to the endpoint lab fixture, and the fixture
writes Sysmon/auditd/EDR-style telemetry from the received activity records.
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
  - **All attacked-server events** sends a merged time-ordered stream of the
    Docker target's access, auth, endpoint, security, error, and structured web telemetry.
  - **Real web access log** sends `lab-web-access.log` lines.
  - **Endpoint EDR/Sysmon log** sends `lab-endpoint.log` lines for host-level
    activity such as Sysmon-style process creation/process access, Linux
    auditd-style file access, and EDR canary events.
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

## AI Attack Assistant

The AI Attack Assistant builds SIEM-validation telemetry stories. It does not
execute malware, exploit targets, or run arbitrary commands. The assistant sends
generated telemetry to the configured SIEM destination so detection rules,
parsers, dashboards, and correlation logic can be tested.

Assistant modes:

- **Selected TTP** — build a focused telemetry sequence around the selected
  technique.
- **Threat actor** — build a coherent actor-inspired validation scenario using
  ATT&CK techniques and telemetry sources relevant to that actor profile.
- **Challenge me** — generate a multi-phase detection challenge for analyst
  training and blind rule validation.

Planning controls:

- **LLM provider** selects Claude, OpenAI, Gemini, MiniMax, or a local
  OpenAI-compatible model when configured.
- **Complicated attack** asks the assistant for a longer, multi-source flow with
  Windows Event, Sysmon, EDR, DNS, proxy, firewall, web, and WAF-style events.
- If the selected LLM is unavailable or times out, AdversaryGraph falls back to
  deterministic scenario templates so the workflow remains repeatable. The UI
  reports whether AI planning succeeded or a deterministic fallback was used.

Event-shape rules:

- Windows Security events keep Windows Event Log structure and event IDs such as
  `4624`, `4625`, `4698`, and `1102`.
- Sysmon events keep Sysmon-style provider/channel structure and event IDs such
  as `1`, `3`, `7`, `10`, `11`, `13`, and `22`.
- EDR, proxy, DNS, firewall, WAF, and web events are sent in source/vendor
  shaped formats instead of being flattened into one generic schema.
- The attack-chain graph remains the high-level explanation; the SIEM receives
  source-shaped event bodies.

## Named AI Scenario Library

The current library contains 25 named coherent scenarios. They are designed as
plausible detection-validation stories with ordered phases, not as random event
bundles.

| Scenario | Difficulty | Main validation focus |
|---|---:|---|
| Web App to Endpoint Compromise | full intrusion | Reconnaissance, web access, endpoint execution, credential access, persistence, C2/exfiltration |
| Password Spray to Valid Account Foothold | simple chain | User enumeration, password spray, successful logon, endpoint discovery |
| SQL Injection to Data Theft | full intrusion | SQLi-shaped web telemetry, database audit style events, staging, exfiltration |
| Recon to Web Shell Persistence | full intrusion | HTTP discovery, upload/web-shell canaries, persistence-style access |
| Valid Account to LSASS Access | simple chain | Successful logon, discovery, LSASS access, credential-dumping detections |
| Password Spray to Exfiltration | full intrusion | Identity attack, valid account, staged collection, proxy upload |
| XSS Canary to Session Abuse | simple chain | XSS-shaped telemetry, session token misuse, suspicious authenticated actions |
| SSRF Metadata Probe to C2 | full intrusion | SSRF-shaped requests, metadata access canaries, follow-on beaconing |
| Ransomware Precursor Chain | full intrusion | Discovery, defense evasion, credential access, mass file change canaries |
| Living-off-the-Land Transfer and Execution | simple chain | Certutil/BITS/rundll32 style telemetry and process lineage |
| Internal Discovery After Foothold | simple chain | Host, user, network, process, and service discovery telemetry |
| Web Enumeration to Password Spray | simple chain | HTTP enumeration followed by identity/authentication failures |
| Public App Exploit to Persistence | full intrusion | Public web exposure, endpoint execution, Run key/service persistence |
| Credential Dump to Cloud Upload | full intrusion | LSASS access, archive creation, proxy/cloud upload telemetry |
| Signed Binary Proxy to C2 | simple chain | LOLBin process creation, suspicious network connection, beacon pattern |
| FIN7-Style Web, Identity, Persistence | full intrusion | Web entry, credential attack, persistence, lateral discovery signals |
| APT29-Style Identity and PowerShell | full intrusion | Identity abuse, PowerShell, discovery, C2-style telemetry |
| Lazarus-Style Delivery and Exfiltration | full intrusion | Delivery, execution, credential access, collection, exfiltration |
| Noisy Red-Team Drill | noisy drill | High-volume multi-source detections for tuning and dashboard testing |
| Stealthy Low-Volume Intrusion Chain | full intrusion | Sparse cross-source correlation and low-noise detections |
| WAF Bypass Retry Chain | simple chain | Repeated web probes with encoding/bypass variation |
| Service Account Abuse | simple chain | Service-account logon behavior, privilege use, unusual source host |
| External Recon to Credential Access | full intrusion | Public discovery, credential attack, endpoint credential-access telemetry |
| C2 Telemetry Validation | atomic chain | DNS/proxy/beacon detections and periodicity checks |
| Persistence Control Validation | atomic chain | Run key, scheduled task, service, WMI, and startup artifact events |

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
| HTTP method and override probing | `T1595` | Validate real OPTIONS, TRACE, and method-override telemetry |
| Web 404 discovery burst | `T1595` | Validate short path-discovery bursts with real 404 access logs |
| Scanner and tool user-agent fingerprinting | `T1595` | Validate scanner/tool user-agent detection from real HTTP requests |
| HTTP Basic authentication brute-force sequence | `T1110.001` | Validate Basic auth failures/success with redacted authorization telemetry |
| Suspicious web extension upload | `T1505.003` | Validate benign upload attempts to PHP/ASPX/JSP paths without persisting files |
| Linux `/etc/shadow` access canary | `T1003.008` | Validate internal process/file telemetry for shadow credential-file access without reading real files |
| LSASS and Mimikatz usage canary | `T1003.001` | Validate Mimikatz/LSASS command-line and credential-dumping telemetry without running tools or dumping memory |
| PowerShell encoded command execution | `T1059.001` | Validate encoded PowerShell process telemetry without executing PowerShell |
| Windows command shell execution | `T1059.003` | Validate cmd.exe shell execution telemetry without starting a shell |
| Certutil and BITS ingress tool transfer | `T1105` | Validate LOLBin transfer command telemetry without downloading files |
| Registry Run key persistence | `T1547.001` | Validate Run-key registry-set telemetry without registry writes |
| Scheduled task creation | `T1053.005` | Validate scheduled-task creation telemetry without creating tasks |
| Windows service creation | `T1543.003` | Validate service creation telemetry without creating services |
| Rundll32 signed binary proxy execution | `T1218.011` | Validate rundll32 proxy-execution telemetry without loading DLLs |
| Regsvr32 signed binary proxy execution | `T1218.010` | Validate regsvr32 proxy-execution telemetry without registration or network fetch |
| System information discovery | `T1082` | Validate common discovery command telemetry without executing commands |
| File and directory discovery | `T1083` | Validate file-discovery command telemetry without traversing the filesystem |
| System owner and user discovery | `T1033` | Validate user-discovery process telemetry without executing commands |
| Process discovery | `T1057` | Validate process-listing command telemetry without enumerating processes |
| System network configuration discovery | `T1016` | Validate network configuration discovery telemetry without querying interfaces |
| Remote system discovery | `T1018` | Validate domain/remote-system discovery telemetry without network enumeration |
| Software discovery | `T1518` | Validate installed-software discovery telemetry without querying installed software |
| Web failed-login sequence canary | `T1110` | Validate low-rate web login failure telemetry against lab-only endpoints |
| Web login brute-force sequence | `T1110.001` | Validate repeated-password attempts against one lab user, including final success telemetry |
| Web password spraying sequence | `T1110.003` | Validate one-password-across-many-users auth telemetry without real accounts |
| Web user enumeration sequence | `T1589.002` | Validate known/unknown username probe telemetry and enumeration alerts |
| HTTP web beacon canary | `T1071.001` | Validate web-protocol beacon-shaped telemetry with a fixed small sequence |
| Web exfiltration-shaped upload canary | `T1041` | Validate small benign POST body telemetry and exfiltration-shaped parser logic |
| External remote service reachability plan | `T1133` | Validate remote-service reachability telemetry without authentication attempts |
| Controlled HTTP/DNS beacon validation plan | `T1071` | Plan lab-agent egress telemetry validation |
| Lab-only failed-login sequence plan | `T1110` | Plan low-rate identity telemetry validation against lab-only test accounts |

## Atomic Event Pack

The atomic event pack adds single-event/artifact simulations for techniques that
can reasonably be validated from one high-signal telemetry record. These are not
real attack executions. They are detection-validation fixtures that write one
event to the endpoint telemetry target.

Windows-based atomic events are emitted as strict Windows Event Log shaped JSON:
`Event.System.Provider`, `Event.System.EventID`, `Event.System.Channel`,
`Event.System.Computer`, `Event.System.Security`, `Event.EventData.Data[]`, and
`event.original` XML are present. Sysmon records use the
`Microsoft-Windows-Sysmon/Operational` channel and Sysmon-style `EventData`
field names such as `Image`, `CommandLine`, `ParentImage`, `TargetFilename`,
`TargetObject`, `SourceImage`, and `TargetImage`. Windows Security records use
native field names such as `TargetUserName`, `LogonType`, `IpAddress`,
`ShareName`, and `ObjectName`.

Non-Windows atomic events, such as proxy, email gateway, firewall, cloud-like,
or generic EDR artifacts, are emitted as structured vendor JSON with observer,
event, host, process, source, destination, URL, rule, and AdversaryGraph
correlation fields.

Use these when the rule trigger is event/artifact based, for example Sysmon
ProcessCreate, Windows Security logon, PowerShell 4104, Defender configuration
change, proxy upload, email gateway delivery, or EDR API/file events.

Current atomic pack: 55 simulations. Validation status: 55/55 create endpoint
events, 41/55 are strict Windows Event Log shaped records, and 14/55 are
non-Windows vendor JSON records.

| ATT&CK | Simulation | Atomic event |
|---|---|---|
| `T1027` | `sim-t1027-atomic-encoded-powershell-scriptblock` | windows_powershell `4104` ScriptBlockLogging |
| `T1036` | `sim-t1036-atomic-masqueraded-svchost-user-path` | sysmon `1` ProcessCreate |
| `T1047` | `sim-t1047-atomic-wmic-process-call-create` | sysmon `1` ProcessCreate |
| `T1048` | `sim-t1048-atomic-exfiltration-over-alternative-protocol` | firewall `NETFLOW` OutboundTransfer |
| `T1049` | `sim-t1049-atomic-netstat-network-connections` | sysmon `1` ProcessCreate |
| `T1055` | `sim-t1055-atomic-remote-thread-injection` | sysmon `8` CreateRemoteThread |
| `T1056.001` | `sim-t1056-001-atomic-keylogger-driver-or-hook` | edr `INPUT_CAPTURE` KeyboardHookRegistered |
| `T1059.005` | `sim-t1059-005-atomic-visual-basic-script-execution` | sysmon `1` ProcessCreate |
| `T1059.006` | `sim-t1059-006-atomic-python-execution` | sysmon `1` ProcessCreate |
| `T1068` | `sim-t1068-atomic-privilege-escalation-exploit-child-shell` | edr `PRIV_ESC` ExploitPrivilegeEscalation |
| `T1070.001` | `sim-t1070-001-atomic-windows-event-log-cleared` | windows_security `1102` AuditLogCleared |
| `T1070.004` | `sim-t1070-004-atomic-suspicious-file-delete` | sysmon `23` FileDelete |
| `T1078` | `sim-t1078-atomic-valid-account-remote-logon` | windows_security `4624` SuccessfulLogon |
| `T1090` | `sim-t1090-atomic-proxy-tool-network-connection` | sysmon `3` NetworkConnection |
| `T1098` | `sim-t1098-atomic-account-added-to-admin-group` | windows_security `4728` MemberAddedToSecurityEnabledGlobalGroup |
| `T1102` | `sim-t1102-atomic-web-service-c2-user-agent` | proxy `HTTP_REQUEST` ProxyWebRequest |
| `T1106` | `sim-t1106-atomic-suspicious-native-api-call` | edr `API_CALL` NativeApiCall |
| `T1112` | `sim-t1112-atomic-registry-security-setting-modified` | sysmon `13` RegistryValueSet |
| `T1113` | `sim-t1113-atomic-screen-capture-api` | edr `SCREEN_CAPTURE` ScreenCapture |
| `T1115` | `sim-t1115-atomic-clipboard-read` | edr `CLIPBOARD_READ` ClipboardAccess |
| `T1123` | `sim-t1123-atomic-audio-capture-api` | edr `AUDIO_CAPTURE` MicrophoneAccess |
| `T1125` | `sim-t1125-atomic-video-capture-api` | edr `VIDEO_CAPTURE` CameraAccess |
| `T1134` | `sim-t1134-atomic-token-impersonation` | edr `TOKEN_IMPERSONATION` TokenImpersonation |
| `T1135` | `sim-t1135-atomic-network-share-discovery` | sysmon `1` ProcessCreate |
| `T1140` | `sim-t1140-atomic-certutil-decode` | sysmon `1` ProcessCreate |
| `T1203` | `sim-t1203-atomic-office-spawned-script-host` | sysmon `1` ProcessCreate |
| `T1204.002` | `sim-t1204-002-atomic-user-executed-downloaded-file` | sysmon `1` ProcessCreate |
| `T1219` | `sim-t1219-atomic-remote-access-software-started` | sysmon `1` ProcessCreate |
| `T1222.001` | `sim-t1222-001-atomic-icacls-permission-change` | sysmon `1` ProcessCreate |
| `T1482` | `sim-t1482-atomic-domain-trust-discovery` | sysmon `1` ProcessCreate |
| `T1486` | `sim-t1486-atomic-ransomware-file-rename` | edr `RANSOMWARE_CANARY` MassFileRename |
| `T1490` | `sim-t1490-atomic-shadow-copy-deletion` | sysmon `1` ProcessCreate |
| `T1497` | `sim-t1497-atomic-sandbox-evasion-check` | sysmon `1` ProcessCreate |
| `T1518.001` | `sim-t1518-001-atomic-security-software-discovery` | sysmon `1` ProcessCreate |
| `T1539` | `sim-t1539-atomic-browser-cookie-access` | sysmon `11` FileCreate |
| `T1546.003` | `sim-t1546-003-atomic-wmi-event-subscription` | sysmon `19` WmiEventFilter |
| `T1546.008` | `sim-t1546-008-atomic-accessibility-feature-backdoor` | sysmon `13` RegistryValueSet |
| `T1547.009` | `sim-t1547-009-atomic-shortcut-modification` | sysmon `11` FileCreate |
| `T1550.002` | `sim-t1550-002-atomic-pass-the-hash-logon` | windows_security `4624` SuccessfulLogon |
| `T1552.002` | `sim-t1552-002-atomic-credentials-in-registry` | sysmon `1` ProcessCreate |
| `T1552.006` | `sim-t1552-006-atomic-cloud-credential-file-access` | edr `FILE_READ` SensitiveFileAccess |
| `T1555.003` | `sim-t1555-003-atomic-browser-login-data-access` | sysmon `11` FileCreate |
| `T1556.002` | `sim-t1556-002-atomic-password-filter-dll-registered` | sysmon `13` RegistryValueSet |
| `T1560.001` | `sim-t1560-001-atomic-archive-with-rar` | sysmon `1` ProcessCreate |
| `T1562.001` | `sim-t1562-001-atomic-disable-defender-realtime` | windows_defender `5007` ConfigurationChanged |
| `T1562.004` | `sim-t1562-004-atomic-disable-windows-firewall` | sysmon `1` ProcessCreate |
| `T1564.001` | `sim-t1564-001-atomic-hidden-file-attribute` | sysmon `1` ProcessCreate |
| `T1566.001` | `sim-t1566-001-atomic-email-attachment-delivery` | email_gateway `MESSAGE_DELIVERED` EmailDelivered |
| `T1567.002` | `sim-t1567-002-atomic-exfil-to-cloud-storage` | proxy `HTTP_UPLOAD` LargeUpload |
| `T1569.002` | `sim-t1569-002-atomic-service-execution` | windows_system `7045` ServiceInstalled |
| `T1574.002` | `sim-t1574-002-atomic-dll-side-loading` | sysmon `7` ImageLoaded |
| `T1574.011` | `sim-t1574-011-atomic-services-registry-permissions-weakness` | sysmon `13` RegistryValueSet |
| `T1021.001` | `sim-t1021-001-atomic-rdp-network-logon` | windows_security `4624` SuccessfulLogon |
| `T1021.002` | `sim-t1021-002-atomic-smb-admin-share-access` | windows_security `5140` NetworkShareAccess |
| `T1039` | `sim-t1039-atomic-network-share-data-access` | windows_security `4663` ObjectAccess |

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
