# Attack Simulation TTP Descriptions for LLM Analysis

Source: live AdversaryGraph Attack Simulation catalog at `http://localhost:3000/api/simulation/catalog`.

Purpose: structured context for LLM review of each attack simulation scenario, expected telemetry, event structure, and detection focus.

Total simulations: 96
Unique ATT&CK techniques: 85

---

## [T1003.001](http://localhost:3000/navigator?technique=T1003.001) - LSASS and Mimikatz usage canary

**Simulation ID:** `sim-t1003-lsass-mimikatz-canary`
**Risk:** 2

Generate lab-only process telemetry for Mimikatz/LSASS dumping patterns without running tools or touching memory.

**Tags / Target Types**

- `credential-dumping-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST fixed process telemetry canaries to the lab target. The attacked server records command-line-shaped telemetry but never executes Mimikatz, rundll32, or ProcDump.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- process command line
- lsass.exe target
- mimikatz indicator
- credential_dumping alert
- run correlation ID

**Safety Controls**

- canary event only
- no Mimikatz execution
- no memory dump
- no credential access
- local lab server only

---

## [T1003.008](http://localhost:3000/navigator?technique=T1003.008) - Linux /etc/shadow access canary

**Simulation ID:** `sim-t1003-shadow-file-access`
**Risk:** 2

Generate lab-only internal activity telemetry for attempted Linux shadow credential-file access without reading any real files.

**Tags / Target Types**

- `credential-dumping-canary`
- `endpoint`
- `linux-endpoint`

**What Happens**

POST fixed internal-activity canaries to the lab target. The attacked server records process/file telemetry but does not read or copy /etc/shadow.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- process/file access event
- /etc/shadow path
- read/copy operation
- credential_file_access alert
- run correlation ID

**Safety Controls**

- canary event only
- no real file read
- no host /etc/shadow access
- local lab server only
- fixed payloads

---

## [T1016](http://localhost:3000/navigator?technique=T1016) - System network configuration discovery

**Simulation ID:** `sim-t1016-network-config-discovery`
**Risk:** 1

Generate network-configuration discovery telemetry without querying host networking.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST ipconfig and netsh discovery canaries. Record process telemetry with network-configuration indicators.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- ipconfig.exe
- netsh.exe
- interface discovery
- network_config_discovery alert

**Safety Controls**

- no network configuration query
- endpoint telemetry fixture only
- fixed discovery commands

---

## [T1018](http://localhost:3000/navigator?technique=T1018) - Remote system discovery

**Simulation ID:** `sim-t1018-remote-system-discovery`
**Risk:** 1

Generate remote-system discovery telemetry without querying a domain or network.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST net view and nltest discovery canaries. Record process telemetry with remote-system discovery indicators.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- net view
- nltest dclist
- domain discovery
- remote_system_discovery alert

**Safety Controls**

- no domain query
- no network enumeration
- endpoint telemetry fixture only

---

## [T1021.001](http://localhost:3000/navigator?technique=T1021.001) - Atomic event: Remote Desktop Protocol logon

**Simulation ID:** `sim-t1021-001-atomic-rdp-network-logon`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1021.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 4624 (SuccessfulLogon). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=4624
- event_name=SuccessfulLogon
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1021.002](http://localhost:3000/navigator?technique=T1021.002) - Atomic event: SMB admin share access

**Simulation ID:** `sim-t1021-002-atomic-smb-admin-share-access`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1021.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 5140 (NetworkShareAccess). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=5140
- event_name=NetworkShareAccess
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1027](http://localhost:3000/navigator?technique=T1027) - Atomic event: Obfuscated PowerShell script block

**Simulation ID:** `sim-t1027-atomic-encoded-powershell-scriptblock`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1027. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_powershell telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 4104 (ScriptBlockLogging). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_powershell event
- event_id=4104
- event_name=ScriptBlockLogging
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1033](http://localhost:3000/navigator?technique=T1033) - System owner and user discovery

**Simulation ID:** `sim-t1033-user-discovery`
**Risk:** 1

Generate user-discovery process telemetry without running commands.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST user-discovery process canaries to the endpoint target. Record Sysmon-style process telemetry with user-discovery command lines.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- whoami.exe
- username environment lookup
- process creation
- user_discovery alert

**Safety Controls**

- no command execution
- endpoint telemetry fixture only
- fixed discovery commands

---

## [T1036](http://localhost:3000/navigator?technique=T1036) - Atomic event: Masqueraded system process from user-writable path

**Simulation ID:** `sim-t1036-atomic-masqueraded-svchost-user-path`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1036. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1039](http://localhost:3000/navigator?technique=T1039) - Atomic event: Data from network shared drive

**Simulation ID:** `sim-t1039-atomic-network-share-data-access`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1039. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 4663 (ObjectAccess). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=4663
- event_name=ObjectAccess
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1041](http://localhost:3000/navigator?technique=T1041) - Web exfiltration-shaped upload canary

**Simulation ID:** `sim-t1041-web-exfil-canary`
**Risk:** 2

Generate small benign exfiltration-shaped uploads to validate outbound/body telemetry parsing.

**Tags / Target Types**

- `exfiltration-canary`
- `http`
- `https`
- `web`

**What Happens**

POST small benign JSON and text bodies to lab collection endpoints. Record body metadata without storing sensitive content.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- POST body length
- multi-line body
- export endpoint
- canary classification

**Safety Controls**

- small benign payload
- no sensitive data
- local telemetry server only
- no external destination

---

## [T1047](http://localhost:3000/navigator?technique=T1047) - Atomic event: WMI process creation

**Simulation ID:** `sim-t1047-atomic-wmic-process-call-create`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1047. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1048](http://localhost:3000/navigator?technique=T1048) - Atomic event: Exfiltration over alternative protocol

**Simulation ID:** `sim-t1048-atomic-exfiltration-over-alternative-protocol`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1048. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

firewall telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured firewall JSON with code NETFLOW (OutboundTransfer). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- firewall event
- event_id=NETFLOW
- event_name=OutboundTransfer
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1049](http://localhost:3000/navigator?technique=T1049) - Atomic event: System network connection discovery

**Simulation ID:** `sim-t1049-atomic-netstat-network-connections`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1049. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1053.005](http://localhost:3000/navigator?technique=T1053.005) - Scheduled task creation

**Simulation ID:** `sim-t1053-scheduled-task`
**Risk:** 2

Generate scheduled-task creation telemetry without creating a task.

**Tags / Target Types**

- `persistence-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST schtasks and PowerShell scheduled-task canaries. Record process telemetry for task creation patterns.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- schtasks.exe
- Register-ScheduledTask
- task name
- process creation
- scheduled_task alert

**Safety Controls**

- no task creation
- endpoint telemetry fixture only
- fixed task name

---

## [T1055](http://localhost:3000/navigator?technique=T1055) - Atomic event: Remote thread creation into another process

**Simulation ID:** `sim-t1055-atomic-remote-thread-injection`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1055. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 8 (CreateRemoteThread). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=8
- event_name=CreateRemoteThread
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1056.001](http://localhost:3000/navigator?technique=T1056.001) - Atomic event: Keylogging hook artifact

**Simulation ID:** `sim-t1056-001-atomic-keylogger-driver-or-hook`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1056.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code INPUT_CAPTURE (KeyboardHookRegistered). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=INPUT_CAPTURE
- event_name=KeyboardHookRegistered
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1057](http://localhost:3000/navigator?technique=T1057) - Process discovery

**Simulation ID:** `sim-t1057-process-discovery`
**Risk:** 1

Generate process-discovery telemetry without listing real processes.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST tasklist and PowerShell process-discovery canaries. Record process telemetry without enumerating the host.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- tasklist.exe
- Get-Process
- process creation
- process_discovery alert

**Safety Controls**

- no process enumeration
- endpoint telemetry fixture only
- fixed discovery commands

---

## [T1059](http://localhost:3000/navigator?technique=T1059) - Web command execution canary validation

**Simulation ID:** `sim-t1059-web-command-canary`
**Risk:** 1

Generate command-injection-shaped canary requests without command execution.

**Tags / Target Types**

- `execution-canary`
- `http`
- `https`
- `web`

**What Happens**

Send command-shaped parameters and JSON fields to lab endpoints. Record request body length, hash, and preview.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- cmd parameter
- JSON command field
- body hash
- canary classification

**Safety Controls**

- commands are never executed
- local telemetry server only
- fixed canary values

---

## [T1059.001](http://localhost:3000/navigator?technique=T1059.001) - PowerShell encoded command execution

**Simulation ID:** `sim-t1059-powershell-encoded-command`
**Risk:** 2

Generate endpoint process telemetry for encoded PowerShell execution patterns without running commands.

**Tags / Target Types**

- `execution-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST fixed PowerShell process-create canaries to the endpoint lab target. The endpoint fixture records Sysmon-style process events only.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- Sysmon process creation
- powershell.exe or pwsh.exe
- EncodedCommand flag
- hidden/no-profile flags
- run correlation ID

**Safety Controls**

- endpoint telemetry fixture only
- no command execution
- fixed command-line canaries
- no external target

---

## [T1059.003](http://localhost:3000/navigator?technique=T1059.003) - Windows command shell execution

**Simulation ID:** `sim-t1059-cmd-shell-execution`
**Risk:** 1

Generate endpoint process telemetry for cmd.exe shell execution patterns without running commands.

**Tags / Target Types**

- `execution-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST cmd.exe process-create canaries to the endpoint lab target. Record command-line-shaped telemetry without creating a shell.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- Sysmon process creation
- cmd.exe
- /c command flag
- discovery command string
- run correlation ID

**Safety Controls**

- endpoint telemetry fixture only
- no shell execution
- fixed command-line canaries

---

## [T1059.005](http://localhost:3000/navigator?technique=T1059.005) - Atomic event: Visual Basic script execution

**Simulation ID:** `sim-t1059-005-atomic-visual-basic-script-execution`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1059.005. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1059.006](http://localhost:3000/navigator?technique=T1059.006) - Atomic event: Python script execution

**Simulation ID:** `sim-t1059-006-atomic-python-execution`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1059.006. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1068](http://localhost:3000/navigator?technique=T1068) - Atomic event: Privileged service spawned shell after exploit-like event

**Simulation ID:** `sim-t1068-atomic-privilege-escalation-exploit-child-shell`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1068. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code PRIV_ESC (ExploitPrivilegeEscalation). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=PRIV_ESC
- event_name=ExploitPrivilegeEscalation
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1070.001](http://localhost:3000/navigator?technique=T1070.001) - Atomic event: Windows event log cleared

**Simulation ID:** `sim-t1070-001-atomic-windows-event-log-cleared`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1070.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1102 (AuditLogCleared). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=1102
- event_name=AuditLogCleared
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1070.004](http://localhost:3000/navigator?technique=T1070.004) - Atomic event: Suspicious file deletion

**Simulation ID:** `sim-t1070-004-atomic-suspicious-file-delete`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1070.004. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 23 (FileDelete). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=23
- event_name=FileDelete
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1071](http://localhost:3000/navigator?technique=T1071) - Controlled HTTP/DNS beacon validation plan

**Simulation ID:** `sim-t1071-controlled-beacon`
**Risk:** 2

Plan a controlled beacon from a lab agent to a controlled endpoint.

**Tags / Target Types**

- `c2-emulation`
- `lab-agent`
- `egress`

**What Happens**

Confirm the target is a lab agent, not a production host. Prepare a fixed benign HTTP or DNS callback to a controlled domain.

**Telemetry Source**

Approved lab target telemetry from the selected simulation target.

**System / Event Structure**

The simulation records a plan and expected evidence fields for the target telemetry owner.

**Detection Focus**

- DNS resolver log
- proxy log
- NDR metadata
- EDR network event

**Safety Controls**

- lab agent only
- controlled endpoint only
- no malware
- fixed interval cap

---

## [T1071.001](http://localhost:3000/navigator?technique=T1071.001) - HTTP web beacon canary

**Simulation ID:** `sim-t1071-web-beacon`
**Risk:** 2

Generate benign periodic HTTP beacon-shaped telemetry to the local lab server.

**Tags / Target Types**

- `c2-emulation`
- `http`
- `https`
- `web`

**What Happens**

Send a short fixed sequence of beacon-shaped GET and POST requests. Record sequence values and timing.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- periodic paths
- sequence parameter
- POST telemetry body
- canary classification

**Safety Controls**

- local telemetry server only
- fixed small sequence
- no external C2
- no malware

---

## [T1078](http://localhost:3000/navigator?technique=T1078) - Atomic event: Valid account remote interactive logon

**Simulation ID:** `sim-t1078-atomic-valid-account-remote-logon`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1078. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 4624 (SuccessfulLogon). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=4624
- event_name=SuccessfulLogon
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1082](http://localhost:3000/navigator?technique=T1082) - System information discovery

**Simulation ID:** `sim-t1082-system-discovery`
**Risk:** 1

Generate process telemetry for common system discovery commands without executing them.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST systeminfo, whoami, and ipconfig process canaries. Record endpoint process telemetry for discovery command sequence detection.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- systeminfo.exe
- whoami.exe
- ipconfig.exe
- process creation
- discovery command sequence

**Safety Controls**

- no command execution
- endpoint telemetry fixture only
- fixed discovery commands

---

## [T1083](http://localhost:3000/navigator?technique=T1083) - File and directory discovery

**Simulation ID:** `sim-t1083-file-discovery`
**Risk:** 1

Generate file-discovery telemetry without traversing the filesystem.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST cmd and PowerShell file-discovery canaries. Record file-discovery shaped telemetry without touching real files.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- cmd dir
- PowerShell Get-ChildItem
- target path
- file_discovery alert
- run correlation ID

**Safety Controls**

- no filesystem traversal
- endpoint telemetry fixture only
- fixed public path

---

## [T1090](http://localhost:3000/navigator?technique=T1090) - Atomic event: Proxy tool network connection

**Simulation ID:** `sim-t1090-atomic-proxy-tool-network-connection`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1090. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 3 (NetworkConnection). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=3
- event_name=NetworkConnection
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1098](http://localhost:3000/navigator?technique=T1098) - Atomic event: Account added to privileged group

**Simulation ID:** `sim-t1098-atomic-account-added-to-admin-group`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1098. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 4728 (MemberAddedToSecurityEnabledGlobalGroup). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=4728
- event_name=MemberAddedToSecurityEnabledGlobalGroup
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1102](http://localhost:3000/navigator?technique=T1102) - Atomic event: Web service used as C2 channel

**Simulation ID:** `sim-t1102-atomic-web-service-c2-user-agent`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1102. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

proxy telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured proxy JSON with code HTTP_REQUEST (ProxyWebRequest). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- proxy event
- event_id=HTTP_REQUEST
- event_name=ProxyWebRequest
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1105](http://localhost:3000/navigator?technique=T1105) - Certutil and BITS ingress tool transfer

**Simulation ID:** `sim-t1105-certutil-transfer`
**Risk:** 2

Generate endpoint process telemetry for LOLBin-based tool transfer commands without downloading files.

**Tags / Target Types**

- `transfer-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST certutil and BITS command-line canaries to the endpoint target. Record process creation telemetry with URL and destination path indicators.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- certutil.exe
- bitsadmin.exe
- URL in command line
- destination path
- process creation

**Safety Controls**

- no network download
- no file write
- endpoint telemetry fixture only
- fixed canaries

---

## [T1105](http://localhost:3000/navigator?technique=T1105) - Ingress tool transfer upload/download canary

**Simulation ID:** `sim-t1105-web-upload-download`
**Risk:** 1

Generate benign upload/download telemetry for tool-transfer detection validation.

**Tags / Target Types**

- `transfer-canary`
- `http`
- `https`
- `web`

**What Happens**

Request a fixed benign download path. POST a small benign canary body to an upload endpoint.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- download path
- upload endpoint
- body length
- user-agent
- canary classification

**Safety Controls**

- no executable content
- small benign body
- local telemetry server only

---

## [T1106](http://localhost:3000/navigator?technique=T1106) - Atomic event: Suspicious Native API sequence

**Simulation ID:** `sim-t1106-atomic-suspicious-native-api-call`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1106. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code API_CALL (NativeApiCall). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=API_CALL
- event_name=NativeApiCall
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1110](http://localhost:3000/navigator?technique=T1110) - Lab-only failed-login sequence plan

**Simulation ID:** `sim-t1110-lab-login-sequence`
**Risk:** 2

Plan low-rate failed logins against a lab-only identity target and test account.

**Tags / Target Types**

- `credential-access`
- `identity-lab`
- `sso-lab`

**What Happens**

Confirm the identity target is lab-only and uses a test account. Prepare a low-rate failed-login sequence.

**Telemetry Source**

Approved lab target telemetry from the selected simulation target.

**System / Event Structure**

The simulation records a plan and expected evidence fields for the target telemetry owner.

**Detection Focus**

- IdP sign-in log
- MFA log
- VPN/SSO log
- SIEM identity alert

**Safety Controls**

- lab-only target
- test account only
- low rate
- no real users
- explicit approval

---

## [T1110](http://localhost:3000/navigator?technique=T1110) - Web failed-login sequence canary

**Simulation ID:** `sim-t1110-web-login-failures`
**Risk:** 2

Generate low-rate failed-login-shaped telemetry against the lab web server only.

**Tags / Target Types**

- `credential-access`
- `http`
- `https`
- `web`

**What Happens**

Send three fixed failed-login canaries to the local lab login endpoint. Record body hash and username-like fields without authenticating.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- login endpoint
- username field
- failed status
- low-rate sequence
- canary classification

**Safety Controls**

- lab server only
- no real accounts
- fixed low rate
- no brute force

---

## [T1110.001](http://localhost:3000/navigator?technique=T1110.001) - HTTP Basic authentication brute-force sequence

**Simulation ID:** `sim-t1110-basic-auth-bruteforce`
**Risk:** 2

Perform a fixed lab-only Basic auth sequence against the attacked web server and record auth/access/security telemetry.

**Tags / Target Types**

- `credential-attack`
- `http`
- `https`
- `web`

**What Happens**

Send two failed Basic auth requests for the lab admin user. Send one known-good lab Basic auth request for success telemetry.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- Authorization header present
- 401 failures
- final 200 success
- basic_auth_bruteforce alert
- auth log password hash

**Safety Controls**

- lab credentials only
- three requests only
- authorization header redacted in stored telemetry
- no external target

---

## [T1110.001](http://localhost:3000/navigator?technique=T1110.001) - Web login brute-force sequence

**Simulation ID:** `sim-t1110-web-bruteforce`
**Risk:** 2

Generate a fixed lab-only brute-force sequence against the built-in auth endpoint.

**Tags / Target Types**

- `credential-attack`
- `http`
- `https`
- `web`

**What Happens**

Send a fixed sequence of failed passwords for the admin lab account. Send one final known-good lab password to prove successful-auth telemetry.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- auth log failures
- auth log final success
- same username repeated
- WAF/security brute_force alerts

**Safety Controls**

- lab server only
- fixed test account
- four requests only
- no real credentials
- no external target

---

## [T1110.003](http://localhost:3000/navigator?technique=T1110.003) - Web password spraying sequence

**Simulation ID:** `sim-t1110-web-password-spray`
**Risk:** 2

Generate a fixed password-spray pattern across lab-only users using one incorrect password.

**Tags / Target Types**

- `credential-attack`
- `http`
- `https`
- `web`

**What Happens**

POST the same incorrect password across a fixed list of lab users. Record user existence, outcome, failure reason, and source IP without logging the cleartext password.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- auth log failures
- one password across many users
- password_spray security alerts
- source IP correlation

**Safety Controls**

- lab server only
- fixed test users
- one benign password
- four requests only
- no lockout logic

---

## [T1112](http://localhost:3000/navigator?technique=T1112) - Atomic event: Security-sensitive registry modification

**Simulation ID:** `sim-t1112-atomic-registry-security-setting-modified`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1112. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 13 (RegistryValueSet). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=13
- event_name=RegistryValueSet
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1113](http://localhost:3000/navigator?technique=T1113) - Atomic event: Screen capture API use

**Simulation ID:** `sim-t1113-atomic-screen-capture-api`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1113. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code SCREEN_CAPTURE (ScreenCapture). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=SCREEN_CAPTURE
- event_name=ScreenCapture
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1115](http://localhost:3000/navigator?technique=T1115) - Atomic event: Clipboard data access

**Simulation ID:** `sim-t1115-atomic-clipboard-read`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1115. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code CLIPBOARD_READ (ClipboardAccess). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=CLIPBOARD_READ
- event_name=ClipboardAccess
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1123](http://localhost:3000/navigator?technique=T1123) - Atomic event: Audio capture API use

**Simulation ID:** `sim-t1123-atomic-audio-capture-api`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1123. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code AUDIO_CAPTURE (MicrophoneAccess). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=AUDIO_CAPTURE
- event_name=MicrophoneAccess
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1125](http://localhost:3000/navigator?technique=T1125) - Atomic event: Video capture API use

**Simulation ID:** `sim-t1125-atomic-video-capture-api`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1125. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code VIDEO_CAPTURE (CameraAccess). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=VIDEO_CAPTURE
- event_name=CameraAccess
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1133](http://localhost:3000/navigator?technique=T1133) - External remote service reachability plan

**Simulation ID:** `sim-t1133-remote-service-reachability`
**Risk:** 1

Validate telemetry for approved remote-service reachability checks.

**Tags / Target Types**

- `remote-access`
- `vpn`
- `ssh`
- `rdp`
- `remote-service`

**What Happens**

Confirm service and port are approved for reachability validation. Prepare one low-rate connection attempt without credentials.

**Telemetry Source**

Approved lab target telemetry from the selected simulation target.

**System / Event Structure**

The simulation records a plan and expected evidence fields for the target telemetry owner.

**Detection Focus**

- firewall deny/allow
- VPN gateway log
- remote access service log

**Safety Controls**

- no authentication attempts
- no brute force
- target allowlist
- single connection intent

---

## [T1134](http://localhost:3000/navigator?technique=T1134) - Atomic event: Access token impersonation

**Simulation ID:** `sim-t1134-atomic-token-impersonation`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1134. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code TOKEN_IMPERSONATION (TokenImpersonation). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=TOKEN_IMPERSONATION
- event_name=TokenImpersonation
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1135](http://localhost:3000/navigator?technique=T1135) - Atomic event: Network share discovery

**Simulation ID:** `sim-t1135-atomic-network-share-discovery`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1135. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1140](http://localhost:3000/navigator?technique=T1140) - Atomic event: File deobfuscation with certutil decode

**Simulation ID:** `sim-t1140-atomic-certutil-decode`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1140. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1190](http://localhost:3000/navigator?technique=T1190) - Path traversal canary validation

**Simulation ID:** `sim-t1190-traversal-canary`
**Risk:** 1

Send harmless path-traversal-shaped canary requests to validate parser and WAF telemetry.

**Tags / Target Types**

- `web-exploit-canary`
- `http`
- `https`
- `web`

**What Happens**

Send fixed traversal-looking requests containing explicit ag_canary markers. Do not read files or resolve paths on the server.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- query string
- encoded traversal sequence
- canary tag
- HTTP 404/200 status

**Safety Controls**

- canary strings only
- local telemetry server only
- no filesystem access
- no exploit execution

---

## [T1190](http://localhost:3000/navigator?technique=T1190) - Public web exposure validation plan

**Simulation ID:** `sim-t1190-web-exposure`
**Risk:** 1

Validate visibility for benign public-facing web exposure checks without exploit payloads.

**Tags / Target Types**

- `initial-access-surface`
- `http`
- `https`
- `web`

**What Happens**

Review target technology and allowed URL paths. Start the local telemetry web server on 127.0.0.1.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- lab web access log
- application access log
- request headers
- path and status

**Safety Controls**

- no exploit payload
- no fuzzing
- local telemetry server only
- single request set

---

## [T1190](http://localhost:3000/navigator?technique=T1190) - SQL injection and XSS canary validation

**Simulation ID:** `sim-t1190-sqli-xss-canary`
**Risk:** 1

Generate SQLi/XSS-shaped canary requests without database, browser, or script execution.

**Tags / Target Types**

- `web-exploit-canary`
- `http`
- `https`
- `web`

**What Happens**

Send one SQLi-shaped query and one XSS-shaped query to benign lab endpoints. Classify canary indicators in web telemetry.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- sqli-shaped query
- xss-shaped query
- URL encoding
- canary classification

**Safety Controls**

- local telemetry server only
- no database
- no script execution
- fixed canaries

---

## [T1190](http://localhost:3000/navigator?technique=T1190) - SSRF metadata and loopback canary validation

**Simulation ID:** `sim-t1190-ssrf-canary`
**Risk:** 1

Generate SSRF-shaped URL parameters without making server-side outbound requests.

**Tags / Target Types**

- `web-exploit-canary`
- `http`
- `https`
- `web`

**What Happens**

Send fixed SSRF-looking URL parameters to local lab endpoints. The server records the parameter but never fetches it.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- metadata URL parameter
- loopback URL parameter
- query keys
- canary classification

**Safety Controls**

- no server-side fetch
- local telemetry server only
- fixed URL parameters
- metadata not contacted

---

## [T1203](http://localhost:3000/navigator?technique=T1203) - Atomic event: Exploitation for client execution artifact

**Simulation ID:** `sim-t1203-atomic-office-spawned-script-host`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1203. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1204.002](http://localhost:3000/navigator?technique=T1204.002) - Atomic event: User execution of downloaded file

**Simulation ID:** `sim-t1204-002-atomic-user-executed-downloaded-file`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1204.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1218.010](http://localhost:3000/navigator?technique=T1218.010) - Regsvr32 signed binary proxy execution

**Simulation ID:** `sim-t1218-regsvr32-proxy`
**Risk:** 2

Generate regsvr32 proxy-execution telemetry without registering DLLs or fetching scriptlets.

**Tags / Target Types**

- `defense-evasion-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST regsvr32 scriptlet and DLL-registration canaries. Record process creation telemetry with proxy-execution indicators.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- regsvr32.exe
- scrobj.dll
- scriptlet URL
- process creation
- proxy execution alert

**Safety Controls**

- no DLL registration
- no network fetch
- endpoint telemetry fixture only

---

## [T1218.011](http://localhost:3000/navigator?technique=T1218.011) - Rundll32 signed binary proxy execution

**Simulation ID:** `sim-t1218-rundll32-proxy`
**Risk:** 2

Generate rundll32 proxy-execution telemetry without loading DLLs or scripts.

**Tags / Target Types**

- `defense-evasion-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST rundll32 command-line canaries to the endpoint target. Record process creation telemetry only.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- rundll32.exe
- suspicious command line
- DLL/function launch
- process creation

**Safety Controls**

- no DLL load
- no script execution
- endpoint telemetry fixture only

---

## [T1219](http://localhost:3000/navigator?technique=T1219) - Atomic event: Remote access software execution

**Simulation ID:** `sim-t1219-atomic-remote-access-software-started`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1219. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1222.001](http://localhost:3000/navigator?technique=T1222.001) - Atomic event: Windows file permission modification

**Simulation ID:** `sim-t1222-001-atomic-icacls-permission-change`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1222.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1482](http://localhost:3000/navigator?technique=T1482) - Atomic event: Domain trust discovery

**Simulation ID:** `sim-t1482-atomic-domain-trust-discovery`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1482. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1486](http://localhost:3000/navigator?technique=T1486) - Atomic event: Ransomware-like file encryption artifact

**Simulation ID:** `sim-t1486-atomic-ransomware-file-rename`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1486. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code RANSOMWARE_CANARY (MassFileRename). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=RANSOMWARE_CANARY
- event_name=MassFileRename
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1490](http://localhost:3000/navigator?technique=T1490) - Atomic event: Inhibit system recovery command

**Simulation ID:** `sim-t1490-atomic-shadow-copy-deletion`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1490. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1497](http://localhost:3000/navigator?technique=T1497) - Atomic event: Virtualization and sandbox evasion check

**Simulation ID:** `sim-t1497-atomic-sandbox-evasion-check`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1497. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1505.003](http://localhost:3000/navigator?technique=T1505.003) - Suspicious web extension upload

**Simulation ID:** `sim-t1505-suspicious-extension-upload`
**Risk:** 1

POST benign upload bodies to suspicious web extension paths so the attacked server emits real upload telemetry.

**Tags / Target Types**

- `persistence-canary`
- `http`
- `https`
- `web`

**What Happens**

POST benign bodies to PHP, ASPX, and JSP upload paths. Record real access log lines and structured body metadata.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- POST upload paths
- php/aspx/jsp extension
- body length/hash
- suspicious_upload alert

**Safety Controls**

- benign payload text only
- no file is persisted
- lab server only
- fixed extension list

---

## [T1505.003](http://localhost:3000/navigator?technique=T1505.003) - Web shell URI and POST canary validation

**Simulation ID:** `sim-t1505-webshell-canary`
**Risk:** 1

Generate web-shell-shaped requests to validate telemetry without uploading or running shells.

**Tags / Target Types**

- `persistence-canary`
- `http`
- `https`
- `web`

**What Happens**

Send URI and POST canaries that resemble web-shell access patterns. The lab server returns benign responses and records indicators.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- shell-like extension
- cmd parameter
- POST body hash
- canary classification

**Safety Controls**

- no file creation
- no command execution
- local telemetry server only
- fixed canaries

---

## [T1518](http://localhost:3000/navigator?technique=T1518) - Software discovery

**Simulation ID:** `sim-t1518-software-discovery`
**Risk:** 1

Generate installed-software discovery telemetry without querying installed software.

**Tags / Target Types**

- `discovery-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST WMIC and PowerShell software-discovery canaries. Record process telemetry with software-discovery indicators.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- wmic product
- PowerShell registry uninstall path
- software_discovery alert

**Safety Controls**

- no registry/software query
- endpoint telemetry fixture only
- fixed discovery commands

---

## [T1518.001](http://localhost:3000/navigator?technique=T1518.001) - Atomic event: Security software discovery

**Simulation ID:** `sim-t1518-001-atomic-security-software-discovery`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1518.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1539](http://localhost:3000/navigator?technique=T1539) - Atomic event: Browser cookie database access

**Simulation ID:** `sim-t1539-atomic-browser-cookie-access`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1539. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 11 (FileCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=11
- event_name=FileCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1543.003](http://localhost:3000/navigator?technique=T1543.003) - Windows service creation

**Simulation ID:** `sim-t1543-service-creation`
**Risk:** 2

Generate service-creation telemetry without creating a service.

**Tags / Target Types**

- `persistence-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST service creation command-line canaries. Record process telemetry with service name and binary path indicators.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- sc.exe create
- New-Service
- service name
- binary path
- service_creation alert

**Safety Controls**

- no service creation
- endpoint telemetry fixture only
- fixed service name

---

## [T1546.003](http://localhost:3000/navigator?technique=T1546.003) - Atomic event: WMI event subscription persistence

**Simulation ID:** `sim-t1546-003-atomic-wmi-event-subscription`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1546.003. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 19 (WmiEventFilter). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=19
- event_name=WmiEventFilter
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1546.008](http://localhost:3000/navigator?technique=T1546.008) - Atomic event: Accessibility feature persistence

**Simulation ID:** `sim-t1546-008-atomic-accessibility-feature-backdoor`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1546.008. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 13 (RegistryValueSet). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=13
- event_name=RegistryValueSet
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1547.001](http://localhost:3000/navigator?technique=T1547.001) - Registry Run key persistence

**Simulation ID:** `sim-t1547-run-key-persistence`
**Risk:** 2

Generate registry-set telemetry for Run key persistence patterns without modifying a registry.

**Tags / Target Types**

- `persistence-canary`
- `endpoint`
- `windows-endpoint`

**What Happens**

POST Run-key persistence canaries to the endpoint target. Record registry-set shaped telemetry with the Run key path.

**Telemetry Source**

Endpoint lab telemetry: endpoint JSONL plus endpoint log source. Current non-atomic endpoint flows are safe telemetry fixtures, not OS command execution.

**System / Event Structure**

Endpoint events contain provider, event_id, event_name, process, command, file_path, target_process, operation, host, user, run_id, and simulation_id.

**Detection Focus**

- Registry value set
- HKCU Run key
- reg.exe or PowerShell
- persistence alert
- run correlation ID

**Safety Controls**

- no real registry write
- endpoint telemetry fixture only
- fixed key path

---

## [T1547.009](http://localhost:3000/navigator?technique=T1547.009) - Atomic event: Shortcut modification persistence

**Simulation ID:** `sim-t1547-009-atomic-shortcut-modification`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1547.009. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 11 (FileCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=11
- event_name=FileCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1550.002](http://localhost:3000/navigator?technique=T1550.002) - Atomic event: Pass-the-Hash style network logon

**Simulation ID:** `sim-t1550-002-atomic-pass-the-hash-logon`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1550.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_security telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 4624 (SuccessfulLogon). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_security event
- event_id=4624
- event_name=SuccessfulLogon
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1552.001](http://localhost:3000/navigator?technique=T1552.001) - Web-exposed secret and backup file canary

**Simulation ID:** `sim-t1552-web-secret-exposure-canary`
**Risk:** 1

Generate requests for exposed .env, backup config, and private-key paths without returning secrets.

**Tags / Target Types**

- `credential-exposure-canary`
- `http`
- `https`
- `web`

**What Happens**

Request fixed secret/config/key-looking paths against the local lab server. The server records access attempts but never serves secret material.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- secret-like path
- backup config path
- private-key path
- canary classification

**Safety Controls**

- no real secrets
- local telemetry server only
- fixed path list
- 404/benign responses only

---

## [T1552.002](http://localhost:3000/navigator?technique=T1552.002) - Atomic event: Credentials read from registry

**Simulation ID:** `sim-t1552-002-atomic-credentials-in-registry`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1552.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1552.006](http://localhost:3000/navigator?technique=T1552.006) - Atomic event: Cloud credential file access

**Simulation ID:** `sim-t1552-006-atomic-cloud-credential-file-access`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1552.006. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

edr telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured edr JSON with code FILE_READ (SensitiveFileAccess). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- edr event
- event_id=FILE_READ
- event_name=SensitiveFileAccess
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1555.003](http://localhost:3000/navigator?technique=T1555.003) - Atomic event: Browser credential store access

**Simulation ID:** `sim-t1555-003-atomic-browser-login-data-access`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1555.003. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 11 (FileCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=11
- event_name=FileCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1556.002](http://localhost:3000/navigator?technique=T1556.002) - Atomic event: Password filter DLL registration

**Simulation ID:** `sim-t1556-002-atomic-password-filter-dll-registered`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1556.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 13 (RegistryValueSet). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=13
- event_name=RegistryValueSet
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1560.001](http://localhost:3000/navigator?technique=T1560.001) - Atomic event: Archive collected data with utility

**Simulation ID:** `sim-t1560-001-atomic-archive-with-rar`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1560.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1562.001](http://localhost:3000/navigator?technique=T1562.001) - Atomic event: Impair defenses by disabling Defender

**Simulation ID:** `sim-t1562-001-atomic-disable-defender-realtime`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1562.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_defender telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 5007 (ConfigurationChanged). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_defender event
- event_id=5007
- event_name=ConfigurationChanged
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1562.004](http://localhost:3000/navigator?technique=T1562.004) - Atomic event: Disable host firewall

**Simulation ID:** `sim-t1562-004-atomic-disable-windows-firewall`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1562.004. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1564.001](http://localhost:3000/navigator?technique=T1564.001) - Atomic event: Hidden file attribute set

**Simulation ID:** `sim-t1564-001-atomic-hidden-file-attribute`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1564.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 1 (ProcessCreate). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=1
- event_name=ProcessCreate
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1566.001](http://localhost:3000/navigator?technique=T1566.001) - Atomic event: Spearphishing attachment delivery

**Simulation ID:** `sim-t1566-001-atomic-email-attachment-delivery`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1566.001. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

email_gateway telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured email_gateway JSON with code MESSAGE_DELIVERED (EmailDelivered). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- email_gateway event
- event_id=MESSAGE_DELIVERED
- event_name=EmailDelivered
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1567.002](http://localhost:3000/navigator?technique=T1567.002) - Atomic event: Exfiltration to cloud storage

**Simulation ID:** `sim-t1567-002-atomic-exfil-to-cloud-storage`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1567.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

proxy telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Structured proxy JSON with code HTTP_UPLOAD (LargeUpload). Includes observer/event metadata, host/process fields, source/destination or URL context when relevant, rule name, run_id, and simulation_id.

**Detection Focus**

- proxy event
- event_id=HTTP_UPLOAD
- event_name=LargeUpload
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1569.002](http://localhost:3000/navigator?technique=T1569.002) - Atomic event: Service execution

**Simulation ID:** `sim-t1569-002-atomic-service-execution`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1569.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

windows_system telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 7045 (ServiceInstalled). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- windows_system event
- event_id=7045
- event_name=ServiceInstalled
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1574.002](http://localhost:3000/navigator?technique=T1574.002) - Atomic event: DLL side-loading artifact

**Simulation ID:** `sim-t1574-002-atomic-dll-side-loading`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1574.002. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 7 (ImageLoaded). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=7
- event_name=ImageLoaded
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1574.011](http://localhost:3000/navigator?technique=T1574.011) - Atomic event: Service registry permissions weakness artifact

**Simulation ID:** `sim-t1574-011-atomic-services-registry-permissions-weakness`
**Risk:** 1

Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed.

**Tags / Target Types**

- `atomic-event-artifact`
- `endpoint`
- `windows-endpoint`
- `linux-endpoint`
- `identity-lab`
- `cloud`
- `email`
- `proxy`

**What Happens**

One high-signal event is emitted for T1574.011. No malware, exploit, command, registry write, file write, or cloud/identity action is executed.

**Telemetry Source**

sysmon telemetry fixture through the endpoint log source. Use the Endpoint EDR/Sysmon log or forward endpoint events to SIEM.

**System / Event Structure**

Strict Windows Event Log shaped JSON for EventID 13 (RegistryValueSet). Includes Event.System.Provider, Event.System.EventID, Event.System.Channel, Event.System.Computer, Event.System.Security, Event.EventData.Data[], winlog.event_data, and event.original XML.

**Detection Focus**

- sysmon event
- event_id=13
- event_name=RegistryValueSet
- ATT&CK technique mapped in simulation metadata
- run_id and simulation_id correlation fields

**Safety Controls**

- single event only
- local endpoint telemetry fixture only
- no command execution
- no credential access
- no filesystem, registry, cloud, identity, or network changes

---

## [T1589.002](http://localhost:3000/navigator?technique=T1589.002) - Web user enumeration sequence

**Simulation ID:** `sim-t1589-web-user-enumeration`
**Risk:** 1

Generate user-enumeration-shaped requests against the built-in auth fixture.

**Tags / Target Types**

- `reconnaissance`
- `http`
- `https`
- `web`

**What Happens**

Probe fixed known and unknown lab usernames. Record whether the auth fixture treated each username as existing.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- username probe
- user exists flag
- unknown user failure
- user_enumeration security alerts

**Safety Controls**

- lab server only
- fixed user list
- no password attack volume
- no external identity provider

---

## [T1595](http://localhost:3000/navigator?technique=T1595) - HTTP method and override probing

**Simulation ID:** `sim-t1595-http-method-probing`
**Risk:** 1

Send real OPTIONS, TRACE, and method-override probes to the lab web server to validate method-anomaly telemetry.

**Tags / Target Types**

- `web-reconnaissance`
- `http`
- `https`
- `web`

**What Happens**

Send OPTIONS and TRACE requests to the lab target. Send a benign request with X-HTTP-Method-Override.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- OPTIONS request
- TRACE request
- method override header
- 405/200 status
- WAF method_probe alert

**Safety Controls**

- lab server only
- fixed methods
- no payload execution
- no external target

---

## [T1595](http://localhost:3000/navigator?technique=T1595) - HTTP/TLS service fingerprint plan

**Simulation ID:** `sim-t1595-http-fingerprint`
**Risk:** 0

Prepare a safe external-service fingerprint validation for approved web targets.

**Tags / Target Types**

- `reconnaissance`
- `http`
- `https`
- `web`

**What Happens**

Confirm target authorization and maintenance window. Start the local telemetry web server on 127.0.0.1.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- lab web access log
- request headers
- response status
- source IP
- run correlation ID

**Safety Controls**

- target allowlist
- local telemetry server only
- no payloads
- rate limit
- analyst review

---

## [T1595](http://localhost:3000/navigator?technique=T1595) - Scanner and tool user-agent fingerprinting

**Simulation ID:** `sim-t1595-tool-user-agent-fingerprint`
**Risk:** 1

Send real HTTP requests with fixed scanner/tool user-agents to validate server-side telemetry and parser coverage.

**Tags / Target Types**

- `reconnaissance`
- `http`
- `https`
- `web`

**What Happens**

Send benign requests with tool-like user-agent headers. Record headers in structured web telemetry and real access logs.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- curl user-agent
- python-requests user-agent
- sqlmap user-agent
- Nmap NSE user-agent
- tool_user_agent alert

**Safety Controls**

- lab server only
- fixed benign requests
- no exploit payload
- no scan volume

---

## [T1595](http://localhost:3000/navigator?technique=T1595) - Web 404 discovery burst

**Simulation ID:** `sim-t1595-web-404-burst`
**Risk:** 1

Generate a small real 404 burst against common admin and technology paths to validate path-scan detections.

**Tags / Target Types**

- `web-reconnaissance`
- `http`
- `https`
- `web`

**What Happens**

Request a fixed list of common admin and technology paths. Observe real NGINX 404 access log lines from the attacked server.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- multiple 404 statuses
- CMS/admin paths
- same source correlation
- not_found_burst alert

**Safety Controls**

- six fixed paths only
- lab server only
- no directory brute force
- no recursion

---

## [T1595](http://localhost:3000/navigator?technique=T1595) - Web content discovery and path enumeration

**Simulation ID:** `sim-t1595-web-content-discovery`
**Risk:** 1

Generate benign admin/API/backup/repository path probes against the lab web server.

**Tags / Target Types**

- `web-reconnaissance`
- `http`
- `https`
- `web`

**What Happens**

Start the local telemetry web server. Request a fixed set of common administrative, API, backup, and repository paths.

**Telemetry Source**

Attacked lab web server telemetry: real NGINX access log, structured web JSONL, auth log, and WAF/security-style log when the request matches a canary.

**System / Event Structure**

Web events contain method, URI/path, status, client IP, user-agent, request length, response bytes, body hash/length, run_id, simulation_id, and canary classification. Auth scenarios also include username hash, user-exists flag, outcome, and failure reason.

**Detection Focus**

- access log path distribution
- 404 status spikes
- admin path probes
- backup path probes

**Safety Controls**

- local telemetry server only
- fixed path list
- no directory brute force
- no payload execution

---
