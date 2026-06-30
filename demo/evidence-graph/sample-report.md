# Fictional Intrusion Report

This safe sample report describes a fictional investigation for demo use only.

On 2026-06-30, workstation `WS-DEMO-01` received a suspicious email that linked
to `https://update.example.com/download`. The user downloaded a script named
`invoice-check.ps1`. Endpoint telemetry later showed `powershell.exe` launching
with encoded command arguments.

The same host contacted `203.0.113.44` over HTTPS. No malware binary is included
in this demo. Indicators use documentation-safe domains and RFC5737 IP ranges.

Analyst hypothesis:

- PowerShell command execution should map to `T1059.001`.
- Network connection telemetry is needed to validate outbound callback behavior.
- Script Block Logging is not available in the fictional environment, creating a
  telemetry gap.
