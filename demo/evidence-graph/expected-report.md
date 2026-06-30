# Evidence-to-Detection Graph Demo Report

## Summary

The fictional sample demonstrates a complete evidence-to-decision path for
PowerShell command execution and a partial path for outbound transfer behavior.

## Detection Readiness Score

The PowerShell path can reach a high readiness score after analyst review,
validated telemetry, a rule, replay validation, SIEM match, and analyst
acceptance. The score is operational guidance, not proof of full coverage.

## Validated Path

Evidence from report/log
→ Claim
→ Behavior
→ ATT&CK Technique `T1059.001`
→ Required Telemetry
→ Detection Candidate
→ Detection Rule
→ Validation Scenario
→ SIEM Result
→ Analyst Decision

## Open Gaps

- PowerShell Script Block Logging is missing.
- `T1105` needs a separate detection candidate and validation path.

## Limitations

This demo uses fictional data, documentation IP ranges, and safe indicators. It
does not include real malware, private customer data, or operational attack
instructions.
