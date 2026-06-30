# Validation and Limitations

This document records what AdversaryGraph can validate today and where analyst review is still required.

## Validation Rules

| Output | Validation requirement |
|---|---|
| ATT&CK mapping | Confirm the evidence describes behavior, not just a tool name or actor label |
| Group/campaign similarity | Treat TTP overlap as an investigation lead, not attribution |
| Generated detection logic | Test in the target SIEM/EDR/query engine before operational deployment |
| IOC enrichment | Check source, timestamp, confidence, and relationship context |
| Malware-analysis summary | Confirm static and runtime evidence separately; do not merge AI interpretation into ground truth |
| Asset Surface matrix | Validate exposure, ownership, criticality, and reachable services against authoritative inventory |
| Attack Simulation real telemetry | Confirm the lab target emitted the event and that the SIEM parsed it as expected |
| Attack Simulation synthetic telemetry | Use for parser/rule/correlation drills only; it is not proof of real exploit detection |

## Implemented Validation Aids

- Review states for extracted mappings.
- Evidence snippets and source references where available.
- Saved investigations, asset-surface cases, and attack simulation runs.
- Real-time attacked-server log view for lab simulations.
- SIEM forwarding status, event counts, and recent destination history.
- Demo dataset with expected mappings and expected outputs.
- CI checks for tests, lint, dependency audit, Docker build, container scan, secret scan, and version consistency.

## Current Limitations

- The default deployment is not a hardened multi-tenant SaaS.
- Native username/password authentication provides project-level access control, but the default deployment is still not a hardened internet-facing SaaS.
- AI provider behavior can vary between model versions.
- Generated detections are drafts.
- Synthetic telemetry may match a vendor structure but is still generated data.
- SQL, FTP, identity, and egress simulation target classes require dedicated lab fixtures before they can be treated as real lab telemetry.
- Malware dynamic analysis requires isolated MalwareGraph runtime profiles and remains disabled by default.

## Reviewer Checklist

Before accepting a result as validated:

- Confirm the source record exists.
- Confirm the timestamp, run ID, case ID, or analysis ID matches the reviewed output.
- Confirm the ATT&CK technique is behaviorally justified.
- Confirm no private data was uploaded to public demos.
- Confirm generated detections were tested against representative telemetry.
- Document unresolved assumptions and validation gaps in the investigation.
