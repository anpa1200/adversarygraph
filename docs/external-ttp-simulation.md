# External TTP Simulation

External TTP Simulation prepares and records ATT&CK-aligned validation scenarios
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

## Workflow

1. Open **External Simulation** from the sidebar or Discover page.
2. Select a predefined ATT&CK simulation.
3. Select an approved lab target from the target registry.
4. Generate a dry-run plan.
5. Review safety controls, expected telemetry, and approval checklist.
6. Create a controlled run record.
7. Run the approved scenario from an isolated lab runner outside the API container.
8. Paste SIEM/WAF/firewall/DNS/proxy/EDR/IdP evidence into the manual result form.
9. Mark the detection result as `passed`, `failed`, `partial`, or `not_proven`.

## Current Simulation Catalog

| Simulation | ATT&CK | Purpose |
|---|---|---|
| HTTP/TLS service fingerprint plan | `T1595` | Validate telemetry for external service fingerprinting |
| Public web exposure validation plan | `T1190` | Validate web/WAF visibility without exploit payloads |
| External remote service reachability plan | `T1133` | Validate remote-service reachability telemetry without authentication attempts |
| Controlled HTTP/DNS beacon validation plan | `T1071` | Plan lab-agent egress telemetry validation |
| Lab-only failed-login sequence plan | `T1110` | Plan low-rate identity telemetry validation against lab-only test accounts |

## API Endpoints

```text
GET  /api/simulation/catalog
GET  /api/simulation/targets
POST /api/simulation/plan
POST /api/simulation/run
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
