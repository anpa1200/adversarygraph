# AdversaryGraph v5.0.0 Release Summary

AdversaryGraph v5.0.0 adds Attack Simulation: a controlled ATT&CK validation
workflow for choosing a TTP, running benign web simulations against a built-in
local telemetry target, viewing real-time attack logs, and forwarding generated
telemetry to HTTP(S) SIEM collectors.

The release also adds an AI Attack Assistant for detection engineering drills:
analysts can generate coherent multi-phase telemetry stories, send source-shaped
events to a SIEM collector, review an attack-chain graph, and open an
explanation of the scenario logic.

## Highlights

- New **Attack Simulation** workspace with TTP-first selection.
- Dedicated simulation configuration page per ATT&CK technique.
- Built-in local web telemetry server for safe web-focused simulations.
- Docker Compose `attack-lab-web` target container for real request flow: the
  API attacks the lab webserver over the compose network and the target writes
  the server logs.
- Expanded web scenario matrix covering fingerprinting, public exposure, path
  discovery, traversal, SQLi/XSS, SSRF, command-injection, web-shell,
  upload/download, exposed secret/config/key paths, failed-login, brute-force,
  password-spray, user-enumeration, beacon, and exfiltration-shaped canaries.
- Web telemetry classification for clean path, query keys, body metadata, body
  hash, body preview, and matched canary categories.
- Real access, security, error, and auth log streams for SIEM parser and
  detection validation. Auth logs preserve outcomes and password metadata
  without writing cleartext passwords.
- JSONL attack-run and web-access logs under `/app/logs/attack-simulation/`.
- Real-time log polling in the UI.
- SIEM forwarding for generated telemetry with HTTP(S), IP/URL destination
  input, direct/Docker-host/auto connection routing, none/bearer/token/basic/
  custom-header authentication, and destination guardrails.
- Last 10 non-secret SIEM destinations are retained for repeated parser and
  rule validation.
- AI Attack Assistant with selected-TTP, actor-oriented, and Challenge Me modes.
- 25 named coherent scenario templates for repeatable kill-chain validation.
- Complicated attack mode for longer multi-source flows across web, WAF, DNS,
  proxy, firewall, Windows Security, Sysmon, and EDR-shaped telemetry.
- Attack-chain graph with ordered phases, ATT&CK IDs, telemetry sources, event
  counts, and detection goals.
- Explain Attack panel for analyst-facing scenario rationale and validation
  focus.
- Compatibility redirect from `/external-simulation` to `/attack-simulation`.

## Safety Boundaries

- No exploit execution. Attack-shaped web scenarios are fixed benign canaries.
- No arbitrary command execution.
- No arbitrary external target execution.
- Web simulation traffic is limited to predefined benign requests against the
  local lab telemetry server.
- SIEM forwarding sends only generated Attack Simulation telemetry and blocks
  unsafe URL schemes plus metadata/link-local destinations.

## Documentation

- Detailed module docs: [`docs/attack-simulation.md`](attack-simulation.md)
- Screenshot manifest: [`docs/assets/attack-simulation-v5/manifest.md`](assets/attack-simulation-v5/manifest.md)
- Release notes: [`docs/release-notes/v5.0.0.md`](release-notes/v5.0.0.md)
