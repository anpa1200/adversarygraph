# Attack Simulation Feature Checklist

Status key: `[x]` implemented, `[~]` started, `[ ]` planned.

## Scenario Quality

- [x] Named coherent complicated kill chain instead of random TTP selection.
- [x] Scenario library templates with preconditions, success criteria, difficulty, telemetry sources, and expected detections.
- [x] Scenario templates: at least 20 coherent named scenarios using currently supported telemetry families.
- [ ] Explicit precondition validation before run: target type, logging sources, SIEM destination, saved authorization context.
- [ ] Scenario success criteria evaluated after delivery.
- [ ] Difficulty levels: atomic, simple chain, full intrusion, noisy red-team drill.
- [ ] Timeline controls: fast replay, realistic timing, burst mode, business-hours only.

## Telemetry Realism

- [x] Raw source-shaped events for NGINX, WAF, Windows Event XML, Sysmon XML, firewall, DNS, proxy, EDR, and CrowdStrike-style JSON.
- [ ] Native vendor modes: Zeek, Suricata EVE, AWS CloudTrail, Azure AD, Okta, Fortinet, Defender, Elastic, Splunk HEC.
- [ ] Benign background noise mixed with malicious signals.
- [ ] Decoy false positives for precision testing.
- [ ] Host/user/IP consistency validator across all scenario phases.
- [ ] Clock skew, delayed delivery, dropped events, and missing-source simulation.

## AI Assistant

- [x] LLM provider selector.
- [x] AI-used/model/fallback state shown in UI.
- [x] Complicated attack option.
- [x] Challenge explanation button.
- [~] AI-generated scenario plan before delivery.
- [ ] Approve-and-run workflow.
- [ ] Explain each event and expected detection rule.
- [ ] Mutate scenario: same kill chain with different tools, users, paths, domains.
- [ ] Make harder: add noise, slower timing, living-off-the-land variants, partial telemetry.
- [ ] Blue-team hints and no-hints modes.

## SIEM Integration

- [x] Saved SIEM destinations.
- [x] Auth options and raw-line/per-event/envelope payload modes.
- [ ] Test connection button.
- [ ] Payload preview before sending.
- [ ] Vendor output modes: Splunk HEC, Elastic, Sentinel Log Analytics, QRadar, LogEye, OpenSearch.
- [ ] Delivery report with sent/failed/retried/rejected details.
- [ ] Replay previous run to same or different SIEM.

## Detection Engineering

- [ ] Generate Sigma, Splunk SPL, KQL, EQL, and YARA-L draft rules per scenario.
- [x] Expected detections panel.
- [ ] Validation result: passed, missed, partial, noisy.
- [ ] Gap analysis: missed TTP, missed correlation, parser issue, data-source issue.
- [ ] ATT&CK coverage delta after every run.

## Product UX

- [x] Scenario graph view.
- [ ] Timeline replay view.
- [x] Clickable TTP links in result steps.
- [ ] Clickable phase details with raw events, detection logic, and MITRE links.
- [ ] Export evidence bundle: events, plan, detections, gaps, screenshots.
- [ ] Run history and comparison between runs.
- [ ] Tags: web, identity, endpoint, cloud, C2, exfiltration, persistence.

## Lab Targets

- [x] Web lab target.
- [x] Endpoint telemetry lab target.
- [ ] Identity/auth lab target.
- [ ] SQL server lab target.
- [ ] FTP/SFTP lab target.
- [ ] Mail server lab target.
- [ ] Cloud audit log simulator.
- [ ] Per-target supported TTPs and telemetry source readiness.
- [ ] Health checks: logging enabled, writable logs, target reachable, SIEM reachable.
