# Threat Radar

Threat Radar is the product-security CTI early-warning module for turning public,
private, and internal threat signals into scored cases and downstream defensive
work. It connects threat claims to products, components, dependencies, CVEs,
TTPs, IOCs, suppliers, and workflow owners.

The module is designed for PSIRT, detection engineering, threat hunting, IR,
legal, and product engineering coordination. It is not an exploit marketplace
collector and it must not store stolen credentials, exploit payloads, illegal
forum access instructions, or stolen data.

## Signal Types

Threat Radar accepts these signal categories:

- CVE disclosure.
- CISA KEV or active exploitation.
- Public PoC.
- Zero-day claim.
- Exploit-sale claim.
- Closed-source provider mention.
- Marketplace or hardware listing.
- Firmware dump claim.
- Source-code leak claim.
- Credential exposure.
- Supplier breach.
- Malicious package.
- Critical dependency vulnerability.
- Customer report.
- Internal telemetry anomaly.

Restricted-source and legal-sensitive categories are stored as sanitized
metadata only. Evidence summaries are redacted for credentials, private keys,
exploit payload phrasing, and direct illegal-source instructions.

## Data Model

Threat Radar stores separate objects for source, signal, claim, evidence,
entity, case, product mapping, score, action, and generated report:

```text
Threat Source
  -> Threat Signal
  -> Evidence and Claims
  -> Entities: CVE, TTP, IOC, product, component, dependency, supplier, actor
  -> Product Exposure Mapping
  -> Threat Case
  -> Score, Recommended Actions, Reports, Work Queues
```

The graph is intentionally explicit. A signal can mention a CVE and a product,
but a product-security action should be based on a case where the relevant
product, component, exposure, and blast-radius fields are visible.

## Scoring

Each signal and case receives a 0-100 score using normalized factors:

| Factor | Meaning |
|---|---|
| Source reliability | How trusted the source is, from unverified to authoritative. |
| Claim credibility | Whether the claim is vague, corroborated, or evidence-backed. |
| Product relevance | Whether the affected asset maps to your product, component, dependency, or customer environment. |
| Exploitability | Whether exploitation is theoretical, proof-of-concept, or observed. |
| Exposure | Whether the affected surface is internet-facing, third-party, internal, or lab-only. |
| Blast radius | Expected customer, operational, or supply-chain impact. |

Priority bands:

| Score | Priority |
|---|---|
| 90-100 | P0 Emergency |
| 75-89 | P1 High |
| 55-74 | P2 Medium |
| 30-54 | P3 Monitor |
| 0-29 | P4 Low / archive |

## Auto Actions

Threat Radar recommends workflow actions from the scored signal:

- **P0/P1 + product relevance:** create PSIRT task, IR escalation, hunt request,
  detection requirement, and legal review when source sensitivity requires it.
- **CISA KEV / active exploitation:** create patch-verification and detection
  validation work.
- **Supplier breach or malicious package:** create supply-chain finding and
  dependency review.
- **Source-code leak, credential exposure, exploit-sale, and closed-source
  claims:** mark legal-sensitive and require sanitized handling.

Actions are recommendations until an analyst creates the work item.

## Analyst Workflow

1. Open **Threat Radar** from the sidebar or Discover page.
2. Create a signal from a CVE, KEV, PoC, supplier, package, hardware, customer,
   or internal telemetry lead.
3. Add sanitized evidence and product exposure context.
4. Review score factors, priority, and recommended actions.
5. Open the generated case and inspect the graph.
6. Create PSIRT, Threat Hunt, IR, Detection, or Legal workflow objects.
7. Generate a Flash Note, Product Impact Assessment, Threat Hunt Pack, PSIRT
   Appendix, or Executive Summary.

## Pages

| Page | Purpose |
|---|---|
| Dashboard | Overview counters, recent cases, product exposure, and priority legend. |
| Signal Inbox | Search and select scored signals. |
| Signal Detail | Review claims, evidence, entities, score factors, and product mappings. |
| Cases | Work a case, create actions, and generate reports. |
| Case Graph | Visualize signal, case, CVE, TTP, product, component, and dependency links. |
| Product Exposure | Review affected products, components, versions, environments, and blast radius. |
| Watchlists | CVE, zero-day, supply-chain, hardware, and marketplace queues. |
| Workflows | Hunt, PSIRT, IR, Detection, action, and audit queues. |
| Reports | Generated case outputs. |
| Settings / Sources | Configured signal sources and reliability metadata. |

## API Routes

The backend exposes the module under `/api/threat-radar`:

- `GET /sources`, `POST /sources`
- `GET /signals`, `POST /signals`
- `GET /signals/{signal_id}`
- `POST /signals/{signal_id}/triage`
- `GET /cases`, `GET /cases/{case_id}`
- `GET /cases/{case_id}/graph`
- `POST /cases/{case_id}/score`
- `POST /cases/{case_id}/escalate`
- `POST /evidence`
- `POST /product-map`
- `POST /cases/{case_id}/create-hunt`
- `POST /cases/{case_id}/create-psirt-task`
- `POST /cases/{case_id}/create-ir-escalation`
- `POST /cases/{case_id}/create-detection-requirement`
- `POST /cases/{case_id}/generate-report`
- `GET /product-exposure`
- `GET /watchlists/{cve|zero-day|supply-chain|hardware}`
- `GET /queues/{hunts|psirt|ir|detections|reports|actions|marketplace|supply-chain|audit}`

## Validation Boundary

Threat Radar helps prioritize and coordinate response. It does not prove
exploitation by itself. Analysts must validate:

- whether the affected product or dependency is actually present;
- whether the affected version is deployed;
- whether the vulnerable path is reachable;
- whether internal telemetry confirms exploitation;
- whether legal or disclosure handling is required.

Use the module to preserve this reasoning instead of flattening all claims into
a single alert.
