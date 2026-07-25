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

## Product-Security Inventory Tables

Threat Radar should not flatten every product-security fact into one asset CSV.
Use related inventories so CVE, actor, IOC, and TTP relevance can be traced
through the same graph that PSIRT, hunt, IR, and detection teams use:

```text
Signal
  -> Claim
  -> Product
  -> Component
  -> Dependency / SBOM
  -> Exposure
  -> Owner
  -> PSIRT / Hunt / IR / Detection Action
```

The UI provides these downloadable CSV headers:

| Table | Template | Purpose |
|---|---|---|
| `asset_inventory` | [`asset_inventory_template.csv`](../templates/threat-radar/asset_inventory_template.csv) | Real deployed systems, domains, IPs, services, owners, exposure, and criticality. |
| `product_inventory` | [`product_inventory_template.csv`](../templates/threat-radar/product_inventory_template.csv) | Product family, product line, ownership, support status, release channel, deployment model, and criticality. |
| `component_inventory` | [`component_inventory_template.csv`](../templates/threat-radar/component_inventory_template.csv) | Product-to-component mapping for drivers, firmware, SDK libraries, containers, management interfaces, and cloud services. |
| `dependency_sbom_inventory` | [`dependency_sbom_inventory_template.csv`](../templates/threat-radar/dependency_sbom_inventory_template.csv) | SBOM/dependency records for package, CPE, PURL, supplier, build/runtime use, customer shipment, and CVE/supply-chain matching. |
| `product_exposure_inventory` | [`product_exposure_inventory_template.csv`](../templates/threat-radar/product_exposure_inventory_template.csv) | Exploitability and customer-exposure context: reachable paths, trust boundary, privilege, telemetry, mitigation, and patch status. |

Recommended controlled values include:

- Product families: `GPU Driver`, `CUDA`, `cuDNN`, `TensorRT`, `NCCL`,
  `NGC Container`, `Jetson`, `IGX`, `BlueField`, `ConnectX`, `DOCA`, `vGPU`,
  `Firmware`, and `BMC`.
- Component types: `kernel_driver`, `user_mode_driver`, `firmware`,
  `bootloader`, `sdk_library`, `container_image`, `dpu_firmware`,
  `nic_firmware`, `bmc_component`, `open_source_dependency`, `cloud_service`,
  and `management_interface`.
- Trust boundaries: `guest_to_host`, `container_to_host`, `vf_to_pf`,
  `user_to_kernel`, `workload_to_gpu_memory`, `host_to_firmware`,
  `network_to_management_plane`, and `supplier_to_build_pipeline`.

Use stable IDs across tables. For example, `component_inventory.product_id`
must reference `product_inventory.product_id`, and
`dependency_sbom_inventory.component_id` must reference
`component_inventory.component_id`. This is what lets Threat Radar correlate a
new CVE or actor report to the affected product, component, dependency,
customer exposure, owner, and response workflow.

## Product-Security Feeds

Threat Radar uses the shared CVE Library as its vulnerability intelligence
backbone. The **Settings / Sources** page includes product-security feed
controls for:

| Feed | Purpose | Storage |
|---|---|---|
| NVD CVE API 2.0 | CVE metadata, CVSS, CWE, CPE, and references. | `cve_records`, `cve_sources` |
| CISA KEV | Known-exploited vulnerability priority and required actions. | `cve_records.known_exploited`, `kev_*` fields |
| GitHub Advisory Database | Reviewed package/security advisories, affected ecosystems, packages, CVSS, CWE, and references. | CVE records tagged `tag:github-advisory`, `tag:product-security`, `tag:ecosystem-*`, `dependency:*` |
| FIRST EPSS | Exploitation probability and percentile for prioritization. | `cve_records.raw.epss` and tags such as `tag:epss-top-percentile` |
| OSV.dev | Dependency/SBOM package lookup by ecosystem, package, and optional version. | CVE records tagged `tag:osv`, `tag:product-security`, `tag:ecosystem-*`, `dependency:*` |

The Product Security feed catalog also registers additional relevant sources so
operators can configure and track them in one place:

| Feed family | Sources | Typical use |
|---|---|---|
| Package and ecosystem advisories | GitLab Advisory Database, PyPA Advisory Database, Go Vulnerability Database, RustSec Advisory Database, deps.dev, Snyk, Socket | Match SBOM/package inventory to language ecosystem vulnerabilities and supply-chain risk. |
| Vendor security advisories | Microsoft Security Update Guide, Red Hat Security Data API, Ubuntu Security Notices, Debian Security Tracker, Alpine SecDB, CERT/CC Vulnerability Notes, CISA ICS Advisories | Map vendor/product advisories to deployed products, components, firmware, operating systems, and customer exposure. |
| Exploit and active exploitation context | Exploit-DB, Metasploit modules, VulnCheck | Prioritize CVEs with public exploit code, exploitation metadata, or KEV-like intelligence. |
| Lifecycle and end-of-support | endoflife.date | Flag products, components, and dependencies that are unsupported or near end of support. |
| External exposure and breach monitoring | Have I Been Pwned, LeakIX, SpyCloud, Flare, DarkOwl, Intel 471, KELA, Recorded Future | Track exposed accounts, leaked credentials, dark web mentions, supplier compromise, and product/customer exposure. |

Active built-in sync currently covers NVD, CISA KEV, GitHub Advisories, FIRST
EPSS, and OSV package lookups. Other catalog entries are intentionally exposed
as configurable source records and API-key readiness checks so paid/private
connectors can be enabled without changing the taxonomy, source model, or
inventory format.

Feed data is normalized into the same taxonomy model used by assets, products,
components, dependencies, and Threat Radar cases. Feed sync does not prove
customer exposure by itself; it creates the evidence needed to match a CVE or
package advisory against the product/component/dependency/exposure inventories.

OSV package lookup expects one package per line in this format:

```text
ecosystem,package,version
npm,express,4.17.1
PyPI,urllib3,1.26.18
Maven,org.apache.logging.log4j:log4j-core,2.14.1
```

## Exposure, Breach, Leak, and Prototype Monitoring

Threat Radar also includes an exposure-monitoring layer for authorized
commercial and open-source providers. It is built for product-security use cases
such as:

- engineering prototype or sample offered for sale;
- firmware dump or product binary leak claim;
- source-code or repository exposure claim;
- corporate credential, SSO, VPN, cookie, or stealer-log exposure;
- supplier, OEM/ODM, contractor, or build-pipeline compromise;
- external internet exposure for management planes, services, and product
  banners;
- malware sample monitoring with VirusTotal Retrohunt/Livehunt rules for
  product names, drivers, firmware, suppliers, package names, and leaked
  components.

Configured providers are visible in **Threat Radar -> Exposure Monitoring** and
**Settings / Sources**. The provider-readiness check shows which API keys are
present without revealing secret values.

| Provider family | Examples | Use in Threat Radar |
|---|---|---|
| Commercial CTI | Recorded Future | Import sanitized finished-intelligence or vulnerability/exposure hits into scored cases. |
| Malware hunting | VirusTotal Retrohunt, VirusTotal Livehunt | Monitor historical and new malware samples for product, supplier, firmware, driver, or YARA matches. |
| Breach/credential monitoring | Have I Been Pwned, SpyCloud, Flare | Track exposed corporate accounts, stealer-log risk, credential reuse, and identity compromise. |
| Dark web/cybercrime intelligence | DarkOwl, Intel 471, KELA | Track access brokers, marketplace mentions, prototype listings, and leak claims. |
| External exposure | LeakIX, Shodan, Censys, urlscan.io | Track exposed services, banners, certificates, URLs, phishing pages, and accidental file exposure. |
| Open CTI and package risk | OTX, ThreatFox, Socket, Snyk, VulnCheck | Enrich package, IOC, exploitability, malware, and vulnerability context. |

### Prototype-sale Detection Logic

A suspected prototype or engineering sample sale is not stored as raw marketplace
content. The analyst or provider connector submits a sanitized hit with fields
such as provider, title, summary, product, component, supplier, handle, price,
and source URL/reference. Threat Radar classifies the hit as
`marketplace_hardware_listing` when prototype/sample language appears together
with sale/broker language, then opens a legal-sensitive case with:

- product/component mapping;
- sanitized evidence;
- legal/IP review action;
- authenticity validation action;
- PSIRT, IR, or detection actions when score factors justify escalation.

### Safety Boundary

Do not paste or store:

- stolen credentials, cookies, tokens, or private keys;
- stolen source files, firmware, product schematics, or build artifacts;
- exploit payloads or instructions to access illegal sources;
- raw dark-web marketplace pages that violate legal handling rules.

Store provider summaries, case IDs, URLs, hashes, tags, confidence, and
sanitized metadata only. Legal-sensitive categories automatically add handling
notes and redaction.

## Inventory-Bound Asset Exposure Assessment

> **Released in v6.5.0 source:** this workflow is part of the v6.5 release
> candidate. It is not part of the historical immutable v6.0.0 release tag;
> immutable v6.5 artifacts exist only after the tag workflow succeeds.

### Saved asset registry and detail pages

After **Asset Surface** parses and saves an inventory into a Threat Radar
company space, open **Threat Radar -> Asset Inventory**. The registry retrieves
the persisted assets from the API, supports name, inventory-ID, owner, IP,
domain, product, component, technology, criticality, and exposure filtering,
and links every row to:

`/threat-radar/assets/{space_id}/{asset_id}`

The dedicated page contains the normalized inventory record, risk summary,
matching Threat Radar alerts, recent assessment history, and bounded
correlations to the local CVE, IOC, and ATT&CK libraries. Correlation evidence
is labelled by origin:

- `exact-inventory-identity` means an exact saved IP/domain/URL identity is
  present in the IOC Library;
- `matched-signal` means a Threat Radar signal was matched to this asset;
- `cve-linked` and `cve-technique-link` are stored, source-backed
  relationships;
- `inventory-cpe` is a CPE-based candidate from the saved inventory;
- `inventory-name-candidate` is a lower-confidence product/component candidate;
- `scan-cpe-candidate` is inferred from an observed service CPE.

None of these labels proves compromise or confirms that a vulnerability
applies. Exact IOC identity matches still require ownership and freshness
review. CVE candidates require deployed-version, affected-range,
configuration, reachability, and compensating-control validation.

### Manage company-space inventory

Open **Threat Radar -> Asset Inventory** to manage the selected company space:

- **Add asset manually** creates one normalized inventory record.
- **Edit asset** updates its name, type, environment, owner, criticality,
  exposure, IP addresses, domains, ports, products, components, technologies,
  and tags.
- **Upload & analyze inventory** opens Asset Surface with the company-space ID
  already selected, allowing CSV, JSON, TXT, CMDB, cloud, and scanner exports
  to add or refresh multiple records.

The inventory ID is the stable identity used for deduplication, correlation,
and repeat imports. It is set when the asset is created and is intentionally
read-only during editing. To replace that identity, create a new asset and
retire the old record through the organization's inventory-governance process.

Saving an edit replaces the asset's derived inventory-graph children, refreshes
its unified knowledge relationships, preserves the database UUID and assessment
history, and records the changed field names in the audit log. Values removed
from the form are removed from the current asset relationship set rather than
silently retained as active inventory facts.

The **Threat Radar -> Asset Inventory** page can assess an IP address or
HTTP(S) URL host that is already recorded on the selected asset. It combines:

1. passive lookup in the local IOC Library;
2. configured VirusTotal, OTX, urlscan.io, GreyNoise Community, AbuseIPDB,
   Shodan, and Censys sources;
3. optional, authorized Nmap service discovery;
4. optional, authorized root-only web posture checks;
5. product-family CPE correlation against the local CVE Library;
6. deterministic or governed AI-assisted interpretation; and
7. a controlled inventory merge for newly observed IP addresses, hostnames,
   ports, technologies, and CPEs.

The target field is not an arbitrary internet scanner. The API normalizes the
requested IP, domain, or URL and rejects it unless the exact host is present in
that asset's `ip_addresses` or `domains` inventory field. URL credentials,
query strings, and fragments are rejected or removed before storage and
provider use. External providers are skipped for private, reserved, and
internal-only targets so internal asset names and addresses do not leave the
deployment.

### Safe active-discovery profile

Active discovery is disabled independently with
`ASSET_SCANNER_NMAP_ENABLED`. When enabled, it requires:

- the `run_attack_simulation` permission;
- a per-request authorization confirmation;
- an inventory-bound target; and
- the fixed `safe-service-discovery` profile.

The profile uses an unprivileged TCP connect scan, the configured top-port
limit, light service/version detection, bounded retries, and a host timeout. It
does **not** use NSE vulnerability or exploit scripts, UDP scanning, OS
fingerprinting, evasion flags, credential testing, or exploitation. Nmap XML is
parsed with a hardened XML parser and stored as structured evidence.

The separate `safe-root-http-posture` stage is controlled by
`ASSET_SCANNER_WEB_PROBE_ENABLED` and the same `run_attack_simulation`
permission and per-request authorization confirmation. It sends at most two
root HTTP(S) GET requests, does not follow redirects, and inspects only status
and bounded response headers. It checks observable redirect, security-header,
cookie, CORS, and server-technology posture. It does not crawl, submit forms,
authenticate, fuzz, inject payloads, brute-force, or exploit the application.

An open port is an observation, not a vulnerability. Shodan/Censys
vulnerability references and local CPE-to-CVE matches are explicitly labelled
as candidates requiring analyst confirmation of the detected product, deployed
version, affected version range, reachability, and compensating controls.

### Discovered attack surfaces and inventory updates

When **Add observed attack surfaces to this asset** is selected, the API
normalizes and deduplicates observations before merging them into the same
company asset. DNS resolution and bounded Nmap can contribute addresses,
hostnames, ports, service products, and CPEs. Successful Shodan, Censys, and
AbuseIPDB relationships can contribute typed hostnames, globally routable IPs,
ports, and software. VirusTotal and URLScan remain evidence sources, but their
historical passive-DNS and third-party page relationships are not
automatically treated as company-owned asset identity. Reputation, attribution,
hashes, and CVE candidates are also not converted into asset identity.

Every observation stored in `metadata.discovered_surfaces` records its source,
evidence summary, first and last observation time, and latest assessment ID.
The merge requires `manage_intel`, writes an audit event, refreshes the
normalized inventory graph and unified knowledge model, and preserves existing
values. A repeated observation updates provenance without creating duplicates.
Analysts must still confirm ownership: shared hosting, reverse DNS, certificate
names, and historical provider records can describe infrastructure not owned
by the organization.

### AI evidence boundary

The scanner always produces a deterministic summary. Optional AI analysis uses
the same provider readiness, TLP, cloud-policy, timeout, and explicit remote
processing acknowledgement controls as Threat Hunting AI. The model receives
bounded structured evidence and must separate observed services from provider
claims and inferred CVE candidates. Its output is advisory and always marked
for human review; it cannot run another scan, exploit a target, create evidence,
or assign a confirmed vulnerability.

### Analyst procedure

1. Import or create the asset with its exact IP addresses and domains.
2. Open **Threat Radar -> Asset Inventory**, search or filter the registry,
   then open the asset's dedicated intelligence page.
3. Select one inventory target and the configured passive providers.
4. Optionally enable **Run safe Nmap discovery** and/or **Run safe web posture
   checks**.
5. Keep **Add observed attack surfaces to this asset** selected to merge
   normalized discoveries with provenance, or clear it for a read-only
   assessment.
6. Optionally select an available AI provider. Remote providers require the
   explicit TLP:AMBER processing acknowledgement shown in the UI.
7. Confirm authorization for that exact inventory target.
8. Run the assessment and review provider status, inventory additions, web
   posture, open services, CVE candidates, caveats, and prioritized actions.
9. Validate ownership and product/version evidence in the authoritative CMDB,
   firewall, EDR, and vulnerability-management systems before triage.

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
2. Download the inventory table templates and populate the relevant product,
   component, dependency/SBOM, exposure, and deployed-asset records.
3. Create a signal from a CVE, KEV, PoC, supplier, package, hardware, customer,
   or internal telemetry lead.
4. Add sanitized evidence and product exposure context.
5. Review score factors, priority, and recommended actions.
6. Open the generated case and inspect the graph.
7. Create PSIRT, Threat Hunt, IR, Detection, or Legal workflow objects.
8. Generate a Flash Note, Product Impact Assessment, Threat Hunt Pack, PSIRT
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
| Asset Inventory | Review normalized assets and run inventory-bound passive/Nmap/AI exposure assessments. |
| Exposure Monitoring | Check provider readiness, build watch plans, classify breach/leak/prototype hits, and ingest sanitized hits into cases. |
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
- `GET /exposure/providers`
- `POST /exposure/plan`
- `POST /exposure/classify`
- `POST /exposure/ingest`
- `GET /spaces/{space_id}/assets`
- `GET /spaces/{space_id}/assets/{asset_id}/intelligence`
- `GET /asset-scanner/providers`
- `GET /spaces/{space_id}/assets/{asset_id}/scans`
- `POST /spaces/{space_id}/assets/{asset_id}/scans`
- `GET /spaces/{space_id}/assets/{asset_id}/scans/{scan_id}`
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

## Unified Intelligence Search

After reconciliation, allowlisted Threat Radar signals can be retrieved with
the rest of the Unified RAG corpus. The derived document preserves the source
signal's TLP and legal-sensitivity controls; restricted content cannot be sent
to an unapproved remote provider merely because it was indexed. Retrieval and
business-profile reranking prioritize review—they do not change a signal's
triage state or prove that an affected product is deployed or exploited. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md).
