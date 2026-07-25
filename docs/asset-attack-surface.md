# Asset Attack Surface Mapping

Asset Attack Surface Mapping turns an asset inventory into an analyst-ready
attack surface matrix. It is designed for CMDB exports, cloud asset lists,
external scanner output, service inventories, and plain hostname/IP lists.

## Analyst Workflow

1. Open **Asset Surface** from the AdversaryGraph sidebar.
2. Upload a CSV, JSON, or TXT inventory, or paste the inventory directly.
3. Choose the AI provider. Local OpenAI-compatible models are supported.
4. Keep **Use AI enrichment** enabled when you want an executive summary,
   attack-path hypotheses, control gaps, assumptions, and validation steps.
5. Click **Analyze Attack Surface**.
6. AdversaryGraph creates a saved Asset Surface case for the analysis.
7. Review the matrix by risk and exposure, then open clickable ATT&CK technique
   tags in Navigator for detection planning.
8. Use **Add White Layer** to show all mapped candidates as a white comparison
   layer, **Open Matrix** to replace the current Navigator view with the
   asset-surface layer, **Save Layer** to store the layer server-side, or
   **Export JSON** for audit and handoff.
9. Reopen previous runs from **Saved Cases** when comparing inventories or
   refining an exposure review.

## Versioned Screenshots

Representative v4.1 screenshots captured from the local Docker-served UI are
listed in
[`assets/adversarygraph-v4.1-platform/manifest.md`](assets/adversarygraph-v4.1-platform/manifest.md).
They illustrate the workflow but are not release evidence for v6.5.

| Workflow | Screenshot |
|---|---|
| Discover launchers with Asset Surface and malware-analysis tools | ![Discover launchers](assets/adversarygraph-v4.1-platform/01-discover-launchers.png) |
| Asset Surface analysis result with risk, exposure, TTPs, and actions | ![Asset Surface analysis result](assets/adversarygraph-v4.1-platform/02-asset-surface-analysis.png) |
| Saved previous Asset Surface cases | ![Asset Surface history](assets/adversarygraph-v4.1-platform/03-asset-surface-history.png) |
| White Navigator layer for asset-inventory TTP candidates | ![Asset Surface white Navigator layer](assets/adversarygraph-v4.1-platform/04-asset-surface-white-matrix.png) |

## Supported Inventory Fields

For strict parsing, use the canonical CSV schema below. The engine still accepts
legacy aliases, but production imports should use this exact header:

```csv
asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags
```

Reference files:

- [`asset-inventory-template.csv`](../asset-inventory-template.csv) contains
  only the deployed-asset header.
- [`asset-inventory-example.csv`](../asset-inventory-example.csv) contains a
  realistic multi-asset example. The parser still accepts optional legacy
  product, supplier, and dependency columns for backwards compatibility.
- Threat Radar product-security workflows should use related product,
  component, SBOM dependency, and exposure tables instead of placing those
  fields in one asset CSV. See [`threat-radar.md`](threat-radar.md).
- [`taxonomy-and-label-convention.md`](taxonomy-and-label-convention.md)
  documents the shared `namespace:value` convention used across assets, TTPs,
  actors, CVEs, sectors, risk, technologies, products, suppliers,
  dependencies, and generic tags.

### Strict CSV Schema

| Column | Required | Format | Purpose |
|---|---:|---|---|
| `asset_id` | Yes | Stable CMDB/asset ID, unique per row | Persistent registry fingerprint fallback and case traceability |
| `name` | Yes | Human-readable asset, product, service, or supplier system name | Analyst display and text matching |
| `asset_type` | Yes | Examples: `web-app`, `api-gateway`, `database`, `identity`, `remote-access`, `ci-cd`, `saas`, `container-platform`, `backup-storage`, `file-server` | Risk scoring and TTP mapping |
| `environment` | Yes | `prod`, `stage`, `dev`, `test`, `corp`, `cloud`, `third-party`, or similar controlled value | Scope, prioritization, and tags |
| `owner` | Recommended | Team, service owner, business unit, or vendor owner | Workflow routing and accountability |
| `ip_addresses` | Recommended | One or more IPv4 addresses separated by `;` | IOC/asset correlation and exposure inference |
| `domains` | Recommended | One or more FQDNs/domains separated by `;` | IOC/report correlation and exposure inference |
| `ports` | Recommended | TCP/UDP listener numbers separated by `;` | Entry-point and TTP mapping |
| `technologies` | Yes | Platforms/services separated by `;`, for example `nginx;nodejs;postgresql` | Main technology labels used for CVE/report matching |
| `exposure` | Yes | One of `internet`, `internal`, `third-party`, `unknown` | Risk score, validation priority, and TTP mapping |
| `criticality` | Yes | One of `critical`, `high`, `medium`, `low` | Risk score and prioritization |
| `tags` | Recommended | Business/security tags separated by `;`, for example `pci;tier-0;customer-data` | Filtering, statistics, and analyst context |

Strict import rules:

- Use UTF-8 CSV with a header row.
- Use comma as the CSV delimiter.
- Use semicolon (`;`) inside multi-value fields. Quote the whole cell when it
  contains semicolons, commas, or spaces.
- Keep `asset_id` stable across uploads. This lets AdversaryGraph update the
  same asset instead of creating duplicate registry entries when domain/IP data
  changes.
- Use lowercase controlled values for `exposure` and `criticality`.
- Use stable taxonomy values. The parser normalizes labels into the shared
  `namespace:value` convention, for example `technology:nginx`,
  `product:globalprotect-vpn`, `supplier:microsoft`, `risk:critical`,
  `exposure:internet`, `ttp:T1190`, and `cve:CVE-2024-3400`.
- Do not put credentials, secrets, private keys, or exploit payloads in the
  inventory.

Example:

```csv
asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags
asset-0001,customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,"80;443;8443","nginx;nodejs;postgres",internet,critical,"customer-data;pci"
asset-0002,vpn-gateway,remote-access,prod,IT,198.51.100.20,vpn.example.com,"443;500;4500","vpn;sso;mfa",internet,high,"remote-access;identity-edge"
```

After upload, AdversaryGraph persists normalized assets in the Asset Registry
and immediately retrohunts existing CVEs, actor/TTP relationships, report
intake, and IOC context for relevance to these labels. New CVE and report
ingestion paths also re-run the same asset relevance check.

The parser accepts flexible field names. Common inputs include:

| Field meaning | Accepted examples |
|---|---|
| Asset name | `name`, `asset`, `hostname`, `host`, `fqdn`, `domain`, `ip` |
| Asset ID | `id`, `asset_id`, `cmdb_id` |
| Type | `type`, `asset_type`, `category`, `kind` |
| Environment | `environment`, `env`, `stage`, `account`, `subscription` |
| Owner | `owner`, `team`, `business_owner`, `service_owner` |
| IPs | `ip_addresses`, `ips`, `ip`, `ip_address`, `private_ip`, `public_ip` |
| Domains | `domains`, `domain`, `fqdn`, `dns`, `url`, `hostname` |
| Ports | `ports`, `open_ports`, `port`, `service_ports`, `listeners` |
| Technologies | `technologies`, `technology`, `services`, `software`, `product`, `stack` |
| Criticality | `criticality`, `business_criticality`, `tier`, `priority` |
| Tags | `tags`, `labels`, `business_unit`, `application` |

## Output Matrix

Each asset receives:

- Normalized asset metadata, IPs, domains, ports, technologies, owner, and
  criticality.
- Exposure classification: `internet`, `internal`, `third-party`, or `unknown`.
- Risk score and risk level based on exposure, criticality, remote
  administration, web/API services, databases, identity surfaces, containers,
  and remote-access indicators.
- Likely entry points such as HTTPS, SSH, RDP, SMB, database listeners, and DNS
  or web hostname exposure.
- ATT&CK technique candidates such as `T1190`, `T1021`, `T1005`, `T1078`, and
  `T1611`, rendered as clickable Navigator links.
- Priority actions and validation steps.
- Control gaps, detection ideas, and attack-path hypotheses. Baseline output
  always includes deterministic guidance; AI enrichment can add more specific
  business context and validation questions.
- Cross-asset findings, assumptions, and validation gaps when AI enrichment is
  enabled.

## Saved Cases

Every completed analysis is stored as an Asset Surface case in the backend. A
case preserves the full matrix JSON, summary, provider/model metadata, filename,
asset count, unique ATT&CK technique IDs, high/critical count, timestamps, and
validation gaps.

Saved cases can be reloaded from the left panel without re-uploading the
inventory. Deleting a case removes the saved matrix record, but it does not
delete any ATT&CK layer that was separately saved through **Save Layer**.

## ATT&CK Mapping Scope

The deterministic mapper links common asset-surface signals to relevant
ATT&CK Enterprise techniques. Examples:

| Surface signal | Example techniques |
|---|---|
| Internet-facing web/API surface | `T1190` Exploit Public-Facing Application |
| SSH/RDP/remote administration | `T1021` Remote Services |
| VPN, SSO, Citrix, or identity edge | `T1133` External Remote Services, `T1110` Brute Force |
| Active Directory, LDAP, Kerberos, SMB | `T1078` Valid Accounts, `T1558` Steal or Forge Kerberos Tickets |
| Databases and data stores | `T1005` Data from Local System |
| Cloud storage and backups | `T1530` Data from Cloud Storage, `T1552` Unsecured Credentials |
| Kubernetes, Docker, or container platforms | `T1611` Escape to Host |
| CI/CD and software-delivery systems | `T1195` Supply Chain Compromise, `T1608` Stage Capabilities |
| Legacy or unpatched technology signals | `T1068` Exploitation for Privilege Escalation |

These mappings are investigation leads. The analyst should accept, reject, or
refine them after validating real exposure and telemetry.

## AI Enrichment

The backend first builds a deterministic baseline matrix. AI enrichment then
receives only the parsed inventory and baseline risk matrix. The model is asked
to return strict JSON with executive summary, per-asset attack paths, control
gaps, validation steps, priority actions, assumptions, and validation gaps.

AI output is merged into the deterministic baseline instead of replacing it.
If the model fails or returns malformed JSON, the baseline matrix is still
returned.

## Validation Limits

The module does not prove that an asset is reachable or exploitable. Analysts
must validate:

- Current exposure with scanner, cloud firewall, security-group, and WAF data.
- Ownership and business criticality against authoritative CMDB records.
- Whether open ports are truly reachable from attacker-relevant networks.
- Patch level, authentication, logging, segmentation, and compensating controls.
- Whether suggested ATT&CK techniques are appropriate for the environment.

Use the matrix as a prioritization and investigation aid, not as an automated
vulnerability scanner or attribution mechanism.

## Unified Intelligence Search

After reconciliation, sanitized asset records are available to Unified RAG for
exact, full-text, and optional vector retrieval. Only allowlisted inventory
fields are indexed; asset-derived chunks are treated as local,
legal-sensitive context and are not eligible for unacknowledged cloud-provider
processing. Business-profile or relationship relevance is a triage lead, not
proof that an asset is exposed, vulnerable, targeted, or compromised. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md).
