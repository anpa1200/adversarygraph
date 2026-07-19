# Taxonomy and Label Convention

AdversaryGraph uses one strict naming convention for tags, labels, and
correlation keys. The goal is simple: a technology, sector, actor, CVE, IOC, or
TTP should be searchable and linkable the same way across reports, assets, CVEs,
IOCs, statistics, and attack-surface analysis.

## Canonical Format

Use lowercase namespaces followed by a colon:

```text
namespace:value
```

Values are normalized to lowercase slugs unless the value is a standard
identifier such as ATT&CK or CVE.

| Data type | Canonical examples | Notes |
|---|---|---|
| ATT&CK technique / TTP | `ttp:T1190`, `ttp:T1059.001` | ATT&CK IDs are uppercase and preserve sub-technique suffixes. |
| Threat actor / group | `actor:G0069` | ATT&CK group IDs are uppercase. |
| CVE | `cve:CVE-2024-3400` | CVE IDs are uppercase. |
| Sector | `sector:financial-services`, `sector:energy` | Used for sector intelligence and statistics. |
| Risk / criticality | `risk:critical`, `risk:high`, `risk:medium`, `risk:low` | Aliases such as `p0`, `sev1`, and `crit` normalize to `critical`. |
| Technology | `technology:nginx`, `technology:windows-server` | Used for asset, CVE, and report matching. |
| Product | `product:globalprotect-vpn`, `product:customer-portal` | Product and application names from inventories or reports. |
| Supplier / vendor | `supplier:palo-alto-networks`, `supplier:microsoft` | Used for supply-chain and vendor exposure analysis. |
| Dependency / component | `dependency:openssl`, `dependency:log4j` | Includes packages, libraries, plugins, and SBOM components. |
| Asset type | `asset_type:web-app`, `asset_type:identity` | Used by asset attack-surface scoring. |
| Environment | `environment:prod`, `environment:cloud` | Stable deployment context. |
| Exposure | `exposure:internet`, `exposure:internal`, `exposure:third-party` | Public/external/dmz normalize to `internet`. |
| Generic tag | `tag:pci`, `tag:customer-data` | Fallback for business or analyst labels. |

## Asset Inventory CSV

The Asset Surface module uses the same convention. Production imports should
use this exact CSV header:

```csv
asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,exposure,criticality,tags
```

Multi-value fields use semicolon separators. The parser normalizes each value
into the canonical label model:

```csv
asset-0001,customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,"80;443","nginx;nodejs",internet,critical,"customer-data;pci"
```

This row produces labels such as:

```text
asset_type:web-app
environment:prod
exposure:internet
risk:critical
technology:nginx
technology:nodejs
product:customer-portal
supplier:internal
dependency:npm
tag:customer-data
tag:pci
```

## Correlation Rules

- ATT&CK, CVE, actor, and IOC identifiers remain identifiers, not free text.
- Schema identifier fields such as `technique_ids`, `cve_ids`, and
  `actor_attack_id` keep canonical IDs for application compatibility; related
  tags and labels use the full `namespace:value` convention.
- Asset product, supplier, dependency, and technology values are normalized
  before CVE/report/actor retrohunt runs.
- Free-form labels are kept, but they are stored under `tag:*`.
- Existing source labels from external platforms remain source evidence; new
  normalized records should also add canonical tags where possible.
- Analysts should treat broad tags as context, not attribution proof.

## Migration and Enforcement

Existing databases can be checked and normalized from the admin/system API:

```text
GET  /api/system/taxonomy/status
POST /api/system/taxonomy/normalize
```

The self-test includes `taxonomy_normalized`; a degraded result means legacy
free-text tags still exist and should be migrated. The migration preserves
original source labels in raw metadata fields where practical. A user with
`manage_feeds` can select **Normalize Taxonomy** in the self-test popup or call
the `POST` endpoint above, then rerun the self-test and require `status=ok`.

All AI-assisted extraction prompts include the same taxonomy instruction block:
new reports, asset inventories, IOC enrichment, attack simulation planning, and
threat-radar signals must emit normalized labels such as `ttp:T1190`,
`cve:CVE-2024-3400`, `sector:energy`, `technology:nginx`, or `tag:kev`.

## Why This Matters

Strict labels make cross-dataset queries reliable:

- show assets with `technology:nginx` and `exposure:internet`;
- find CVEs with `cve:CVE-2024-3400` linked to `ttp:T1190`;
- compare actor overlap against assets tagged `sector:financial-services`;
- build statistics by `risk:critical`, `supplier:microsoft`, or
  `dependency:openssl`;
- retrohunt new reports against owned assets without relying on inconsistent
  free-text labels.

Normalized tags also improve Unified RAG exact retrieval and business-profile
reranking. They make cross-source matches explainable, but a shared sector,
region, technology, actor, or TTP label does not prove that an organization is
targeted or compromised. Treat the match as a lead and verify the cited source
and stored relationship. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md).
