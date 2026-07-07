# Product Security Inventory Example

This directory contains a complete multi-file inventory example for AdversaryGraph Threat Radar and Asset Surface workflows.

Upload these files together from `Asset Surface` using **Upload inventory files**, then choose a target Company Space if you want the parsed assets to be stored as monitored company inventory.

## Files

- `asset_inventory.csv` - deployed assets, services, labs, management networks, and telemetry tags.
- `product_inventory.csv` - product catalog with PSIRT, engineering, support status, deployment model, and criticality.
- `component_inventory.csv` - product-to-component map for drivers, firmware, containers, libraries, BMC, DPU/NIC firmware, SDKs, and management interfaces.
- `dependency_sbom_inventory.csv` - component-to-dependency/SBOM map with PURL, CPE, supplier, license, runtime/build flags, and customer-shipped flags.
- `product_exposure_inventory.csv` - exploitability and exposure context: deployment model, trust boundary, customer exposure, telemetry sources, detection availability, mitigation availability, and patch status.

## Relationship Keys

- `product_inventory.product_id` joins to `component_inventory.product_id`.
- `component_inventory.component_id` joins to `dependency_sbom_inventory.component_id`.
- `product_exposure_inventory.product_id` and `product_exposure_inventory.component_id` join exposure context to the product/component graph.
- `asset_inventory.tags` includes product/security labels that help AdversaryGraph correlate deployed surfaces to products, telemetry sources, and owners.

## Intended Product Security Use Cases

- CVE-to-product/component impact analysis.
- Exploitability review across firmware, driver, SDK, container, and management surfaces.
- SBOM and dependency risk triage.
- Customer exposure and patch prioritization.
- PSIRT ownership routing.
- Threat actor/CVE/report relevance matching against owned products and deployed assets.

## Notes

The data is fictional but structured to look like real product security inventory. Do not place secrets, customer PII, private keys, exploit payloads, or proprietary source code into inventory files.
