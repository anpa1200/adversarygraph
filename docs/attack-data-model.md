# ATT&CK and STIX Data Model

AdversaryGraph stores ATT&CK/ATLAS data in two complementary layers:

1. **Normalized query tables** for fast UI/API workflows.
2. **Raw STIX preservation tables** for full object and relationship fidelity.

This keeps the product fast for matrix rendering, group similarity, campaign
comparison, and detection engineering while still preserving the source STIX
graph for audit, export, and future graph expansion.

## Normalized Tables

The normalized layer is the main runtime query model.

| Table | Purpose |
|---|---|
| `attack_versions` | Ingested ATT&CK/ATLAS domain and version metadata |
| `tactics` | ATT&CK tactic records |
| `techniques` | ATT&CK/ATLAS techniques and sub-techniques |
| `technique_tactics` | Technique-to-tactic mapping |
| `apt_groups` | ATT&CK intrusion-set / group profiles |
| `apt_group_techniques` | Group-to-technique `uses` relationships with usage description and references |
| `campaigns` | ATT&CK campaign / named operation records |
| `campaign_techniques` | Campaign-to-technique `uses` relationships |
| `apt_group_campaigns` | Campaign-to-group `attributed-to` relationships |

Selected STIX fields are stored directly on normalized rows. Examples include
`stix_id`, `attack_id`, `description`, `external_references`, `aliases`,
`platforms`, `data_sources`, and MITRE detection text.

## Raw STIX Preservation Tables

Starting in v5.1, AdversaryGraph also preserves raw STIX records.

| Table | Purpose |
|---|---|
| `stix_objects` | One row per non-relationship STIX object in an ingested bundle |
| `stix_relationships` | One row per STIX relationship object in an ingested bundle |

`stix_objects` stores:

- `stix_id`
- `stix_type`
- `attack_id` when present in MITRE external references
- `name`
- `domain`
- `version_id`
- `is_deprecated`
- `is_revoked`
- `raw` JSONB object

`stix_relationships` stores:

- `stix_id`
- `relationship_type`
- `source_stix_id`
- `target_stix_id`
- `description`
- `references`
- `domain`
- `version_id`
- `raw` JSONB relationship

Deprecated or revoked objects are preserved in `stix_objects` for source
fidelity, even when they are excluded from normalized runtime tables.

## Raw STIX API

The raw STIX layer is exposed through read-only API endpoints:

| Endpoint | Purpose |
|---|---|
| `GET /api/attack/stix/objects/{stix_id}` | Return one preserved raw STIX object |
| `GET /api/attack/stix/objects/{stix_id}/graph` | Return the object plus incoming and outgoing STIX relationships |
| `GET /api/attack/stix/relationships` | Filter raw STIX relationships by source, target, or relationship type |

Common query parameters:

- `domain`
- `version`
- `source_stix_id`
- `target_stix_id`
- `relationship_type`
- `limit`

## Ingest Flow

```text
MITRE STIX bundle
        |
        v
backend/app/services/attck/ingestor.py
        |
        +--> raw STIX preservation tables
        |       - stix_objects
        |       - stix_relationships
        |
        +--> normalized query tables
                - tactics
                - techniques
                - apt_groups
                - campaigns
                - relationship join tables
```

## Why Both Layers Exist

Normalized tables are optimized for:

- Navigator matrix rendering
- APT/group TTP overlap scoring
- Campaign comparison
- Technique search and detail pages
- Detection coverage and telemetry readiness workflows
- API performance

Raw STIX tables are optimized for:

- Full source auditability
- Preserving every STIX relationship type
- Reconstructing the original graph
- Future STIX export and graph traversal
- Reviewer validation of source fidelity

## Important Boundary

The normalized layer intentionally models the relationships AdversaryGraph uses
today. The raw STIX layer preserves the complete source graph, but not every raw
relationship is exposed as a first-class UI workflow yet.
