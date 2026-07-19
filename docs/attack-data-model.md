# ATT&CK and STIX Data Model

AdversaryGraph stores ATT&CK/ATLAS data in two authoritative layers and builds
one derived retrieval layer:

1. **Normalized query tables** for fast UI/API workflows.
2. **Raw STIX preservation tables** for full object and relationship fidelity.
3. **Unified RAG documents/chunks** for governed cross-module retrieval. This is
   a rebuildable index, not a new source of truth.

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

normalized ATT&CK and other platform records
        |
        v
Celery RAG reconciliation
        |
        +--> rag_documents
        |       - source identity and version
        |       - canonical platform route
        |       - TLP/legal/sanitization policy
        |       - content checksum and freshness
        |
        +--> rag_chunks
                - generated PostgreSQL tsvector
                - optional pgvector embedding
                - embedding model/dimension/status
```

## Derived Unified RAG Tables

The cross-module intelligence assistant uses the following derived tables:

| Table | Purpose |
|---|---|
| `rag_documents` | One active or tombstoned normalized source document with provenance, policy labels, canonical route, source timestamps, and content hash |
| `rag_chunks` | Bounded source excerpts with generated full-text vectors and optional fixed-dimension embeddings |
| `rag_index_runs` | Queued/running/completed/degraded/failed reconciliation state, attempt count, heartbeat, counts, and bounded failure summary |
| `rag_assistance` | Sanitized generated-answer provenance: provider/model, retrieval mode, effective TLP, checksums, source references, structured output, warnings, and actor/time |
| `rag_navigator_proposals` | Persisted, expiring, checksum-bound ATT&CK advisory proposals and their explicit confirmation state; no named Navigator layer is saved |

Business profiles reuse the platform's stored sector-client profile records.
They are supplied as private per-request ranking context and are not converted
into global RAG documents or embeddings.

The corpus includes normalized ATT&CK techniques, groups, campaigns, actor
observations, IOCs, CVEs, stored analysis reports, Knowledge articles, Threat
Radar signals, Threat Hunting records, Evidence Graph nodes, and sanitized
Asset Surface records. Only allowlisted fields are copied. Raw STIX objects,
raw provider payloads, connector/authentication credential fields, and
unrestricted asset metadata are not embedded. Allowlisted narrative text is
not passed through a general DLP/secret redactor; `sanitized` here means
field-allowlisted and normalized, so operators must remove secrets and apply
correct TLP/legal markings before ingestion.

The `rag_documents` and `rag_chunks` rows can be recreated by reconciliation
from authoritative platform tables. Do not edit them as intelligence records.
Deleting an authoritative source causes its derived document to be tombstoned;
the retention job removes eligible tombstones and cascades to their chunks.

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

The derived RAG layer is optimized for:

- exact IOC, CVE, ATT&CK, campaign, and actor identifier lookup;
- PostgreSQL full-text discovery across normalized source excerpts;
- optional private vector similarity and reciprocal-rank fusion;
- bounded one-hop expansion over allowlisted relationship identifiers;
- source-routed citations and persisted, expiring Navigator advisory proposals
  that cannot save or mutate a named layer.

## Important Boundary

The normalized layer intentionally models the relationships AdversaryGraph uses
today. The raw STIX layer preserves the complete source graph, but not every raw
relationship is exposed as a first-class UI workflow yet.

RAG relationship expansion is likewise not a complete STIX graph traversal. It
is one bounded, non-recursive retrieval step over selected normalized
relationships. A returned edge is an investigation lead, not proof of
attribution, targeting, exploitation, or compromise. See
[Unified Intelligence RAG and MCP](unified-rag-and-mcp.md) for the retrieval and
governance contract.
