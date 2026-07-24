# EMB3D Integration

AdversaryGraph integrates MITRE EMB3D as an embedded-device threat-modeling layer over the saved Asset Surface registry.

## Workflow

1. Upload or paste asset inventory in **Asset Surface**.
2. Open **EMB3D** from the sidebar.
3. Review inferred EMB3D properties, applicable threats, and recommended mitigations per asset.

The integration uses the MITRE EMB3D STIX bundle and caches it locally when possible:

```text
https://emb3d.mitre.org/assets/emb3d-stix-2.0.1.json
```

No additional database tables are created. Reports are derived at request time from `asset_registry_items`.

The first successful request stores the validated bundle at
`/app/data/emb3d/emb3d-stix-2.0.1.json`. Later requests work from that cache and
do not require MITRE to be reachable. If no valid cache exists and the upstream
cannot be reached, the API returns HTTP `503` with a bounded operator message;
it does not fail with an unhandled server exception. Persist `/app/data` in
production so the cache survives container replacement.

## API

```http
GET /api/emb3d/catalog
GET /api/emb3d/assets/report?limit=200&offset=0
POST /api/emb3d/assets/assess
POST /api/emb3d/preview
```

The asset report maps saved assets to EMB3D properties, expands those properties to threats, and attaches available mitigations.

The complete generated platform endpoint inventory is maintained in
[API reference](api-reference.md). A running instance also serves the
interactive OpenAPI contract at `/docs`, `/redoc`, and `/openapi.json`.

## Mapping Notes

Property inference is deterministic and evidence-based. It uses asset fields such as type, exposure, ports, technologies, products, dependencies, tags, labels, and raw metadata. Each mapped property includes confidence and evidence strings so analysts can review the basis for the mapping.

EMB3D output should be treated as an assessment aid. It does not replace firmware review, architecture review, vulnerability analysis, or product-security validation.
