# AdversaryGraph Reference-Book Integration

AdversaryGraph includes the Anomaly Detection Atlas as a Docker-served reference book.
The integration connects each ATT&CK technique in the matrix to the exact relevant paragraphs in
the activity, basic-rule, and statistical-anomaly catalogs.

## Open the Reference Book

With the Docker Compose stack running:

- AdversaryGraph: [http://localhost:3000](http://localhost:3000)
- Reference book: [http://localhost:3001/anomaly-detection-atlas/](http://localhost:3001/anomaly-detection-atlas/)
- Generated TTP crosslink index: [http://localhost:3001/anomaly-detection-atlas/ttp-reference-index.json](http://localhost:3001/anomaly-detection-atlas/ttp-reference-index.json)

The **Reference Book** item in the AdversaryGraph sidebar opens the complete documentation site.

## Exact TTP Crosslinks

Selecting a technique in the AdversaryGraph matrix opens its detail panel with:

- the complete ATT&CK description;
- platforms, tactics, data sources, and detection notes;
- exact links to every matching paragraph or table row in the synchronized reference catalogs.

Links target stable generated anchors such as:

```text
/attack-basic-detection-rule-catalog/#ttp-t1059-001
/attack-statistical-anomaly-mapping/#ttp-t1030
```

When a technique appears in multiple relevant rows, AdversaryGraph lists every matching paragraph.
Catalogs without a matching technique paragraph are not shown.

## Snapshot Publication and Optional Synchronization

The `atlas-builder` Docker service:

1. Builds the reviewed reference-book snapshot embedded in its image.
2. Generates stable anchors and `ttp-reference-index.json`.
3. Atomically publishes the generated site to the serving volume.
4. Keeps that scanned snapshot unchanged until the container is replaced when
   runtime synchronization is disabled.

Runtime synchronization is disabled by default and is required to remain
disabled by the production preflight:

```env
ATLAS_SYNC_INTERVAL=0
```

Publish a reviewed Atlas source change before building the image:

```bash
# Also update ATLAS_REPOSITORY_REF in .env.example to the same full SHA.
ATLAS_REPOSITORY_REF=<reviewed-full-40-character-commit-sha> make sync-atlas-release
cd anomaly_detection/docs-site
npm ci
npm audit --audit-level=high
npm run build
```

`sync-atlas-release` deliberately ignores any sibling working tree, fetches
only the configured commit, applies the AdversaryGraph overlay, and records the
commit in `.atlas-source-ref`. Review the synchronized source and lockfile diff,
then run the complete release gate. The version-consistency check rejects a
snapshot whose recorded commit differs from `.env.example`. Rebuild, scan, and
release a new image; changing only a runtime environment variable does not
change the snapshot embedded in an existing image.

A positive runtime interval is a development-only convenience: it fetches only
the configured full commit SHA and reruns dependency installation, so it does
not share the production image's retained scan evidence.

## Synchronize Local Changes

When `anomaly-detection-atlas` exists beside the AdversaryGraph repository,
synchronize unpushed local documentation changes for development with:

```bash
make sync-atlas
docker compose up -d --build atlas-builder atlas-docs frontend
```

The development command prefers that sibling working tree and records
`local:<commit>` or `local-dirty:<commit>` provenance. Such a snapshot is
intentionally rejected by the release gate. The synchronization process
preserves this AdversaryGraph-specific integration guide while replacing the
authoritative Atlas catalogs and reports.

## Docker Services

| Service | Purpose |
|---|---|
| `atlas-builder` | Builds the pinned snapshot, generates TTP anchors/index, and optionally performs development-only runtime sync |
| `atlas-docs` | Serves the generated reference book and index through Nginx |
| `frontend` | Loads the index and renders exact paragraph links in technique panels |

Configuration:

```env
ATLAS_REPOSITORY=https://github.com/anpa1200/anomaly-detection-atlas.git
ATLAS_REPOSITORY_REF=<reviewed-full-40-character-commit-sha>
ATLAS_SYNC_INTERVAL=0
REFERENCE_URL=http://localhost:3001/anomaly-detection-atlas
```
