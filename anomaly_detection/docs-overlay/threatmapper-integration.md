# ThreatMapper Reference-Book Integration

ThreatMapper includes the Anomaly Detection Atlas as an autonomous Docker-served reference book.
The integration connects each ATT&CK technique in the matrix to the exact relevant paragraphs in
the activity, basic-rule, and statistical-anomaly catalogs.

## Open the Reference Book

With the Docker Compose stack running:

- ThreatMapper: [http://localhost:3000](http://localhost:3000)
- Reference book: [http://localhost:3001/anomaly-detection-atlas/](http://localhost:3001/anomaly-detection-atlas/)
- Generated TTP crosslink index: [http://localhost:3001/anomaly-detection-atlas/ttp-reference-index.json](http://localhost:3001/anomaly-detection-atlas/ttp-reference-index.json)

The **Reference Book** item in the ThreatMapper sidebar opens the complete documentation site.

## Exact TTP Crosslinks

Selecting a technique in the ThreatMapper matrix opens its detail panel with:

- the complete ATT&CK description;
- platforms, tactics, data sources, and detection notes;
- exact links to every matching paragraph or table row in the synchronized reference catalogs.

Links target stable generated anchors such as:

```text
/attack-basic-detection-rule-catalog/#ttp-t1059-001
/attack-statistical-anomaly-mapping/#ttp-t1030
```

When a technique appears in multiple relevant rows, ThreatMapper lists every matching paragraph.
Catalogs without a matching technique paragraph are not shown.

## Autonomous Synchronization

The `atlas-builder` Docker service:

1. Builds the embedded reference-book snapshot on startup.
2. Synchronizes with `https://github.com/anpa1200/anomaly-detection-atlas.git`.
3. Generates stable anchors and `ttp-reference-index.json`.
4. Rebuilds and atomically publishes the updated site.
5. Continues serving the last successful build if synchronization fails.

The default synchronization interval is one hour:

```env
ATLAS_SYNC_INTERVAL=3600
```

Set `ATLAS_SYNC_INTERVAL=0` to disable remote synchronization.

## Synchronize Local Changes

When `anomaly-detection-atlas` exists beside the ThreatMapper repository, synchronize unpushed
local documentation changes with:

```bash
make sync-atlas
docker compose up -d --build atlas-builder atlas-docs frontend
```

The synchronization process preserves this ThreatMapper-specific integration guide while replacing
the authoritative atlas catalogs and reports.

## Docker Services

| Service | Purpose |
|---|---|
| `atlas-builder` | Synchronizes, generates TTP anchors/index, and builds Docusaurus |
| `atlas-docs` | Serves the generated reference book and index through Nginx |
| `frontend` | Loads the index and renders exact paragraph links in technique panels |

Configuration:

```env
ATLAS_REPOSITORY=https://github.com/anpa1200/anomaly-detection-atlas.git
ATLAS_SYNC_INTERVAL=3600
REFERENCE_URL=http://localhost:3001/anomaly-detection-atlas
```
