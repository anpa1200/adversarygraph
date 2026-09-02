#!/bin/sh
set -eu

ATLAS_REPOSITORY="${ATLAS_REPOSITORY:-https://github.com/anpa1200/anomaly-detection-atlas.git}"
ATLAS_SYNC_INTERVAL="${ATLAS_SYNC_INTERVAL:-0}"
WORK_DIR="/work/atlas"
OUTPUT_DIR="/output/anomaly-detection-atlas"

case "$ATLAS_SYNC_INTERVAL" in
  ''|*[!0-9]*)
    echo "ATLAS_SYNC_INTERVAL must be a non-negative integer" >&2
    exit 2
    ;;
esac

build_site() {
  cd "$WORK_DIR"
  node --test scripts/seo-date-manifest.test.cjs || return 1
  npm run build || return 1
  rm -rf "${OUTPUT_DIR}.next" || return 1
  mkdir -p "${OUTPUT_DIR}.next" || return 1
  cp -R build/. "${OUTPUT_DIR}.next/" || return 1
  rm -rf "$OUTPUT_DIR" || return 1
  mv "${OUTPUT_DIR}.next" "$OUTPUT_DIR" || return 1
  echo "Reference book published to $OUTPUT_DIR"
}

restore_seeded_seo_metadata() {
  mkdir -p "$WORK_DIR/seo" "$WORK_DIR/src/pages" "$WORK_DIR/src/theme/DocItem/Metadata"
  cp /seed/docusaurus.config.js "$WORK_DIR/docusaurus.config.js"
  cp /seed/seo-metadata-plugin.cjs "$WORK_DIR/seo-metadata-plugin.cjs"
  cp -R /seed/seo/. "$WORK_DIR/seo/"
  cp /seed/src/pages/index.js "$WORK_DIR/src/pages/index.js"
  cp /seed/src/theme/DocItem/Metadata/index.js "$WORK_DIR/src/theme/DocItem/Metadata/index.js"
}

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cp -R /seed/. "$WORK_DIR/"
node /usr/local/bin/generate-ttp-reference-index.mjs "$WORK_DIR"
node /usr/local/bin/apply-adversarygraph-docs-overlay.mjs "$WORK_DIR" /seed-overlay
restore_seeded_seo_metadata
build_site

if [ "$ATLAS_SYNC_INTERVAL" -eq 0 ]; then
  echo "Runtime Atlas synchronization is disabled; serving the scanned build until this container is replaced."
  while :; do
    sleep 86400
  done
fi

while [ "$ATLAS_SYNC_INTERVAL" -gt 0 ]; do
  sleep "$ATLAS_SYNC_INTERVAL"
  if sync-anomaly-atlas "" "$WORK_DIR"; then
    restore_seeded_seo_metadata
    cd "$WORK_DIR"
    if npm ci --ignore-scripts && build_site; then
      :
    else
      echo "Synchronized Atlas failed its SEO-bound production build; continuing to serve the last successful build" >&2
    fi
  else
    echo "Atlas synchronization failed; continuing to serve the last successful build" >&2
  fi
done
