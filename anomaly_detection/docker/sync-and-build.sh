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
  npm run build
  rm -rf "${OUTPUT_DIR}.next"
  mkdir -p "${OUTPUT_DIR}.next"
  cp -R build/. "${OUTPUT_DIR}.next/"
  rm -rf "$OUTPUT_DIR"
  mv "${OUTPUT_DIR}.next" "$OUTPUT_DIR"
  echo "Reference book published to $OUTPUT_DIR"
}

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cp -R /seed/. "$WORK_DIR/"
node /usr/local/bin/generate-ttp-reference-index.mjs "$WORK_DIR"
node /usr/local/bin/apply-adversarygraph-docs-overlay.mjs "$WORK_DIR" /seed-overlay
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
    cd "$WORK_DIR"
    npm ci --ignore-scripts
    build_site
  else
    echo "Atlas synchronization failed; continuing to serve the last successful build" >&2
  fi
done
