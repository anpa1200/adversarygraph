#!/bin/sh
set -eu

SOURCE_DIR="${1:-}"
TARGET_DIR="${2:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)/anomaly_detection/docs-site}"
ATLAS_REPOSITORY="${ATLAS_REPOSITORY:-https://github.com/anpa1200/anomaly-detection-atlas.git}"
TEMP_DIR=""

cleanup() {
  if [ -n "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
  fi
}
trap cleanup EXIT

if [ -z "$SOURCE_DIR" ]; then
  LOCAL_SOURCE="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)/anomaly-detection-atlas"
  if [ -d "$LOCAL_SOURCE/docs" ]; then
    SOURCE_DIR="$LOCAL_SOURCE"
  else
    TEMP_DIR="$(mktemp -d)"
    git clone --depth 1 "$ATLAS_REPOSITORY" "$TEMP_DIR/source"
    SOURCE_DIR="$TEMP_DIR/source"
  fi
fi

for required in docs static src package.json package-lock.json docusaurus.config.js sidebars.js; do
  if [ ! -e "$SOURCE_DIR/$required" ]; then
    echo "Missing required atlas source: $SOURCE_DIR/$required" >&2
    exit 1
  fi
done

mkdir -p "$TARGET_DIR"
rsync -a --delete "$SOURCE_DIR/docs/" "$TARGET_DIR/docs/"
rsync -a --delete "$SOURCE_DIR/static/" "$TARGET_DIR/static/"
rsync -a --delete "$SOURCE_DIR/src/" "$TARGET_DIR/src/"
cp "$SOURCE_DIR/package.json" "$SOURCE_DIR/package-lock.json" \
  "$SOURCE_DIR/docusaurus.config.js" "$SOURCE_DIR/sidebars.js" "$TARGET_DIR/"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
node "$SCRIPT_DIR/generate-ttp-reference-index.mjs" "$TARGET_DIR"
OVERLAY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../anomaly_detection/docs-overlay" && pwd)"
node "$SCRIPT_DIR/apply-threatmapper-docs-overlay.mjs" "$TARGET_DIR" "$OVERLAY_DIR"

echo "Synchronized Anomaly Detection Atlas from $SOURCE_DIR to $TARGET_DIR"
