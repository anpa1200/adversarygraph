#!/bin/sh
set -eu

SOURCE_DIR="${1:-}"
TARGET_DIR="${2:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)/anomaly_detection/docs-site}"
ATLAS_REPOSITORY="${ATLAS_REPOSITORY:-https://github.com/anpa1200/anomaly-detection-atlas.git}"
# Pin to the reviewed source commit bundled in the current post-v6 snapshot to
# prevent supply-chain substitution of a moving branch. Set a different full
# SHA only after reviewing that revision and rebuilding the release image.
ATLAS_REPOSITORY_REF="${ATLAS_REPOSITORY_REF:-819995c5681668ffd0c6a4e0f86b170b5a6bbbac}"
ATLAS_PREFER_LOCAL_SOURCE="${ATLAS_PREFER_LOCAL_SOURCE:-true}"
TEMP_DIR=""
SOURCE_PROVENANCE="local"

case "$ATLAS_PREFER_LOCAL_SOURCE" in
  true|false) ;;
  *)
    echo "ATLAS_PREFER_LOCAL_SOURCE must be true or false" >&2
    exit 2
    ;;
esac

cleanup() {
  if [ -n "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
  fi
}
trap cleanup EXIT

if [ -z "$SOURCE_DIR" ]; then
  LOCAL_SOURCE="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)/anomaly-detection-atlas"
  if [ "$ATLAS_PREFER_LOCAL_SOURCE" = "true" ] && [ -d "$LOCAL_SOURCE/docs" ]; then
    SOURCE_DIR="$LOCAL_SOURCE"
  else
    if ! printf '%s\n' "$ATLAS_REPOSITORY_REF" | grep -Eq '^[a-f0-9]{40}$'; then
      echo "ATLAS_REPOSITORY_REF must be a full lowercase 40-character commit SHA" >&2
      exit 1
    fi
    TEMP_DIR="$(mktemp -d)"
    git clone --depth 1 "$ATLAS_REPOSITORY" "$TEMP_DIR/source"
    # Fetch the pinned commit and verify that checkout did not resolve to a
    # moving tag or branch.
    git -C "$TEMP_DIR/source" fetch --depth 1 origin "$ATLAS_REPOSITORY_REF"
    git -C "$TEMP_DIR/source" checkout --detach FETCH_HEAD
    RESOLVED_REF="$(git -C "$TEMP_DIR/source" rev-parse HEAD)"
    if [ "$RESOLVED_REF" != "$ATLAS_REPOSITORY_REF" ]; then
      echo "Atlas checkout mismatch: expected $ATLAS_REPOSITORY_REF, got $RESOLVED_REF" >&2
      exit 1
    fi
    echo "Checked out pinned ref $ATLAS_REPOSITORY_REF"
    SOURCE_DIR="$TEMP_DIR/source"
    SOURCE_PROVENANCE="remote"
  fi
fi

for required in docs static src package.json package-lock.json docusaurus.config.js sidebars.js; do
  if [ ! -e "$SOURCE_DIR/$required" ]; then
    echo "Missing required atlas source: $SOURCE_DIR/$required" >&2
    exit 1
  fi
done

if [ "$SOURCE_PROVENANCE" = "remote" ]; then
  SOURCE_REF_RECORD="$ATLAS_REPOSITORY_REF"
elif SOURCE_COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD 2>/dev/null)"; then
  if [ -n "$(git -C "$SOURCE_DIR" status --porcelain --untracked-files=normal)" ]; then
    SOURCE_REF_RECORD="local-dirty:$SOURCE_COMMIT"
  else
    SOURCE_REF_RECORD="local:$SOURCE_COMMIT"
  fi
else
  SOURCE_REF_RECORD="local-unversioned"
fi

mkdir -p "$TARGET_DIR"
rsync -a --delete "$SOURCE_DIR/docs/" "$TARGET_DIR/docs/"
rsync -a --delete "$SOURCE_DIR/static/" "$TARGET_DIR/static/"
rsync -a --delete "$SOURCE_DIR/src/" "$TARGET_DIR/src/"
cp "$SOURCE_DIR/package.json" "$SOURCE_DIR/package-lock.json" \
  "$SOURCE_DIR/docusaurus.config.js" "$SOURCE_DIR/sidebars.js" "$TARGET_DIR/"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
node "$SCRIPT_DIR/generate-ttp-reference-index.mjs" "$TARGET_DIR"
if [ -n "${ATLAS_OVERLAY_DIR:-}" ]; then
  OVERLAY_DIR="$ATLAS_OVERLAY_DIR"
elif [ -d /seed-overlay ]; then
  OVERLAY_DIR="/seed-overlay"
else
  OVERLAY_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../anomaly_detection/docs-overlay" && pwd)"
fi
node "$SCRIPT_DIR/apply-adversarygraph-docs-overlay.mjs" "$TARGET_DIR" "$OVERLAY_DIR"
printf '%s\n' "$SOURCE_REF_RECORD" > "$TARGET_DIR/.atlas-source-ref"

echo "Synchronized Anomaly Detection Atlas from $SOURCE_DIR to $TARGET_DIR ($SOURCE_REF_RECORD)"
