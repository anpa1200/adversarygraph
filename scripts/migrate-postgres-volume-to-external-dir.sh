#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$PWD")}"
SOURCE_VOLUME="${1:-${PROJECT_NAME}_pg_data}"
TARGET_DIR="${ADVERSARYGRAPH_DB_DIR:-./data/postgres}"
if [[ "$TARGET_DIR" = /* ]]; then
  TARGET_MOUNT="$TARGET_DIR"
else
  TARGET_MOUNT="$(pwd)/$TARGET_DIR"
fi

if ! docker volume inspect "$SOURCE_VOLUME" >/dev/null 2>&1; then
  echo "Source Docker volume not found: $SOURCE_VOLUME" >&2
  echo "Nothing to migrate. New deployments will create $TARGET_DIR automatically." >&2
  exit 0
fi

mkdir -p "$TARGET_DIR"

if find "$TARGET_DIR" -mindepth 1 -maxdepth 1 | grep -q .; then
  echo "Target directory is not empty: $TARGET_DIR" >&2
  echo "Refusing to overwrite existing external DB data." >&2
  exit 1
fi

echo "Stopping Postgres before copying data..."
docker compose stop postgres >/dev/null 2>&1 || true

echo "Copying $SOURCE_VOLUME -> $TARGET_DIR"
docker run --rm \
  -v "$SOURCE_VOLUME:/from:ro" \
  -v "$TARGET_MOUNT:/to" \
  alpine:3.20 \
  sh -c 'cp -a /from/. /to/ && chown -R 999:999 /to'

echo "Migration complete. Start services with: docker compose up -d"
