#!/usr/bin/env bash
set -euo pipefail

backup_dir="${ADVERSARYGRAPH_BACKUP_DIR:-./backups}"
mkdir -p "$backup_dir"

db_name="$(
  docker compose exec -T postgres sh -lc 'printf "%s" "${POSTGRES_DB:-adversarygraph}"'
)"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$backup_dir/adversarygraph-${db_name}-${stamp}.dump"

docker compose exec -T postgres sh -lc '
  set -eu
  pg_dump -U "${POSTGRES_USER:-ag_user}" -d "${POSTGRES_DB:-adversarygraph}" \
    --format=custom --compress=9 --no-owner --no-privileges
' > "$out"

sha256sum "$out" > "$out.sha256"
echo "Backup written: $out"
