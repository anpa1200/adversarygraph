#!/usr/bin/env bash
set -euo pipefail
umask 077

backup_dir="${ADVERSARYGRAPH_BACKUP_DIR:-./backups}"
mkdir -p "$backup_dir"

db_name="$(
  docker compose exec -T postgres sh -lc 'printf "%s" "${POSTGRES_DB:-adversarygraph}"'
)"
safe_db_name="${db_name//[^A-Za-z0-9_.-]/_}"
safe_db_name="${safe_db_name:0:80}"
safe_db_name="${safe_db_name:-adversarygraph}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$backup_dir/adversarygraph-${safe_db_name}-${stamp}.dump"
partial="${out}.partial"
checksum_partial="${out}.sha256.partial"
if [[ -e "$out" || -e "$out.sha256" ]]; then
  echo "Refusing to overwrite an existing backup for timestamp ${stamp}." >&2
  exit 1
fi
trap 'rm -f "$partial" "$checksum_partial"' EXIT

docker compose exec -T postgres sh -lc '
  set -eu
  pg_dump -U "${POSTGRES_USER:-ag_user}" -d "${POSTGRES_DB:-adversarygraph}" \
    --format=custom --compress=9 --no-owner --no-privileges
' > "$partial"

docker compose exec -T postgres sh -lc 'pg_restore --list >/dev/null' < "$partial"
mv "$partial" "$out"
sha256sum "$out" > "$checksum_partial"
mv "$checksum_partial" "$out.sha256"
trap - EXIT
echo "Backup written: $out"
