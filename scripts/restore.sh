#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 ./backups/adversarygraph-<db>-<timestamp>.dump" >&2
  exit 2
fi

backup_file="$1"
if [[ ! -s "$backup_file" ]]; then
  echo "Backup file is missing or empty: $backup_file" >&2
  exit 1
fi

if [[ -f "$backup_file.sha256" ]]; then
  sha256sum -c "$backup_file.sha256"
fi

compose_files=(-f docker-compose.yml)
if [[ -f docker-compose.prod.yml ]]; then
  compose_files+=(-f docker-compose.prod.yml)
fi

backup_abs="$(realpath "$backup_file")"
backup_base="$(basename "$backup_file")"

cat <<'WARN'
WARNING: restore is destructive for the target database.
It drops and recreates the public schema before pg_restore.
Set CONFIRM_RESTORE=yes to continue.
WARN

if [[ "${CONFIRM_RESTORE:-}" != "yes" ]]; then
  echo "Restore cancelled. Re-run with CONFIRM_RESTORE=yes." >&2
  exit 1
fi

docker compose "${compose_files[@]}" up -d postgres

compose_project="${COMPOSE_PROJECT_NAME:-$(basename "$PWD")}"

docker run --rm \
  --network "${compose_project}_default" \
  -e PGPASSWORD="${DB_PASS:?DB_PASS is required}" \
  -e DB_USER="${DB_USER:-ag_user}" \
  -e DB_NAME="${DB_NAME:-adversarygraph}" \
  -v "$backup_abs:/restore/$backup_base:ro" \
  postgres:16-alpine \
  sh -lc '
    set -eu
    until pg_isready -h postgres -U "${DB_USER:-ag_user}" -d "${DB_NAME:-adversarygraph}"; do sleep 2; done
    psql -h postgres -U "${DB_USER:-ag_user}" -d "${DB_NAME:-adversarygraph}" -v ON_ERROR_STOP=1 \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
    pg_restore -h postgres -U "${DB_USER:-ag_user}" -d "${DB_NAME:-adversarygraph}" \
      --clean --if-exists --no-owner --no-privileges "/restore/'"$backup_base"'"
  '

docker compose "${compose_files[@]}" up -d --force-recreate api worker beat frontend
echo "Restore complete. Run ./scripts/selftest.sh and inspect /observability."
