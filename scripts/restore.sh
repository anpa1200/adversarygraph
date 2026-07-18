#!/usr/bin/env bash
set -euo pipefail
umask 077

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
  expected_checksum="$(awk 'NF { print $1; exit }' "$backup_file.sha256")"
  if [[ ! "$expected_checksum" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "Invalid SHA-256 checksum file: $backup_file.sha256" >&2
    exit 1
  fi
  IFS=' ' read -r actual_checksum _ < <(sha256sum "$backup_file")
  actual_checksum="${actual_checksum#\\}"
  if [[ "$actual_checksum" != "$expected_checksum" ]]; then
    echo "Backup checksum verification failed: $backup_file" >&2
    exit 1
  fi
  echo "Backup checksum verified: $backup_file"
elif [[ "${ALLOW_UNVERIFIED_BACKUP:-}" != "yes" ]]; then
  echo "Backup checksum is missing: $backup_file.sha256" >&2
  echo "Set ALLOW_UNVERIFIED_BACKUP=yes only for a separately verified legacy archive." >&2
  exit 1
fi

compose_files=(-f docker-compose.yml)
if [[ -f docker-compose.prod.yml ]]; then
  compose_files+=(-f docker-compose.prod.yml)
fi

# Restore uses the production overlay and must therefore consume the same
# validated immutable image set as a normal production rollout. Fail before
# the destructive confirmation if credentials or image references are unsafe.
"$(dirname "$0")/validate-production-env.sh"

cat <<'WARN'
WARNING: restore is destructive for the target database.
It validates the archive, stops application writers, then drops and recreates
the public schema before pg_restore.
Set CONFIRM_RESTORE=yes to continue.
WARN

if [[ "${CONFIRM_RESTORE:-}" != "yes" ]]; then
  echo "Restore cancelled. Re-run with CONFIRM_RESTORE=yes." >&2
  exit 1
fi

docker compose "${compose_files[@]}" up -d --no-build postgres

docker compose "${compose_files[@]}" exec -T postgres sh -lc '
  set -eu
  until pg_isready -U "${POSTGRES_USER:-ag_user}" -d "${POSTGRES_DB:-adversarygraph}"; do sleep 2; done
'

docker compose "${compose_files[@]}" exec -T postgres \
  sh -lc 'pg_restore --list >/dev/null' < "$backup_file"
echo "Backup archive structure verified: $backup_file"

docker compose "${compose_files[@]}" stop api worker beat frontend
restore_started=yes
restore_complete=no
restore_failure_notice() {
  exit_code=$?
  trap - EXIT
  if [[ "$exit_code" -ne 0 && "$restore_started" == "yes" && "$restore_complete" != "yes" ]]; then
    echo "Restore failed after application writers were stopped." >&2
    echo "API, worker, beat, and frontend remain stopped to prevent writes to a partial database." >&2
    echo "Correct the failure and restore a verified backup before restarting them." >&2
  fi
  exit "$exit_code"
}
trap restore_failure_notice EXIT

docker compose "${compose_files[@]}" exec -T postgres sh -lc '
    set -eu
    export PGPASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}"
    psql -U "${POSTGRES_USER:-ag_user}" -d "${POSTGRES_DB:-adversarygraph}" -v ON_ERROR_STOP=1 \
      -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
    pg_restore -U "${POSTGRES_USER:-ag_user}" -d "${POSTGRES_DB:-adversarygraph}" \
      --clean --if-exists --no-owner --no-privileges
  ' < "$backup_file"

docker compose "${compose_files[@]}" up -d --no-build --force-recreate api worker beat frontend
restore_complete=yes
trap - EXIT
echo "Restore complete. Run ./scripts/selftest.sh and inspect /observability."
