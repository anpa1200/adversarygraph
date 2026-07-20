#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose up -d postgres
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend

set +e
ADVERSARYGRAPH_URL="${ADVERSARYGRAPH_URL:-http://localhost:3000}" ./scripts/selftest.sh
selftest_status=$?
set -e

if [[ "$selftest_status" -eq 3 ]]; then
  echo "PostgreSQL credential rotation completed, but the full self-test is auth-protected." >&2
  echo "Complete the gate from an authenticated troubleshooting UI/API session." >&2
fi
exit "$selftest_status"
