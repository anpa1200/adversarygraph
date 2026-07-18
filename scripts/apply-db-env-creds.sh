#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose up -d postgres
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend
ADVERSARYGRAPH_URL="${ADVERSARYGRAPH_URL:-http://localhost:3000}" ./scripts/selftest.sh
