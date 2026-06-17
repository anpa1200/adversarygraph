#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose up -d postgres
docker compose --profile tools run --rm db-apply-env-creds
docker compose up -d --force-recreate api worker beat frontend
curl -fsS http://localhost:8000/api/health || {
  echo
  echo "API health check failed. Check logs with: docker compose logs --tail=120 api"
  exit 1
}
echo
