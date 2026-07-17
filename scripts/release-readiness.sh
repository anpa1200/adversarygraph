#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mode="${1:---full}"
if [[ "$mode" != "--quick" && "$mode" != "--full" ]]; then
  echo "Usage: $0 [--quick|--full]" >&2
  exit 2
fi

run_step() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

run_step "Release metadata" ./scripts/check-version-consistency.sh
run_step "Patch hygiene" git diff --check
run_step "Default Compose configuration" docker compose config --quiet
run_step "Production Compose configuration" \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
run_step "Frontend lint" bash -lc 'cd frontend && npm run lint'
run_step "Frontend production build" bash -lc 'cd frontend && npm run build'
run_step "Frontend browser smoke tests" bash -lc 'cd frontend && npm run test:e2e'
run_step "Backend lint" bash -lc 'cd backend && ruff check .'

if [[ "$mode" == "--full" ]]; then
  run_step "Backend tests" bash -lc \
    'cd backend && PYTHONPATH=. DB_PASS=ci_test_password LOG_DIR=/tmp/adversarygraph-test-logs python -m pytest -q'
  run_step "Security validation" ./scripts/security-scan.sh
fi

printf '\nRelease readiness checks passed (%s).\n' "${mode#--}"
