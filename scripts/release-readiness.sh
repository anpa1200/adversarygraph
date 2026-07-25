#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mode="${1:---full}"
if [[ "$mode" != "--quick" && "$mode" != "--full" ]]; then
  echo "Usage: $0 [--quick|--full]" >&2
  exit 2
fi

select_backend_python() {
  local candidate

  if [[ -n "${PYTHON_BIN:-}" ]]; then
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
      echo "PYTHON_BIN is not executable or is not on PATH: $PYTHON_BIN" >&2
      return 1
    fi
    if ! "$PYTHON_BIN" -c \
      'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'; then
      echo "Backend release validation requires Python 3.12; PYTHON_BIN reports: $("$PYTHON_BIN" --version 2>&1)" >&2
      return 1
    fi
    BACKEND_PYTHON="$PYTHON_BIN"
    return
  fi

  for candidate in python3.12 python; do
    if command -v "$candidate" >/dev/null 2>&1 && \
      "$candidate" -c \
        'import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 12) else 1)'; then
      BACKEND_PYTHON="$candidate"
      return
    fi
  done

  echo "Backend release validation requires Python 3.12. Install it or set PYTHON_BIN to its executable." >&2
  return 1
}

run_backend_tests() (
  cd backend
  PYTHONPATH=. \
    DB_PASS=ci_test_password \
    LOG_DIR=/tmp/adversarygraph-test-logs \
    "$BACKEND_PYTHON" -m pytest -q
)

run_backend_lint() (
  cd backend
  "$BACKEND_PYTHON" -m ruff check .
)

check_patch_hygiene() {
  local file output status
  git diff HEAD --check
  while IFS= read -r -d '' file; do
    set +e
    output="$(git diff --no-index --check /dev/null "$file" 2>&1)"
    status=$?
    set -e
    if [[ $status -eq 3 ]]; then
      printf '%s\n' "$output" >&2
      return 1
    fi
    if [[ $status -ne 0 && $status -ne 1 ]]; then
      printf 'Could not check untracked file %s (git exit %s).\n' "$file" "$status" >&2
      return 1
    fi
  done < <(git ls-files --others --exclude-standard -z)
}

run_step() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

run_step "Release metadata" ./scripts/check-version-consistency.sh
select_backend_python
run_step "Backend/OpenAPI/frontend API contract" ./scripts/check-api-contracts.py
run_step "Governed module documentation coverage" \
  "$BACKEND_PYTHON" scripts/check-module-docs.py
run_step "Patch hygiene (tracked, staged, and untracked)" check_patch_hygiene
run_step "Release tag ruleset verifier tests" \
  "$BACKEND_PYTHON" -m unittest discover -s scripts/tests -p 'test_*.py' -q
run_step "Default Compose configuration" docker compose config --quiet
run_step "Development Compose configuration" \
  docker compose -f docker-compose.yml -f docker-compose.dev.yml config --quiet
run_step "Private local-AI Compose configuration" \
  docker compose -f docker-compose.yml -f docker-compose.local-ai.yml config --quiet
run_step "Production environment policy" ./scripts/validate-production-env.sh
run_step "Production Compose configuration" \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
run_step "Frontend lint" bash -lc 'cd frontend && npm run lint'
run_step "Frontend production build" bash -lc 'cd frontend && npm run build'
run_step "Frontend browser smoke tests" bash -lc 'cd frontend && npm run test:e2e'
run_step "Anomaly documentation production build" bash -lc 'cd anomaly_detection/docs-site && npm run build'
run_step "Backend lint (Python 3.12: $BACKEND_PYTHON)" run_backend_lint

if [[ "$mode" == "--full" ]]; then
  run_step "Backend tests (Python 3.12: $BACKEND_PYTHON)" run_backend_tests
  run_step "Strict security validation" ./scripts/security-scan.sh --strict
fi

printf '\nRelease readiness checks passed (%s).\n' "${mode#--}"
