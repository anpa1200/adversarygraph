#!/usr/bin/env sh
set -eu

BASE_URL="${ADVERSARYGRAPH_URL:-http://localhost:3000}"
MAX_WAIT_SECONDS="${SELFTEST_TIMEOUT:-120}"
SLEEP_SECONDS="${SELFTEST_INTERVAL:-3}"
SELFTEST_URL="${BASE_URL}/api/system/selftest"
HEALTH_URL="${BASE_URL}/api/health"

tmp_response="$(mktemp)"
tmp_err="$(mktemp)"
trap 'rm -f "$tmp_response" "$tmp_err"' EXIT

echo "AdversaryGraph self-test: waiting for ${SELFTEST_URL}"

elapsed=0
while [ "$elapsed" -le "$MAX_WAIT_SECONDS" ]; do
  http_code="$(curl -sS -o "$tmp_response" -w '%{http_code}' "$SELFTEST_URL" 2>"$tmp_err" || true)"
  if [ "$http_code" = "200" ]; then
    response="$(cat "$tmp_response")"
    printf '%s\n' "$response"
    status="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","error"))')"
    if [ "$status" = "ok" ]; then
      echo "AdversaryGraph self-test passed."
      exit 0
    fi
    echo "AdversaryGraph self-test returned status=${status}."
    exit 1
  fi

  if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    if health="$(curl -fsS "$HEALTH_URL" 2>"$tmp_err")"; then
      printf '%s\n' "$health"
      status="$(printf '%s' "$health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","error"))')"
      if [ "$status" = "ok" ]; then
        echo "AdversaryGraph health check passed. Full self-test is auth-protected."
        exit 0
      fi
      echo "AdversaryGraph health returned status=${status}." >&2
      exit 1
    fi
  fi

  err="$(cat "$tmp_err" 2>/dev/null || true)"
  echo "Self-test not ready after ${elapsed}s: HTTP ${http_code:-000} ${err:-connection failed}"
  sleep "$SLEEP_SECONDS"
  elapsed=$((elapsed + SLEEP_SECONDS))
done

echo "AdversaryGraph self-test timed out after ${MAX_WAIT_SECONDS}s." >&2
exit 1
