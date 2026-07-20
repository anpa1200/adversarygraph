#!/usr/bin/env sh
set -eu

BASE_URL="${ADVERSARYGRAPH_URL:-http://localhost:3000}"
MAX_WAIT_SECONDS="${SELFTEST_TIMEOUT:-900}"
SLEEP_SECONDS="${SELFTEST_INTERVAL:-3}"
STARTUP_URL="${BASE_URL}/api/system/startup"
SELFTEST_URL="${BASE_URL}/api/system/selftest"
READINESS_URL="${BASE_URL}/api/ready"

case "$MAX_WAIT_SECONDS" in
  ''|*[!0-9]*)
    echo "SELFTEST_TIMEOUT must be a non-negative integer." >&2
    exit 2
    ;;
esac
case "$SLEEP_SECONDS" in
  ''|0|*[!0-9]*)
    echo "SELFTEST_INTERVAL must be a positive integer." >&2
    exit 2
    ;;
esac

tmp_response="$(mktemp)"
tmp_err="$(mktemp)"
tmp_startup="$(mktemp)"
trap 'rm -f "$tmp_response" "$tmp_err" "$tmp_startup"' EXIT

echo "AdversaryGraph self-test: waiting for ${SELFTEST_URL}"

elapsed=0
while [ "$elapsed" -le "$MAX_WAIT_SECONDS" ]; do
  startup_http_code="$(curl -sS -o "$tmp_startup" -w '%{http_code}' "$STARTUP_URL" 2>"$tmp_err" || true)"
  if [ "$startup_http_code" = "200" ]; then
    startup_response="$(cat "$tmp_startup")"
    startup_status="$(printf '%s' "$startup_response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","error"))' 2>/dev/null)" || startup_status="error"
    if [ "$startup_status" = "starting" ]; then
      echo "Reference ingestion is still running after ${elapsed}s; waiting before self-test."
      sleep "$SLEEP_SECONDS"
      elapsed=$((elapsed + SLEEP_SECONDS))
      continue
    fi
    if [ "$startup_status" = "degraded" ]; then
      printf '%s\n' "$startup_response" >&2
      echo "AdversaryGraph startup is degraded; reference ingestion failed." >&2
      exit 1
    fi
  fi

  http_code="$(curl -sS -o "$tmp_response" -w '%{http_code}' "$SELFTEST_URL" 2>"$tmp_err" || true)"
  if [ "$http_code" = "200" ]; then
    response="$(cat "$tmp_response")"
    printf '%s\n' "$response"
    status="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","error"))' 2>/dev/null)" || status="error"
    if [ "$status" = "ok" ]; then
      echo "AdversaryGraph self-test passed."
      exit 0
    fi
    echo "AdversaryGraph self-test returned status=${status}." >&2
    exit 1
  fi

  if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
    if readiness="$(curl -fsS "$READINESS_URL" 2>"$tmp_err")"; then
      printf '%s\n' "$readiness"
      status="$(printf '%s' "$readiness" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","error"))' 2>/dev/null)" || status="error"
      if [ "$status" = "ready" ]; then
        echo "AdversaryGraph readiness check passed, but the full self-test is auth-protected." >&2
        echo "Readiness alone is not a passing self-test; run an authenticated full self-test." >&2
        exit 3
      fi
      echo "AdversaryGraph readiness returned status=${status}." >&2
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
