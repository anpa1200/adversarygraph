#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mode="${1:---best-effort}"
if [[ "$mode" != "--best-effort" && "$mode" != "--strict" ]]; then
  echo "Usage: $0 [--best-effort|--strict]" >&2
  exit 2
fi

run_step() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

optional_step() {
  local tool="$1"
  local name="$2"
  shift 2
  if command -v "$tool" >/dev/null 2>&1; then
    run_step "$name" "$@"
  else
    printf '\n==> %s\nSKIP: %s is not installed.\n' "$name" "$tool"
  fi
}

if [[ "$mode" == "--strict" ]]; then
  missing_tools=()
  for tool in bandit pip-audit gitleaks trivy helm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing_tools+=("$tool")
    fi
  done
  if ((${#missing_tools[@]})); then
    printf 'Strict security validation requires missing tool(s): %s\n' "${missing_tools[*]}" >&2
    echo "Install every required scanner or use --best-effort for a non-release developer check." >&2
    exit 2
  fi
fi

scanner_step() {
  local tool="$1"
  local name="$2"
  shift 2
  if [[ "$mode" == "--strict" ]]; then
    run_step "$name" "$@"
  else
    optional_step "$tool" "$name" "$@"
  fi
}

scan_image() {
  local name="$1"
  local context="$2"
  local dockerfile="$3"
  local tag="adversarygraph-${name}:local-scan"
  run_step "Build container for scan (${name})" \
    docker build --pull --no-cache --file "$dockerfile" --tag "$tag" "$context"
  run_step "Container scan (${name})" \
    trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
      --skip-version-check --exit-code 1 "$tag"
}

scan_pinned_image() {
  local name="$1"
  local image_ref="$2"
  run_step "Pull pinned container (${name})" docker pull "$image_ref"
  run_step "Container scan (${name})" \
    trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
      --skip-version-check --exit-code 1 "$image_ref"
}

run_step "Backend lint / SAST baseline (ruff)" bash -lc 'cd backend && ruff check .'
scanner_step bandit "Backend SAST (bandit)" bash -lc 'cd backend && bandit -q -r app -x "tests,app/data" --severity-level medium --confidence-level medium'
scanner_step pip-audit "Backend dependency audit (pip-audit)" bash -lc 'cd backend && pip-audit -r requirements.txt'
run_step "Frontend dependency audit (npm audit)" bash -lc 'cd frontend && npm audit --audit-level=high'
run_step "Anomaly docs dependency audit (npm audit)" bash -lc 'cd anomaly_detection/docs-site && npm audit --audit-level=high'
run_step "Anomaly docs production build" bash -lc 'cd anomaly_detection/docs-site && npm run build'
scanner_step gitleaks "Secret scan (gitleaks)" gitleaks detect --source . --no-banner --redact
run_step "Docker Compose config validation" docker compose config --quiet
run_step "Development Docker Compose config validation" \
  docker compose -f docker-compose.yml -f docker-compose.dev.yml config --quiet
run_step "Private local-AI Docker Compose config validation" \
  docker compose -f docker-compose.yml -f docker-compose.local-ai.yml config --quiet
run_step "Production Docker Compose config validation" \
  docker compose -f docker-compose.yml -f docker-compose.prod.yml config --quiet
scanner_step helm "Helm lint" helm lint helm/adversarygraph
scanner_step helm "Helm render" bash -lc \
  'helm template adversarygraph helm/adversarygraph >/tmp/adversarygraph-security-rendered.yaml'
scanner_step helm "Helm shared-storage render" bash -lc \
  'helm template adversarygraph helm/adversarygraph --set "malwaregraph.accessModes={ReadWriteMany}" --set malwaregraph.storageClassName=shared-rwx --set "persistence.attckData.accessModes={ReadWriteMany}" --set persistence.attckData.storageClassName=shared-rwx --set "persistence.logs.accessModes={ReadWriteMany}" --set persistence.logs.storageClassName=shared-rwx >/tmp/adversarygraph-security-shared-storage.yaml'
scanner_step helm "Helm production render" bash -lc \
  'helm template adversarygraph helm/adversarygraph --set-string config.productionMode=true --set postgresql.image.repository=example.invalid/adversarygraph-postgres --set-string postgresql.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 --set-string image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 --set-string frontend.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 --set-string malwaregraph.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 >/tmp/adversarygraph-security-production.yaml'

if command -v trivy >/dev/null 2>&1; then
  scan_image postgres . docker/postgres/Dockerfile
  scan_image backend backend backend/Dockerfile
  scan_image frontend frontend frontend/Dockerfile
  scan_image malwaregraph . docker/malwaregraph/Dockerfile
  scan_image attack-lab-web . docker/attack-lab-web/Dockerfile
  scan_image attack-lab-endpoint . docker/attack-lab-endpoint/Dockerfile
  scan_image anomaly-docs . anomaly_detection/docs-site/Dockerfile
  scan_pinned_image redis "${REDIS_IMAGE:-redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99}"
  scan_pinned_image busybox-tools "${BUSYBOX_IMAGE:-busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662}"
  scan_pinned_image anomaly-docs-nginx "${NGINX_DOCS_IMAGE:-nginx:stable-alpine@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46}"
else
  printf '\n==> Container image scans\nSKIP: trivy is not installed.\n'
fi

printf '\nSecurity validation completed (%s).\n' "${mode#--}"
