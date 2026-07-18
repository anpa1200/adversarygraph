#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

env_file="${ADVERSARYGRAPH_ENV_FILE:-.env}"
if [[ "${1:-}" == "--env-file" ]]; then
  if [[ $# -ne 2 ]]; then
    echo "Usage: $0 [--env-file PATH]" >&2
    exit 2
  fi
  env_file="$2"
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--env-file PATH]" >&2
  exit 2
fi

file_value() {
  local key="$1"
  local line value=""
  [[ -f "$env_file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == "$key="* ]] || continue
    value="${line#*=}"
  done < "$env_file"

  # Docker Compose accepts simple quoted dotenv values. This parser
  # intentionally does not execute shell syntax or interpolate variables.
  if [[ ${#value} -ge 2 ]]; then
    if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf '%s' "$value"
}

effective_value() {
  local key="$1"
  local default_value="${2:-}"
  if [[ -v "$key" ]]; then
    printf '%s' "${!key}"
  elif [[ -f "$env_file" ]] && grep -q "^${key}=" "$env_file"; then
    file_value "$key"
  else
    printf '%s' "$default_value"
  fi
}

normalize() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]'
}

is_placeholder() {
  local normalized
  normalized="$(normalize "$1")"
  case "$normalized" in
    changeme|changemestronglocalpassword|changemestrongredispassword|\
    replacewithastrongpassword|replacewithastrongtemporarypassword|\
    password|redispassword|dbpassword|secret|example)
      return 0
      ;;
  esac
  return 1
}

errors=()
db_pass="$(effective_value DB_PASS)"
redis_password="$(effective_value REDIS_PASSWORD)"
rate_limit_proxy_secret="$(effective_value RATE_LIMIT_PROXY_SECRET)"
cors_origins="$(effective_value CORS_ALLOWED_ORIGINS)"
auth_enabled="$(normalize "$(effective_value AUTH_ENABLED true)")"
secure_cookies="$(normalize "$(effective_value SECURE_COOKIES true)")"
bootstrap_password="$(effective_value AUTH_BOOTSTRAP_ADMIN_PASSWORD)"
proxy_secret="$(effective_value PROXY_SECRET)"
existing_admin_confirmed="$(normalize "$(effective_value AUTH_EXISTING_ADMIN_CONFIRMED false)")"

for key in DB_PASS REDIS_PASSWORD RATE_LIMIT_PROXY_SECRET; do
  value="$(effective_value "$key")"
  if [[ -z "$value" ]]; then
    errors+=("$key is required")
  elif is_placeholder "$value"; then
    errors+=("$key still contains a known placeholder")
  elif ((${#value} < 24)); then
    errors+=("$key must be at least 24 characters")
  fi
done

if [[ -n "$rate_limit_proxy_secret" && ! "$rate_limit_proxy_secret" =~ ^[A-Za-z0-9_-]+$ ]]; then
  errors+=("RATE_LIMIT_PROXY_SECRET may contain only letters, digits, underscore, and hyphen")
fi

if [[ -n "$redis_password" && ! "$redis_password" =~ ^[A-Za-z0-9_-]+$ ]]; then
  errors+=("REDIS_PASSWORD may contain only letters, digits, underscore, and hyphen because it is embedded in a Redis URL")
fi

if [[ -n "$db_pass" && -n "$redis_password" && "$db_pass" == "$redis_password" ]] ||
   [[ -n "$db_pass" && -n "$rate_limit_proxy_secret" && "$db_pass" == "$rate_limit_proxy_secret" ]] ||
   [[ -n "$redis_password" && -n "$rate_limit_proxy_secret" && "$redis_password" == "$rate_limit_proxy_secret" ]]; then
  errors+=("DB_PASS, REDIS_PASSWORD, and RATE_LIMIT_PROXY_SECRET must be different secrets")
fi

bootstrap_is_strong=false
if [[ -n "$bootstrap_password" ]]; then
  if is_placeholder "$bootstrap_password" || ((${#bootstrap_password} < 24)); then
    errors+=("AUTH_BOOTSTRAP_ADMIN_PASSWORD must be at least 24 characters and not a placeholder")
  else
    bootstrap_is_strong=true
  fi
fi

proxy_is_strong=false
if [[ -n "$proxy_secret" ]]; then
  if is_placeholder "$proxy_secret" || ((${#proxy_secret} < 24)); then
    errors+=("PROXY_SECRET must be at least 24 characters and not a placeholder")
  else
    proxy_is_strong=true
  fi
fi

if [[ "$bootstrap_is_strong" != true && "$proxy_is_strong" != true &&
      "$existing_admin_confirmed" != "true" && "$existing_admin_confirmed" != "1" &&
      "$existing_admin_confirmed" != "yes" ]]; then
  errors+=("configure a strong bootstrap password or proxy secret, or explicitly set AUTH_EXISTING_ADMIN_CONFIRMED=true for a verified upgrade")
fi

if [[ -z "$cors_origins" ]]; then
  errors+=("CORS_ALLOWED_ORIGINS is required")
elif [[ "$cors_origins" == *"*"* ]]; then
  errors+=("CORS_ALLOWED_ORIGINS must not contain a wildcard")
else
  IFS=',' read -r -a origins <<< "$cors_origins"
  for origin in "${origins[@]}"; do
    origin="${origin#"${origin%%[![:space:]]*}"}"
    origin="${origin%"${origin##*[![:space:]]}"}"
    if [[ "$origin" != https://* ]]; then
      errors+=("every production CORS origin must use https://")
      break
    fi
  done
fi

if [[ "$auth_enabled" != "true" && "$auth_enabled" != "1" && "$auth_enabled" != "yes" ]]; then
  errors+=("AUTH_ENABLED must be true for the production overlay")
fi

if [[ "$secure_cookies" != "true" && "$secure_cookies" != "1" && "$secure_cookies" != "yes" ]]; then
  errors+=("SECURE_COOKIES must be true for the production overlay")
fi

custom_image_keys=(
  ADVERSARYGRAPH_POSTGRES_IMAGE
  ADVERSARYGRAPH_BACKEND_IMAGE
  ADVERSARYGRAPH_FRONTEND_IMAGE
  ADVERSARYGRAPH_MALWAREGRAPH_IMAGE
  ADVERSARYGRAPH_ATTACK_LAB_WEB_IMAGE
  ADVERSARYGRAPH_ATTACK_LAB_ENDPOINT_IMAGE
  ADVERSARYGRAPH_ANOMALY_DOCS_IMAGE
)
for key in "${custom_image_keys[@]}"; do
  value="$(effective_value "$key")"
  if [[ ! "$value" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]]; then
    errors+=("$key must identify a reviewed registry image by immutable @sha256 digest")
  fi
done

declare -A third_party_image_defaults=(
  [REDIS_IMAGE]='redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99'
  [BUSYBOX_IMAGE]='busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
  [NGINX_DOCS_IMAGE]='nginx:stable-alpine@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46'
)
for key in "${!third_party_image_defaults[@]}"; do
  value="$(effective_value "$key" "${third_party_image_defaults[$key]}")"
  if [[ ! "$value" =~ ^[^[:space:]@]+@sha256:[a-f0-9]{64}$ ]]; then
    errors+=("$key override must remain pinned by immutable @sha256 digest")
  fi
done

atlas_sync_interval="$(effective_value ATLAS_SYNC_INTERVAL 0)"
if [[ "$atlas_sync_interval" != "0" ]]; then
  errors+=("ATLAS_SYNC_INTERVAL must be 0 in production so scanned image dependencies cannot change at runtime")
fi

if ((${#errors[@]})); then
  echo "Production environment validation failed:" >&2
  for error in "${errors[@]}"; do
    printf '  - %s\n' "$error" >&2
  done
  echo "Generate independent secrets with 'openssl rand -hex 32' and review .env.example." >&2
  exit 1
fi

echo "Production environment validation passed (secret values were not printed)."
