#!/bin/sh
set -eu

mkdir -p \
  /tmp/nginx/client_body \
  /tmp/nginx/proxy \
  /tmp/nginx/fastcgi \
  /tmp/nginx/uwsgi \
  /tmp/nginx/scgi

python /app/server.py &
app_pid="$!"

nginx -g "daemon off;" &
nginx_pid="$!"

term() {
  kill "$nginx_pid" "$app_pid" 2>/dev/null || true
}
trap term INT TERM

wait "$nginx_pid"
