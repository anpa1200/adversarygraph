#!/bin/sh
set -e

mkdir -p /var/run/postgresql-shared
chown -R postgres:postgres /var/run/postgresql-shared
chmod 775 /var/run/postgresql-shared

exec docker-entrypoint.sh "$@"
