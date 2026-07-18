ARG POSTGRES_BASE_IMAGE=postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
FROM ${POSTGRES_BASE_IMAGE}

# The upstream image's gosu binary was compiled with a Go standard library
# that currently carries fixable HIGH/CRITICAL findings. PostgreSQL uses the
# binary only to drop privileges during entrypoint startup. Alpine's small
# su-exec package provides that operation without embedding the affected Go
# runtime, while retaining the upstream entrypoint and data layout.
USER root
RUN set -eux; \
    apk upgrade --no-cache; \
    apk add --no-cache su-exec; \
    grep -q 'exec gosu postgres ' /usr/local/bin/docker-entrypoint.sh; \
    sed -i 's/exec gosu postgres /exec su-exec postgres /' /usr/local/bin/docker-entrypoint.sh; \
    ! grep -q 'exec gosu postgres ' /usr/local/bin/docker-entrypoint.sh; \
    rm -f /usr/local/bin/gosu; \
    su-exec postgres true
