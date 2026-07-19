ARG POSTGRES_BASE_IMAGE=postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
FROM ${POSTGRES_BASE_IMAGE}

ARG PGVECTOR_VERSION=0.8.2
ARG PGVECTOR_SHA256=69f4019389af05dc1c9548deb8628e62878e6e207c03907f2b8af2016472cdaa

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

# Alpine's postgresql-pgvector package is compiled for Alpine's distro-owned
# PostgreSQL installation. The Docker Official Image installs PostgreSQL under
# /usr/local, so build the pinned extension against that exact installation.
# OPTFLAGS is intentionally empty to keep the resulting binary portable across
# hosts instead of compiling with pgvector's default -march=native.
RUN set -eux; \
    apk add --no-cache --virtual .pgvector-build-deps \
        ${DOCKER_PG_LLVM_DEPS} \
        build-base \
    ; \
    wget -O /tmp/pgvector.tar.gz \
        "https://github.com/pgvector/pgvector/archive/refs/tags/v${PGVECTOR_VERSION}.tar.gz"; \
    echo "${PGVECTOR_SHA256}  /tmp/pgvector.tar.gz" | sha256sum -c -; \
    mkdir -p /tmp/pgvector; \
    tar \
        --extract \
        --gzip \
        --file /tmp/pgvector.tar.gz \
        --directory /tmp/pgvector \
        --strip-components 1 \
    ; \
    make -C /tmp/pgvector clean; \
    make -C /tmp/pgvector OPTFLAGS="" PG_CONFIG=/usr/local/bin/pg_config; \
    make -C /tmp/pgvector install PG_CONFIG=/usr/local/bin/pg_config; \
    test -s /usr/local/lib/postgresql/vector.so; \
    grep -F "default_version = '${PGVECTOR_VERSION}'" \
        /usr/local/share/postgresql/extension/vector.control; \
    rm -rf /tmp/pgvector /tmp/pgvector.tar.gz; \
    apk del --no-network .pgvector-build-deps
