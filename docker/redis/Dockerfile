FROM redis:7.4.11-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499
RUN apk add --upgrade --no-cache libcrypto3=3.3.7-r2 libssl3=3.3.7-r2

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/anpa1200/adversarygraph" \
      org.opencontainers.image.version="8.1.1" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
