FROM nginx:stable-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5
RUN apk add --upgrade --no-cache libexpat=2.9.0-r0 libx11=1.8.14-r0

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/anpa1200/adversarygraph" \
      org.opencontainers.image.version="8.1.1" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
