FROM node:22-alpine

RUN apk upgrade --no-cache && apk add --no-cache git rsync
RUN npm install -g npm@11.18.0

WORKDIR /seed
COPY anomaly_detection/docs-site/package.json anomaly_detection/docs-site/package-lock.json ./
COPY anomaly_detection/docs-site/vendor/ ./vendor/
# Replace vulnerable packages bundled by npm 11.18.0 with the lockfile-verified
# patches used by the docs tree, then fail closed if any expected package was
# not installed.
RUN npm ci && \
    rm -rf /usr/local/lib/node_modules/npm/node_modules/brace-expansion && \
    cp -R node_modules/brace-expansion /usr/local/lib/node_modules/npm/node_modules/brace-expansion && \
    rm -rf /usr/local/lib/node_modules/npm/node_modules/ip-address && \
    cp -R node_modules/ip-address /usr/local/lib/node_modules/npm/node_modules/ip-address && \
    rm -rf /usr/local/lib/node_modules/npm/node_modules/tar && \
    cp -R node_modules/tar /usr/local/lib/node_modules/npm/node_modules/tar && \
    node -e "const p=require('/usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json'); if (p.version !== '5.0.12') process.exit(1)" && \
    node -e "const p=require('/usr/local/lib/node_modules/npm/node_modules/ip-address/package.json'); if (p.version !== '10.7.4') process.exit(1)" && \
    node -e "const p=require('/usr/local/lib/node_modules/npm/node_modules/tar/package.json'); if (p.version !== '7.5.22') process.exit(1)"

COPY anomaly_detection/docs-site/ /seed/
COPY scripts/sync-anomaly-atlas.sh /usr/local/bin/sync-anomaly-atlas
COPY scripts/generate-ttp-reference-index.mjs /usr/local/bin/generate-ttp-reference-index.mjs
COPY scripts/apply-adversarygraph-docs-overlay.mjs /usr/local/bin/apply-adversarygraph-docs-overlay.mjs
COPY anomaly_detection/docs-overlay/ /seed-overlay/
COPY anomaly_detection/docker/sync-and-build.sh /usr/local/bin/sync-and-build

RUN npm run build && rm -rf build
RUN chmod +x /usr/local/bin/sync-anomaly-atlas /usr/local/bin/sync-and-build

RUN addgroup -S atlas && adduser -S -G atlas -h /seed atlas && \
    mkdir -p /work /output && \
    chown -R atlas:atlas /seed /seed-overlay /work /output

USER atlas

HEALTHCHECK --interval=60s --timeout=5s --start-period=120s --retries=3 \
    CMD test -s /output/anomaly-detection-atlas/index.html || exit 1

CMD ["/usr/local/bin/sync-and-build"]

ARG SOURCE_REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/anpa1200/adversarygraph" \
      org.opencontainers.image.version="8.1.0-beta.2" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
