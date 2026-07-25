FROM node:22-alpine

RUN apk upgrade --no-cache && apk add --no-cache git rsync
RUN npm install -g npm@11.18.0

WORKDIR /seed
COPY anomaly_detection/docs-site/package.json anomaly_detection/docs-site/package-lock.json ./
# npm 11.18.0 bundles brace-expansion 5.0.7. Replace that copy with the
# lockfile-verified 5.0.8 patch used by the docs tree, then fail closed if the
# expected package was not installed.
RUN npm ci && \
    rm -rf /usr/local/lib/node_modules/npm/node_modules/brace-expansion && \
    cp -R node_modules/brace-expansion /usr/local/lib/node_modules/npm/node_modules/brace-expansion && \
    node -e "const p=require('/usr/local/lib/node_modules/npm/node_modules/brace-expansion/package.json'); if (p.version !== '5.0.8') process.exit(1)"

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
