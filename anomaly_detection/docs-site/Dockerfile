FROM node:22.22.2-alpine@sha256:8ea2348b068a9544dae7317b4f3aafcdc032df1647bb7d768a05a5cad1a7683f

RUN apk upgrade --no-cache && apk add --no-cache git rsync
# Install the official checksum-pinned npm distribution without replacing a
# running npm process's dependencies halfway through its own upgrade.
RUN wget -qO /tmp/npm.tgz https://registry.npmjs.org/npm/-/npm-12.2.0.tgz \
    && echo "66c2632a94e796649738b2d7894d710c2cc2e1696893823066687f6b0d8a52e5f2b54eeaeaa32ffdc513ecca1e49ff794a5c2ec3f9515d879f1b3182b291cf35  /tmp/npm.tgz" | sha512sum -c - \
    && rm -rf /usr/local/lib/node_modules/npm \
    && mkdir -p /usr/local/lib/node_modules/npm \
    && tar -xzf /tmp/npm.tgz -C /usr/local/lib/node_modules/npm --strip-components=1 \
    && rm /tmp/npm.tgz \
    && test "$(npm --version)" = "12.2.0" \
    && node -e "const s=require('/usr/local/lib/node_modules/npm/node_modules/semver'); const p=require('/usr/local/lib/node_modules/npm/node_modules/tar/package.json'); if (!s.gte(p.version, '7.5.22')) process.exit(1)"

WORKDIR /seed
COPY anomaly_detection/docs-site/package.json anomaly_detection/docs-site/package-lock.json ./
COPY anomaly_detection/docs-site/vendor/ ./vendor/
# Overlay compatible fixed dependencies from this integrity-checked lockfile
# into npm's separately bundled tree; project audits do not cover global npm.
RUN npm ci \
    && rm -rf /usr/local/lib/node_modules/npm/node_modules/brace-expansion /usr/local/lib/node_modules/npm/node_modules/undici /usr/local/lib/node_modules/npm/node_modules/http-cache-semantics \
    && cp -R node_modules/brace-expansion node_modules/undici node_modules/http-cache-semantics /usr/local/lib/node_modules/npm/node_modules/ \
    && node -e "for (const [name,version] of Object.entries({'brace-expansion':'5.0.12','undici':'6.28.1','http-cache-semantics':'4.3.0'})) { if(require('/usr/local/lib/node_modules/npm/node_modules/'+name+'/package.json').version !== version) process.exit(1); }" \
    && npm cache clean --force

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
      org.opencontainers.image.version="8.1.1" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
