# Build a dependency-hardened Nuclei binary from an immutable official source
# snapshot. Explicit transitive pins keep the Nuclei v3.11.0 build on remediated
# dependency versions even when the upstream snapshot's module graph lags.
FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS nuclei

ARG NUCLEI_SOURCE_COMMIT=6ecdb947408db868f9f9865e09f51a0a19e4413f
ARG NUCLEI_SOURCE_SHA256=f923448173fa10021aed3c3c5f8d7638003f055fce22c1d319a1f2292dc86d99
ARG NUCLEI_KIN_OPENAPI_VERSION=v0.144.0
ARG NUCLEI_GO_GIT_VERSION=v5.19.2
ARG NUCLEI_X_TEXT_VERSION=v0.39.0
RUN apk add --no-cache build-base ca-certificates curl git tar \
    && curl -fsSL \
      "https://github.com/projectdiscovery/nuclei/archive/${NUCLEI_SOURCE_COMMIT}.tar.gz" \
      -o /tmp/nuclei-source.tar.gz \
    && echo "${NUCLEI_SOURCE_SHA256}  /tmp/nuclei-source.tar.gz" | sha256sum -c - \
    && mkdir -p /src \
    && tar -xzf /tmp/nuclei-source.tar.gz -C /src --strip-components=1 \
    && rm /tmp/nuclei-source.tar.gz \
    && cd /src \
    && go get "github.com/getkin/kin-openapi@${NUCLEI_KIN_OPENAPI_VERSION}" \
    && go get "github.com/go-git/go-git/v5@${NUCLEI_GO_GIT_VERSION}" \
    && go get "golang.org/x/text@${NUCLEI_X_TEXT_VERSION}" \
    && go mod tidy \
    && grep -Fqx $'\t\t\tif schema.ExclusiveMin {' pkg/input/formats/openapi/examples.go \
    && grep -Fqx $'\t\t\tif schema.ExclusiveMax {' pkg/input/formats/openapi/examples.go \
    && sed -i \
      -e 's/if schema\.ExclusiveMin {/if schema.ExclusiveMin.IsTrue() {/' \
      -e 's/if schema\.ExclusiveMax {/if schema.ExclusiveMax.IsTrue() {/' \
      pkg/input/formats/openapi/examples.go \
    && gofmt -w pkg/input/formats/openapi/examples.go \
    && CGO_ENABLED=0 go build -trimpath -pgo=auto \
      -ldflags="-s -w -extldflags -static" \
      -o /out/nuclei ./cmd/nuclei/main.go \
    && /out/nuclei -version 2>&1 | grep -F "Nuclei Engine Version: v3.11.0"


# Checksum-pinned official Nuclei Templates v10.4.6. Fixtures containing test
# private keys/default-secret literals are omitted because their corresponding
# JavaScript/credential templates are excluded by runtime policy; image-wide
# secret scanning remains enabled.
FROM alpine:3.22 AS nuclei-templates

ARG NUCLEI_TEMPLATES_COMMIT=7d66fa06cc0a5ad85f7bf35f18cf8ee9218fa9a5
ARG NUCLEI_TEMPLATES_SHA256=bb519f9fe89bfc37ae4bf5590c82507536aa1fc7fa00268d15589a0314643aa7
RUN apk add --no-cache ca-certificates curl tar \
    && curl -fsSL \
      "https://github.com/projectdiscovery/nuclei-templates/archive/${NUCLEI_TEMPLATES_COMMIT}.tar.gz" \
      -o /tmp/nuclei-templates.tar.gz \
    && echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/nuclei-templates \
    && tar -xzf /tmp/nuclei-templates.tar.gz \
      -C /opt/nuclei-templates --strip-components=1 \
    && rm /tmp/nuclei-templates.tar.gz \
    && rm -rf /opt/nuclei-templates/helpers/payloads/cve-2023-34039-keys \
    && rm -f \
      /opt/nuclei-templates/http/global-matchers/secrets-patterns-rules.yaml \
      /opt/nuclei-templates/http/misconfiguration/symfony/symfony-default-key-rce.yaml \
    && test ! -e /opt/nuclei-templates/helpers/payloads/cve-2023-34039-keys \
    && test ! -e /opt/nuclei-templates/http/global-matchers/secrets-patterns-rules.yaml \
    && test ! -e /opt/nuclei-templates/http/misconfiguration/symfony/symfony-default-key-rce.yaml


FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 \
    && python -m pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim

WORKDIR /app
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10002 scanner \
    && useradd --system --uid 10002 --gid 10002 --home-dir /tmp --shell /usr/sbin/nologin scanner

COPY --from=builder /install /usr/local
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-templates --chown=10002:10002 /opt/nuclei-templates /app/nuclei-templates
COPY --chown=10002:10002 scanner_mcp /app/scanner_mcp

USER scanner
EXPOSE 8200
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8200/health', timeout=3).read()"]

CMD ["uvicorn", "scanner_mcp.server:app", "--host", "0.0.0.0", "--port", "8200", "--no-access-log"]
