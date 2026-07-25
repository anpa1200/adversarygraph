# Pinned official Nuclei engine. The runtime command further restricts it to
# signed, rate-limited network templates without fuzzing, code, headless, file,
# JavaScript, or out-of-band execution.
FROM projectdiscovery/nuclei:v3.8.0@sha256:aa3a9c0894629405b5bbe644765dfffd6ff87b7663b5f1d64bcbc01341da335a AS nuclei


# Immutable Nuclei Templates v10.4.6 source commit. The archive checksum is
# verified before extraction; Nuclei additionally rejects unsigned or
# signature-mismatched templates when the scan runs.
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
    && rm /tmp/nuclei-templates.tar.gz


# Stage 1: build — installs gcc/libpq-dev only for compiling Python extensions
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 && \
    python -m pip install --no-cache-dir --prefix=/install -r requirements.txt


# Stage 2: runtime — slim image without compiler toolchain
FROM python:3.12-slim

WORKDIR /app

# Refresh base-image packages before installing runtime dependencies so that
# published images include Debian security updates available at build time.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
      libpq5 \
      curl \
      nmap \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-templates --chown=999:999 /opt/nuclei-templates /app/nuclei-templates

COPY . .

RUN mkdir -p /app/data/attck /app/logs /app/nuclei-templates && \
    groupadd --system --gid 999 appuser && \
    useradd --system --uid 999 --gid 999 --home-dir /app --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/ready || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
