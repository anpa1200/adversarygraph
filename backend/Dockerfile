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

COPY . .

RUN mkdir -p /app/data/attck /app/logs && \
    groupadd --system --gid 999 appuser && \
    useradd --system --uid 999 --gid 999 --home-dir /app --shell /usr/sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/ready || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
