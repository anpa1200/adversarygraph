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

# Runtime-only native libs needed by asyncpg / psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

COPY . .

RUN mkdir -p /app/data/attck /app/logs && \
    groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000
