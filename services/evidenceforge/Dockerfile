FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

ARG EVIDENCEFORGE_REF=a68836bc10ea55971e2ce984b9e47eb4d01b7246

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && git clone https://github.com/Cisco-Talos/EvidenceForge.git /opt/evidenceforge \
    && cd /opt/evidenceforge \
    && git checkout --detach "${EVIDENCEFORGE_REF}" \
    && pip install --no-cache-dir /opt/evidenceforge fastapi==0.116.1 uvicorn==0.35.0 \
    && apt-get purge -y --auto-remove git \
    && rm -rf /var/lib/apt/lists/* /opt/evidenceforge/.git

COPY app.py /app/app.py
RUN groupadd --gid 10001 evidenceforge \
    && useradd --uid 10001 --gid evidenceforge --no-create-home --shell /usr/sbin/nologin evidenceforge \
    && mkdir -p /data/runs \
    && chown -R evidenceforge:evidenceforge /data

USER evidenceforge
WORKDIR /app
ENV EVIDENCEFORGE_REF="${EVIDENCEFORGE_REF}" \
    EVIDENCEFORGE_DATA_DIR=/data/runs \
    EVIDENCEFORGE_MAX_SCENARIO_BYTES=262144 \
    EVIDENCEFORGE_TIMEOUT_SECONDS=180

EXPOSE 8091
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8091", "--no-access-log"]
