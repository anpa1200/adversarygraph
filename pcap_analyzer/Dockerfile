FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY pcap_analyzer/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip==26.1.2 \
    && python -m pip install --no-cache-dir -r /tmp/requirements.txt

COPY pcap_analyzer/app.py /app/app.py

RUN groupadd --system --gid 10003 pcap \
    && useradd --system --uid 10003 --gid 10003 --home-dir /tmp --shell /usr/sbin/nologin pcap

USER pcap

EXPOSE 8300

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=10s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8300/health', timeout=3).read()"]

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8300", "--workers", "1"]
