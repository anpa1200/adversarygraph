FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app
COPY docker/attack-lab-endpoint/server.py /app/server.py

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -g nogroup -d /app -s /usr/sbin/nologin labendpoint \
    && mkdir -p /app/logs/attack-simulation \
    && chown -R labendpoint:nogroup /app

USER labendpoint
EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=3).read()" || exit 1

CMD ["python", "/app/server.py"]
