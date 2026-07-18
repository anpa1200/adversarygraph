FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app

# UID 999 is shared with the API and the Compose log-volume initializer.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends nginx ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 999 --gid nogroup --home-dir /app --shell /usr/sbin/nologin labweb \
    && mkdir -p /app/logs/attack-simulation \
    && chown -R labweb:nogroup /app

COPY docker/attack-lab-web/server.py /app/server.py
COPY docker/attack-lab-web/nginx.conf /etc/nginx/nginx.conf
COPY docker/attack-lab-web/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && chown labweb:nogroup /app/server.py /app/entrypoint.sh

USER labweb
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).read()" || exit 1

CMD ["/app/entrypoint.sh"]
