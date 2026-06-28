FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -g nogroup -d /app -s /usr/sbin/nologin labweb \
    && mkdir -p /app/logs/attack-simulation \
    && chown -R labweb:nogroup /app

COPY docker/attack-lab-web/server.py /app/server.py
COPY docker/attack-lab-web/nginx.conf /etc/nginx/nginx.conf
COPY docker/attack-lab-web/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh \
    && chown labweb:nogroup /app/server.py /app/entrypoint.sh

USER labweb
EXPOSE 8080

CMD ["/app/entrypoint.sh"]
