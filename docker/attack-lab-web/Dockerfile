FROM python:3.12-slim

WORKDIR /app
COPY docker/attack-lab-web/server.py /app/server.py

RUN useradd -r -g nogroup -d /app -s /usr/sbin/nologin labweb \
    && mkdir -p /app/logs/attack-simulation \
    && chown -R labweb:nogroup /app

USER labweb
EXPOSE 8080

CMD ["python", "/app/server.py"]
