# Stage 1: build the Vite app
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: serve the built dist/ with nginx
FROM nginx:alpine

RUN apk upgrade --no-cache

ENV API_UPSTREAM=api:8000
ENV RATE_LIMIT_PROXY_SECRET=""

COPY --from=builder /app/dist /usr/share/nginx/html

# Nginx config: serve static files and proxy API routes to the deployment-specific
# backend. The official entrypoint substitutes API_UPSTREAM into this template.
RUN rm -f /etc/nginx/conf.d/default.conf \
    && sed -i \
      -e '/^user[[:space:]]/d' \
      -e 's#^pid[[:space:]].*;#pid /tmp/nginx.pid;#' \
      /etc/nginx/nginx.conf \
    && grep -q '^pid /tmp/nginx.pid;$' /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/templates/default.conf.template

# Run as the built-in non-root nginx user
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d /etc/nginx/templates

USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/ >/dev/null || exit 1

CMD ["nginx", "-g", "daemon off;"]
