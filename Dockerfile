ARG SSL_WATCH_VERSION=1.17.2
FROM ghcr.io/idesyatov/ssl-watch:v${SSL_WATCH_VERSION} AS sslwatch

FROM node:22-alpine
ARG SSL_WATCH_VERSION=1.17.2
LABEL org.opencontainers.image.title="DomainPosture" \
      org.opencontainers.image.version="3.4.0" \
      org.opencontainers.image.description="Domain, email, and certificate health monitoring" \
      org.opencontainers.image.source="https://github.com/TechJedi51/domainposture" \
      org.opencontainers.image.ssl-watch.version="${SSL_WATCH_VERSION}"
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=sslwatch /ssl-watch /usr/local/bin/ssl-watch
RUN test -x /usr/local/bin/ssl-watch
COPY package.json server.js smtp.js dns-security.js dns-tools.js network-tools.js ssl-monitor.js THIRD_PARTY_NOTICES.md ./
COPY public ./public
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
CMD ["node", "server.js"]
