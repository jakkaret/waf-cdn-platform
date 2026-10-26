# Edge Caddy with shared certificate storage in Redis (waf-caddy-storage on
# Main, over WireGuard). Same Caddy version the edges ran before (2.11.4);
# the storage module is pinned too.
#   docker build -t waf-edge-caddy:2.11.4-redis1.9.0 cdn/edge/caddy
FROM caddy:2.11.4-builder-alpine AS builder
RUN xcaddy build v2.11.4 --with github.com/pberkel/caddy-storage-redis@v1.9.0

FROM caddy:2.11.4-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
