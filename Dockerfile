# syntax=docker/dockerfile:1

# xgress — single-container image.
# Bundles the xgress binary (which embeds the admin SPA) and the official Traefik
# binary. xgress runs as PID 1 and supervises Traefik as a child process, so a
# static-config change restarts only Traefik — the container stays up.

# Base images are pinned by digest for reproducible, substitution-proof builds
# (bump the tag + digest together; a tool like Renovate can automate this). The Go
# builder is 1.26 (go1.26.4) which patches the net/textproto + crypto/x509 advisories.
ARG TRAEFIK_VERSION=v3.7.5
ARG GO_VERSION=1.26
ARG NODE_VERSION=22

# ---- 1. Build the SPA ----
FROM node:22-alpine@sha256:9385cd9f3001dfc3431e8ead12c43e9e1f87cc1b9b5c6cfd0f73865d405b27c4 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install
COPY web/ ./
RUN npm run build

# ---- 2. Build the Go binary (embeds the SPA) ----
FROM golang:1.26@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/ ./third_party/
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# Inject the freshly built SPA so go:embed picks it up.
COPY --from=web /web/dist ./web/dist
ARG VERSION=0.9.0-rc.1
ARG COMMIT=docker
# Cache mounts make rebuilds fast (the lego/cloud-SDK tree is large to compile cold).
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -ldflags "-s -w -X github.com/suckharder/xgress/internal/version.Version=${VERSION} -X github.com/suckharder/xgress/internal/version.Commit=${COMMIT}" \
      -o /out/xgress ./cmd/xgress
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /out/crsbundle ./tools/crsbundle

# ---- 2b. Bundle the OWASP Core Rule Set into a WASM-compatible directives file.
# The Coraza WASM plugin can't Include @owasp_crs, so crsbundle inlines the rules
# (resolving @pmFromFile data files into @pm). Non-fatal: if the download fails
# the WAF simply falls back to its curated ruleset.
FROM build AS crs
ARG CRS_VERSION=v4.14.0
# --checksum fails the build on any mismatch (no silent substitution of WAF rules).
ADD --checksum=sha256:3782e9b6d401bd6109c2986021278d517385ce19743e08ae81292925569a5931 \
    https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz /tmp/crs.tar.gz
RUN mkdir -p /crs-src /out && \
    (tar xzf /tmp/crs.tar.gz -C /crs-src --strip-components=1 && \
     /out/crsbundle /crs-src > /out/crs-bundled.conf && \
     echo "CRS lines: $(wc -l < /out/crs-bundled.conf)") || \
    (echo "# OWASP CRS bundle unavailable at build time" > /out/crs-bundled.conf)

# ---- 3. Grab the official Traefik binary ----
FROM traefik:v3.7.5@sha256:d6858791f9e74df44ca4014166647c41cdc2abd3bf2a71b832ca4e1c6a91b257 AS traefik

# ---- 4. Runtime ----
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache ca-certificates tzdata setpriv && \
    addgroup -S xgress && adduser -S -G xgress xgress && \
    mkdir -p /data && chown xgress:xgress /data
COPY --from=traefik /usr/local/bin/traefik /usr/local/bin/traefik
COPY --from=build /out/xgress /usr/local/bin/xgress
COPY --from=crs /out/crs-bundled.conf /etc/coraza-crs/crs-bundled.conf

# Entrypoint: when started as root, make the /data volume writable by the
# unprivileged xgress user (handles fresh AND pre-existing root-owned volumes), then
# drop to xgress via setpriv WITH ambient CAP_NET_BIND_SERVICE. The ambient cap is
# inherited by the supervised Traefik child, so the non-root process can still bind
# privileged ports (80/443 + any low-port TCP/UDP stream entrypoint) on any host —
# no reliance on the ip_unprivileged_port_start sysctl. Requires `cap_add:
# NET_BIND_SERVICE` (set in the compose files). If already started non-root (a
# `user:` override) it just execs. Compatible with read-only FS + no-new-privileges.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -e' \
    'if [ "$(id -u)" = "0" ]; then' \
    '  chown -R xgress:xgress "${XGRESS_DATA_DIR:-/data}" 2>/dev/null || true' \
    '  exec setpriv --reuid xgress --regid xgress --init-groups \' \
    '    --inh-caps -all,+net_bind_service --ambient-caps -all,+net_bind_service \' \
    '    /usr/local/bin/xgress "$@"' \
    'fi' \
    'exec /usr/local/bin/xgress "$@"' \
    > /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

ENV XGRESS_DATA_DIR=/data \
    XGRESS_TRAEFIK_MANAGED=true \
    XGRESS_TRAEFIK_BINARY=/usr/local/bin/traefik \
    XGRESS_ADMIN_LISTEN=:8088 \
    XGRESS_PROVIDER_LISTEN=127.0.0.1:9000

VOLUME ["/data"]
# 80/443 = proxied traffic; 8088 = admin UI + API.
EXPOSE 80 443 8088

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
