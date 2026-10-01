# Boundary-SIEM Container Image (siem-ingest)
# Multi-stage build: static Go binary on a small non-root runtime image.
#
# Build: docker build -t boundary-siem:latest -f deploy/container/Dockerfile .
# Run:   docker compose -f deploy/container/docker-compose.yml up -d
#
# siem-ingest takes no flags. It reads configs/config.yaml relative to the
# working directory (/app), or the file named by SIEM_CONFIG_PATH, and then
# applies environment overrides (SIEM_API_KEY, CLICKHOUSE_HOST, ...).

# =============================================================================
# Stage 1: Build stage
# =============================================================================
# go.mod declares go 1.26.0
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy go modules first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build with security flags
# -trimpath: Remove file system paths from binary
# -ldflags: Strip debug info, disable symbol table
# CGO_ENABLED=0: Static binary, no C dependencies
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-w -s -X main.version=${VERSION}" \
    -o /build/siem-ingest \
    ./cmd/siem-ingest

# =============================================================================
# Stage 2: Runtime stage
# =============================================================================
FROM alpine:3.22 AS runtime

RUN apk upgrade --no-cache && apk add --no-cache ca-certificates tzdata && \
    addgroup -g 10001 siem && \
    adduser -u 10001 -G siem -s /sbin/nologin -D -H siem

# Working directory layout expected by the shipped config:
#   configs/config.yaml  configuration (read-only)
#   rules/               shipped community rules, copied into data/rules on first start
#   data/                writable: rules written by the rules API (mount a volume here)
#   logs/, certs/        created at startup if missing; mount TLS certificates into certs/
WORKDIR /app

COPY --from=builder /build/siem-ingest /usr/local/bin/siem-ingest
COPY configs/config.yaml /app/configs/config.yaml
COPY rules/ /app/rules/

RUN mkdir -p /app/data/events /app/data/rules /app/logs /app/certs && \
    chown -R siem:siem /app/data /app/logs && \
    chmod 750 /app/data /app/logs

USER 10001:10001

# 8080 - HTTP API, /health, /ready, /metrics, /ws/events
# 5515 - CEF over TCP (enabled by default)
# 5514/udp - CEF over plain UDP (disabled by default)
# 5516/udp - CEF over DTLS (disabled by default)
EXPOSE 8080 5515 5514/udp 5516/udp

VOLUME ["/app/data"]

# /health answers 200 while the process serves requests; use /ready for
# load-balancer decisions (it fails while storage is down or the queue is full).
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/health || exit 1

# siem-ingest drains and exits within server.shutdown_timeout (default 8s),
# inside Docker's default 10s stop grace period.
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/siem-ingest"]

LABEL org.opencontainers.image.title="Boundary-SIEM" \
      org.opencontainers.image.description="Boundary-SIEM ingest server (siem-ingest)" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/kase1111-hash/Boundary-SIEM"
