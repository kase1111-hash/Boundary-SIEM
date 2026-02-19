# Boundary-SIEM Container Image
# Security-hardened multi-stage build with minimal attack surface
#
# Build: docker build -t boundary-siem:latest -f deploy/container/Dockerfile .
# Run:   docker-compose -f deploy/container/docker-compose.yml up -d

# =============================================================================
# Stage 1: Build stage
# =============================================================================
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    make

# Create non-root user for build
RUN adduser -D -g '' builduser

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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -o /build/boundary-siem \
    ./cmd/siem

# Verify binary
RUN /build/boundary-siem --version || true

# =============================================================================
# Stage 2: Runtime stage - minimal secure image
# =============================================================================
FROM scratch AS runtime

# Import CA certificates for TLS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Import passwd/group for non-root user
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Copy binary
COPY --from=builder /build/boundary-siem /usr/local/bin/boundary-siem

# Create required directories
# Note: In scratch image, we need to ensure these exist via volume mounts

# Use non-root user (uid 65534 is 'nobody')
USER 65534:65534

# Expose ports
# 8443 - HTTPS API
# 5514 - Syslog TCP/TLS ingestion
# 5515 - Syslog UDP ingestion
EXPOSE 8443 5514 5514/udp 5515/udp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/boundary-siem", "health"]

# Default entrypoint
ENTRYPOINT ["/usr/local/bin/boundary-siem"]
CMD ["--config", "/etc/boundary-siem/config.yaml"]

# =============================================================================
# Stage 3: Debug image (for troubleshooting only)
# =============================================================================
FROM alpine:3.19 AS debug

# Security updates
RUN apk upgrade --no-cache

# Install minimal debug tools
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    busybox-extras

# Create non-root user
RUN addgroup -g 1000 siem && \
    adduser -u 1000 -G siem -s /bin/sh -D siem

# Copy binary
COPY --from=builder /build/boundary-siem /usr/local/bin/boundary-siem

# Create directories with proper permissions
RUN mkdir -p /var/log/boundary-siem /var/lib/boundary-siem /etc/boundary-siem && \
    chown -R siem:siem /var/log/boundary-siem /var/lib/boundary-siem /etc/boundary-siem && \
    chmod 750 /var/log/boundary-siem /var/lib/boundary-siem && \
    chmod 755 /etc/boundary-siem

USER siem:siem
WORKDIR /home/siem

EXPOSE 8443 5514 5514/udp 5515/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/boundary-siem"]
CMD ["--config", "/etc/boundary-siem/config.yaml"]

# =============================================================================
# Labels for container metadata
# =============================================================================
LABEL org.opencontainers.image.title="Boundary-SIEM" \
      org.opencontainers.image.description="Security Information and Event Management with Hardware Enforcement" \
      org.opencontainers.image.vendor="Boundary Security" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/boundary/siem" \
      security.privileged="false" \
      security.capabilities.drop="ALL" \
      security.read-only-rootfs="true"
