# ============================================================================
# KISS Mail Server - Docker Hardened Images (Alpine)
# ============================================================================
# Uses Docker Hardened Images (DHI) for security-hardened, minimal containers
# https://www.docker.com/products/hardened-images/
#
# PREFERRED: Pull from registry instead of building:
#   docker pull ghcr.io/pegasusheavy/kiss-mail:latest
#
# Build locally (if needed):
#   docker build -t kiss-mail .
#
# Run:
#   docker run -d -p 25:2525 -p 143:1143 -p 110:1100 -p 8080:8080 \
#     -v kiss-mail-data:/data ghcr.io/pegasusheavy/kiss-mail:latest
#
# Security Features:
#   - Docker Hardened Images base (CVE-free, SBOM included)
#   - Alpine Linux (minimal attack surface)
#   - Non-root user
#   - Read-only filesystem compatible
#   - No shell in runtime image
# ============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build (using DHI Rust Alpine dev image)
# -----------------------------------------------------------------------------
FROM dhi.io/rust:1.83-alpine3.21-dev AS builder

WORKDIR /app

# Install build dependencies for native compilation
# Note: Using rustls for TLS, so no OpenSSL needed
RUN apk add --no-cache \
    musl-dev \
    pkgconfig

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./

# Create dummy src to cache dependencies
RUN mkdir src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release && rm -rf src target/release/deps/kiss_mail*

# Copy actual source
COPY src/ src/

# Build release binary (uses rustls for TLS - no native deps needed)
RUN cargo build --release --locked

# Strip binary for smaller size
RUN strip /app/target/release/kiss-mail

# -----------------------------------------------------------------------------
# Stage 2: Runtime (using DHI Alpine minimal image)
# -----------------------------------------------------------------------------
FROM dhi.io/alpine:3.21 AS runtime

# Labels
LABEL org.opencontainers.image.title="KISS Mail Server"
LABEL org.opencontainers.image.description="Simple SMTP, IMAP, POP3 email server - Hardened Container"
LABEL org.opencontainers.image.source="https://github.com/pegasusheavy/kiss-mail"
LABEL org.opencontainers.image.vendor="Pegasus Heavy Industries"
LABEL org.opencontainers.image.base.name="dhi.io/alpine:3.21"
LABEL org.opencontainers.image.licenses="MIT"

# Install minimal runtime dependencies
# - ca-certificates: for TLS connections
# - libgcc: required by Rust binaries on Alpine
# - netcat-openbsd: for healthcheck (nc command)
RUN apk add --no-cache \
    ca-certificates \
    libgcc \
    netcat-openbsd \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 kissmail && \
    adduser -D -u 1000 -G kissmail -s /sbin/nologin kissmail

# Copy binary from builder
COPY --from=builder /app/target/release/kiss-mail /usr/local/bin/kiss-mail

# Ensure binary is executable
RUN chmod +x /usr/local/bin/kiss-mail

# Create data directory
RUN mkdir -p /data && chown kissmail:kissmail /data

# Switch to non-root user
USER kissmail

# Environment defaults
ENV KISS_MAIL_DATA_DIR=/data
ENV KISS_MAIL_DOMAIN=localhost
ENV KISS_MAIL_SMTP_PORT=2525
ENV KISS_MAIL_IMAP_PORT=1143
ENV KISS_MAIL_POP3_PORT=1100
ENV KISS_MAIL_WEB_PORT=8080
ENV KISS_MAIL_WEB_BIND=0.0.0.0
ENV KISS_MAIL_API_PORT=8025
ENV KISS_MAIL_API_BIND=0.0.0.0
ENV RUST_LOG=info

# Expose ports
EXPOSE 2525 1143 1100 8080 8025

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 2525 || exit 1

# Data volume
VOLUME ["/data"]

# Default command
ENTRYPOINT ["kiss-mail"]
CMD ["server"]
