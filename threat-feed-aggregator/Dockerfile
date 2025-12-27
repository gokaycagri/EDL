# Stage 1: Builder
FROM python:3.13-slim as builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build dependencies for python-ldap/python-whois extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    file \
    autoconf \
    automake \
    libtool \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies to a temporary location
COPY requirements.txt .
RUN pip install --prefix=/install --no-warn-script-location -r requirements.txt

# Stage 2: Final
FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=8080

# Install runtime dependencies and utilities
# whois: Required for IP investigation tools
# curl: Required for Healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap2 \
    libsasl2-2 \
    libssl3 \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# --- OpenShift / Kubernetes Compatibility ---
# 1. Ensure directory exists for volume mounting
# 2. Grant permissions to the root group (GID 0) to allow random UIDs to write
RUN mkdir -p /app/threat_feed_aggregator/data && \
    chgrp -R 0 /app && \
    chmod -R g=u /app

# Expose unprivileged port
EXPOSE 8080

# Entrypoint setup
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f -k https://localhost:8080/login || exit 1

# Run as non-root (OpenShift will override UID, but keeps GID 0)
USER 1001

ENTRYPOINT ["/entrypoint.sh"]