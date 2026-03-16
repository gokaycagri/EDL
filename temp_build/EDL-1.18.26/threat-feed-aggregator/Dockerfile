# Stage 1: Builder
FROM python:3.11-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    file \
    autoconf \
    automake \
    libtool \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --prefix=/install --no-warn-script-location -r requirements.txt

# Stage 2: Final
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=8080

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libldap2 \
    libsasl2-2 \
    libssl3 \
    whois \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# OpenShift / Rootless Compatibility
RUN mkdir -p /app/threat_feed_aggregator/data \
             /app/threat_feed_aggregator/certs \
             /app/threat_feed_aggregator/data/edl_cache \
             /app/threat_feed_aggregator/data/flask_session && \
    chgrp -R 0 /app && \
    chmod -R g=u /app && \
    chmod g=u /etc/passwd && \
    chmod +x /app/entrypoint.sh

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

USER 1001

ENTRYPOINT ["/app/entrypoint.sh"]
