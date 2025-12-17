# Use official Python runtime as a parent image
FROM python:3.13-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies (if any needed for ldap/crypto)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (Internal Flask port, we map 443 in compose)
EXPOSE 443

# Entrypoint script to handle config setup
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Run the application
ENTRYPOINT ["/entrypoint.sh"]